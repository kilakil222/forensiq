// Package registry parses Windows registry hives for persistence indicators.
// It extracts Run/RunOnce keys into the persistence table and, for SYSTEM hives,
// services under ControlSet001\Services into the services table.
package registry

import (
	"database/sql"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"strings"
	"time"
	"unicode/utf16"

	"forensiq/internal/parsers"
)

// RegistryParser implements parsers.Parser for offline registry hive files.
type RegistryParser struct {
	hiveName string
}

// New returns a RegistryParser for the given hive name (e.g. "SOFTWARE", "SYSTEM").
func New(hiveName string) *RegistryParser {
	return &RegistryParser{hiveName: hiveName}
}

// Name returns "Registry/<hiveName>".
func (p *RegistryParser) Name() string { return "Registry/" + p.hiveName }

// runKeyPathsByHive returns the persistence-relevant subkey paths for a given
// hive type. SOFTWARE hive root has Microsoft\... directly (no "Software\"
// prefix); NTUSER.DAT root has Software\Microsoft\... .
func runKeyPathsByHive(hive string) []string {
	switch strings.ToUpper(hive) {
	case "SOFTWARE":
		return []string{
			`Microsoft\Windows\CurrentVersion\Run`,
			`Microsoft\Windows\CurrentVersion\RunOnce`,
			`Microsoft\Windows\CurrentVersion\RunServices`,
			`Microsoft\Windows\CurrentVersion\RunServicesOnce`,
			`Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run`,
			`Microsoft\Windows\CurrentVersion\Explorer\Run`,
			`Microsoft\Windows NT\CurrentVersion\Winlogon`,
			`Microsoft\Windows NT\CurrentVersion\Image File Execution Options`,
			`Wow6432Node\Microsoft\Windows\CurrentVersion\Run`,
			`Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce`,
		}
	case "NTUSER":
		return []string{
			`Software\Microsoft\Windows\CurrentVersion\Run`,
			`Software\Microsoft\Windows\CurrentVersion\RunOnce`,
			`Software\Microsoft\Windows\CurrentVersion\RunServices`,
			`Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`,
			`Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run`,
			`Software\Microsoft\Windows NT\CurrentVersion\Windows`,
			`Software\Microsoft\Windows NT\CurrentVersion\Winlogon`,
		}
	default:
		return nil
	}
}

// serviceControlSets are the control set names to try for services.
var serviceControlSets = []string{
	`ControlSet001\Services`,
	`ControlSet002\Services`,
	`CurrentControlSet\Services`,
}

// Parse reads an offline registry hive from r and inserts persistence/services rows.
func (p *RegistryParser) Parse(r io.Reader, db *sql.DB, ch chan<- parsers.Progress) error {
	start := time.Now()

	data, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("registry: read: %w", err)
	}
	log.Printf("registry: %s read %d bytes in %v", p.hiveName, len(data), time.Since(start))

	hive, err := openRegf(data)
	if err != nil {
		return fmt.Errorf("registry: open hive: %w", err)
	}
	rootSubs, _ := hive.root.subkeys()
	rootNames := make([]string, 0, len(rootSubs))
	for _, s := range rootSubs {
		rootNames = append(rootNames, s.name)
	}
	log.Printf("registry: %s opened OK, root.subkeyCount=%d, names=%v", p.hiveName, hive.root.subkeyCount, rootNames)

	var count int64

	// --- Persistence (Run keys) ---
	persistStmt, err := db.Prepare(`INSERT INTO persistence ("type", name, command, key_path, modified) VALUES (?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("registry: prepare persistence insert: %w", err)
	}
	defer persistStmt.Close()

	hivePaths := runKeyPathsByHive(p.hiveName)
	for _, keyPath := range hivePaths {
		key, err := hive.root.openSubkey(keyPath)
		if err != nil {
			// Key not present in this hive — skip silently.
			continue
		}
		vals, err := key.values()
		if err != nil {
			continue
		}
		for _, v := range vals {
			cmd := v.getString()
			if _, err := persistStmt.Exec("Run", v.name, cmd, keyPath, nil); err != nil {
				// Skip individual insert errors.
				continue
			}
			count++
		}
	}

	// --- Services (SYSTEM hive only) ---
	isSystem := strings.EqualFold(p.hiveName, "SYSTEM")
	if isSystem {
		svcStmt, err := db.Prepare(`INSERT INTO services (name, start_type, binary_path, modified) VALUES (?, ?, ?, ?)`)
		if err != nil {
			return fmt.Errorf("registry: prepare services insert: %w", err)
		}
		defer svcStmt.Close()

		for _, csPath := range serviceControlSets {
			servicesKey, err := hive.root.openSubkey(csPath)
			if err != nil {
				continue
			}
			svcKeys, err := servicesKey.subkeys()
			if err != nil {
				continue
			}
			for _, svc := range svcKeys {
				name := svc.name
				startType := ""
				binPath := ""

				vals, err := svc.values()
				if err == nil {
					for _, v := range vals {
						switch {
						case equalFold(v.name, "Start"):
							startType = formatStartType(v.getDword())
						case equalFold(v.name, "ImagePath"):
							binPath = v.getString()
						}
					}
				}

				if _, err := svcStmt.Exec(name, startType, binPath, nil); err != nil {
					continue
				}
				count++
			}
			// Only parse the first control set found.
			break
		}
	}

	// --- UserAssist (NTUSER.dat only) ---
	isNTUSER := strings.EqualFold(p.hiveName, "NTUSER")
	if isNTUSER {
		n, _ := extractUserAssist(hive, db)
		count += n
	}

	// --- BAM/DAM (SYSTEM hive only) ---
	if isSystem {
		n, _ := extractBAMDAM(hive, db)
		count += n
	}

	ch <- parsers.Progress{
		Parser:  p.Name(),
		Count:   count,
		Done:    true,
		Elapsed: time.Since(start),
	}
	return nil
}

// extractUserAssist reads UserAssist execution artifacts from NTUSER.dat.
// Values are ROT13-encoded paths; data is a 72-byte binary struct.
func extractUserAssist(hive *regf, db *sql.DB) (int64, error) {
	stmt, err := db.Prepare(`INSERT INTO userassist (path, run_count, last_run, focus_count, focus_duration) VALUES (?, ?, ?, ?, ?)`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	guidRoot, err := hive.root.openSubkey(`Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist`)
	if err != nil {
		return 0, nil // key absent — not an error
	}

	guids, err := guidRoot.subkeys()
	if err != nil {
		return 0, nil
	}

	var count int64
	for _, guidKey := range guids {
		countKey, err := guidKey.openSubkey("Count")
		if err != nil {
			continue
		}
		vals, err := countKey.values()
		if err != nil {
			continue
		}
		for _, v := range vals {
			name := rot13(v.name)
			if name == "" || name == "UEME_CTLSESSION" {
				continue
			}
			runCount, focusCount, focusDur, lastRun := parseUserAssistData(v.data)
			if _, err := stmt.Exec(name, runCount, lastRun, focusCount, focusDur); err == nil {
				count++
			}
		}
	}
	return count, nil
}

// parseUserAssistData parses a UserAssist binary value (72 bytes for Win7+).
func parseUserAssistData(data []byte) (runCount, focusCount, focusDur int, lastRun time.Time) {
	if len(data) < 16 {
		return 0, 0, 0, time.Time{}
	}
	runCount = int(binary.LittleEndian.Uint32(data[4:8]))
	if len(data) >= 12 {
		focusCount = int(binary.LittleEndian.Uint32(data[8:12]))
	}
	if len(data) >= 16 {
		focusDur = int(binary.LittleEndian.Uint32(data[12:16]))
	}
	if len(data) >= 68 {
		ft := binary.LittleEndian.Uint64(data[60:68])
		const epoch = uint64(116444736000000000)
		if ft > epoch {
			lastRun = time.Unix(0, int64((ft-epoch)*100)).UTC()
		}
	}
	return
}

// rot13 applies ROT13 decoding to UserAssist value names.
func rot13(s string) string {
	b := []byte(s)
	for i, c := range b {
		switch {
		case c >= 'A' && c <= 'Z':
			b[i] = 'A' + (c-'A'+13)%26
		case c >= 'a' && c <= 'z':
			b[i] = 'a' + (c-'a'+13)%26
		}
	}
	return string(b)
}

// extractBAMDAM reads Background Activity Monitor / Desktop Activity Moderator entries.
// Path: ControlSet001\Services\bam\State\UserSettings\{SID}
func extractBAMDAM(hive *regf, db *sql.DB) (int64, error) {
	stmt, err := db.Prepare(`INSERT INTO bam_dam (path, last_run, sid, source) VALUES (?, ?, ?, ?)`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	var count int64
	for _, source := range []string{"bam", "dam"} {
		root, err := hive.root.openSubkey(`ControlSet001\Services\` + source + `\State\UserSettings`)
		if err != nil {
			continue
		}
		sids, err := root.subkeys()
		if err != nil {
			continue
		}
		for _, sidKey := range sids {
			sid := sidKey.name
			vals, err := sidKey.values()
			if err != nil {
				continue
			}
			for _, v := range vals {
				if len(v.data) < 8 || v.name == "SequenceNumber" || v.name == "Version" {
					continue
				}
				ft := binary.LittleEndian.Uint64(v.data[:8])
				const epoch = uint64(116444736000000000)
				var ts time.Time
				if ft > epoch {
					ts = time.Unix(0, int64((ft-epoch)*100)).UTC()
				}
				if _, err := stmt.Exec(v.name, ts, sid, source); err == nil {
					count++
				}
			}
		}
	}
	return count, nil
}

// formatStartType converts a service Start DWORD to a human-readable string.
func formatStartType(v uint32) string {
	switch v {
	case 0:
		return "Boot"
	case 1:
		return "System"
	case 2:
		return "Auto"
	case 3:
		return "Manual"
	case 4:
		return "Disabled"
	default:
		return fmt.Sprintf("%d", v)
	}
}

// ============================================================
// Minimal REGF parser (adapted from amcache/regf.go)
// ============================================================

type regf struct {
	data []byte
	root *nkCell
}

func openRegf(data []byte) (*regf, error) {
	if len(data) < 4096 {
		return nil, fmt.Errorf("regf: hive too small (%d bytes)", len(data))
	}
	if string(data[0:4]) != "regf" {
		return nil, fmt.Errorf("regf: bad signature %q", string(data[0:4]))
	}
	rootOff := binary.LittleEndian.Uint32(data[36:40])
	r := &regf{data: data}
	root, err := r.parseNK(int(rootOff) + 0x1000)
	if err != nil {
		return nil, fmt.Errorf("regf: root NK: %w", err)
	}
	r.root = root
	return r, nil
}

type nkCell struct {
	name          string
	subkeyCount   uint32
	subkeyListOff int
	valueCount    uint32
	valueListOff  int
	r             *regf
}

func (r *regf) parseNK(off int) (*nkCell, error) {
	if off < 0x1000 || off+80 > len(r.data) {
		return nil, fmt.Errorf("regf: NK offset 0x%x out of range", off)
	}
	if string(r.data[off+4:off+6]) != "nk" {
		return nil, fmt.Errorf("regf: expected NK at 0x%x, got %q", off, string(r.data[off+4:off+6]))
	}

	// NK record layout (offsets relative to cell start, +4 = after cell-size header):
	//   +4  magic "nk"        +6  flags         +8  lastWriteTime (8)
	//   +20 parent (4)        +24 subkeyCount   +32 subkeyOff
	//   +40 valueCount        +44 valueOff      +56 maxNameLen
	//   +76 nameLen (2)       +78 classNameLen  +80 name
	subkeyCount := binary.LittleEndian.Uint32(r.data[off+24 : off+28])
	subkeyListRaw := binary.LittleEndian.Uint32(r.data[off+32 : off+36])
	valueCount := binary.LittleEndian.Uint32(r.data[off+40 : off+44])
	valueListRaw := binary.LittleEndian.Uint32(r.data[off+44 : off+48])
	nameLen := binary.LittleEndian.Uint16(r.data[off+76 : off+78])
	flags := binary.LittleEndian.Uint16(r.data[off+6 : off+8])

	nameStart := off + 80
	if nameStart+int(nameLen) > len(r.data) {
		return nil, fmt.Errorf("regf: NK name out of range at 0x%x", off)
	}
	nameBytes := r.data[nameStart : nameStart+int(nameLen)]
	var name string
	if flags&0x20 != 0 {
		name = string(nameBytes)
	} else {
		name = decodeUTF16LE(nameBytes)
	}

	subkeyListOff := -1
	if subkeyCount > 0 && subkeyListRaw != 0xFFFFFFFF && subkeyListRaw != 0 {
		subkeyListOff = int(subkeyListRaw) + 0x1000
	}
	valueListOff := -1
	if valueCount > 0 && valueListRaw != 0xFFFFFFFF && valueListRaw != 0 {
		valueListOff = int(valueListRaw) + 0x1000
	}

	return &nkCell{
		name:          name,
		subkeyCount:   subkeyCount,
		subkeyListOff: subkeyListOff,
		valueCount:    valueCount,
		valueListOff:  valueListOff,
		r:             r,
	}, nil
}

func (nk *nkCell) subkeys() ([]*nkCell, error) {
	if nk.subkeyCount == 0 || nk.subkeyListOff < 0 {
		return nil, nil
	}
	return nk.r.parseSubkeyList(nk.subkeyListOff, int(nk.subkeyCount))
}

func (r *regf) parseSubkeyList(off int, expected int) ([]*nkCell, error) {
	if off+8 > len(r.data) {
		return nil, fmt.Errorf("regf: subkey list offset 0x%x out of range", off)
	}
	sig := string(r.data[off+4 : off+6])
	count := int(binary.LittleEndian.Uint16(r.data[off+6 : off+8]))

	switch sig {
	case "lf", "lh":
		if off+8+count*8 > len(r.data) {
			return nil, fmt.Errorf("regf: %s list truncated at 0x%x", sig, off)
		}
		var keys []*nkCell
		for i := 0; i < count; i++ {
			entryOff := off + 8 + i*8
			nkOff := int(binary.LittleEndian.Uint32(r.data[entryOff:entryOff+4])) + 0x1000
			nk, err := r.parseNK(nkOff)
			if err != nil {
				continue
			}
			keys = append(keys, nk)
		}
		return keys, nil

	case "li":
		if off+8+count*4 > len(r.data) {
			return nil, fmt.Errorf("regf: li list truncated at 0x%x", off)
		}
		var keys []*nkCell
		for i := 0; i < count; i++ {
			entryOff := off + 8 + i*4
			nkOff := int(binary.LittleEndian.Uint32(r.data[entryOff:entryOff+4])) + 0x1000
			nk, err := r.parseNK(nkOff)
			if err != nil {
				continue
			}
			keys = append(keys, nk)
		}
		return keys, nil

	case "ri":
		if off+8+count*4 > len(r.data) {
			return nil, fmt.Errorf("regf: ri list truncated at 0x%x", off)
		}
		var keys []*nkCell
		for i := 0; i < count; i++ {
			entryOff := off + 8 + i*4
			listOff := int(binary.LittleEndian.Uint32(r.data[entryOff:entryOff+4])) + 0x1000
			sub, err := r.parseSubkeyList(listOff, 0)
			if err != nil {
				continue
			}
			keys = append(keys, sub...)
		}
		return keys, nil

	default:
		return nil, fmt.Errorf("regf: unknown subkey list sig %q at 0x%x", sig, off)
	}
}

func (nk *nkCell) openSubkey(path string) (*nkCell, error) {
	cur := nk
	start := 0
	for i := 0; i <= len(path); i++ {
		if i == len(path) || path[i] == '\\' {
			part := path[start:i]
			if part == "" {
				start = i + 1
				continue
			}
			subs, err := cur.subkeys()
			if err != nil {
				return nil, err
			}
			found := false
			for _, sub := range subs {
				if equalFold(sub.name, part) {
					cur = sub
					found = true
					break
				}
			}
			if !found {
				return nil, fmt.Errorf("regf: key %q not found", part)
			}
			start = i + 1
		}
	}
	return cur, nil
}

type vkCell struct {
	name     string
	dataType uint32
	data     []byte
}

func (nk *nkCell) values() ([]*vkCell, error) {
	if nk.valueCount == 0 || nk.valueListOff < 0 {
		return nil, nil
	}
	r := nk.r
	off := nk.valueListOff
	count := int(nk.valueCount)
	if off+count*4 > len(r.data) {
		return nil, fmt.Errorf("regf: value list truncated at 0x%x", off)
	}
	var vals []*vkCell
	for i := 0; i < count; i++ {
		vkOffRaw := binary.LittleEndian.Uint32(r.data[off+i*4 : off+i*4+4])
		vkOff := int(vkOffRaw) + 0x1000
		vk, err := r.parseVK(vkOff)
		if err != nil {
			continue
		}
		vals = append(vals, vk)
	}
	return vals, nil
}

func (r *regf) parseVK(off int) (*vkCell, error) {
	if off+24 > len(r.data) {
		return nil, fmt.Errorf("regf: VK offset 0x%x out of range", off)
	}
	if string(r.data[off+4:off+6]) != "vk" {
		return nil, fmt.Errorf("regf: expected VK at 0x%x, got %q", off, string(r.data[off+4:off+6]))
	}
	nameLen := int(binary.LittleEndian.Uint16(r.data[off+6 : off+8]))
	dataLen := binary.LittleEndian.Uint32(r.data[off+8 : off+12])
	dataOff := binary.LittleEndian.Uint32(r.data[off+12 : off+16])
	dataType := binary.LittleEndian.Uint32(r.data[off+16 : off+20])
	flags := binary.LittleEndian.Uint16(r.data[off+20 : off+22])

	var name string
	if nameLen > 0 {
		if off+24+nameLen > len(r.data) {
			return nil, fmt.Errorf("regf: VK name out of range at 0x%x", off)
		}
		nb := r.data[off+24 : off+24+nameLen]
		if flags&0x01 != 0 {
			name = string(nb)
		} else {
			name = decodeUTF16LE(nb)
		}
	}

	var rawData []byte
	inlineFlag := dataLen & 0x80000000
	realLen := dataLen & 0x7FFFFFFF
	if inlineFlag != 0 {
		tmp := make([]byte, 4)
		binary.LittleEndian.PutUint32(tmp, dataOff)
		if realLen <= 4 {
			rawData = tmp[:realLen]
		} else {
			rawData = tmp
		}
	} else if realLen > 0 {
		absData := int(dataOff) + 0x1000 + 4
		if absData+int(realLen) > len(r.data) {
			return nil, fmt.Errorf("regf: VK data out of range at 0x%x len=%d", absData, realLen)
		}
		rawData = r.data[absData : absData+int(realLen)]
	}

	return &vkCell{
		name:     name,
		dataType: dataType,
		data:     rawData,
	}, nil
}

func (v *vkCell) getString() string {
	if len(v.data) == 0 {
		return ""
	}
	if v.dataType == 1 || v.dataType == 2 {
		s := decodeUTF16LE(v.data)
		for len(s) > 0 && s[len(s)-1] == 0 {
			s = s[:len(s)-1]
		}
		return s
	}
	return string(v.data)
}

func (v *vkCell) getDword() uint32 {
	if len(v.data) < 4 {
		return 0
	}
	return binary.LittleEndian.Uint32(v.data[:4])
}

func decodeUTF16LE(b []byte) string {
	if len(b) < 2 {
		return string(b)
	}
	u16 := make([]uint16, len(b)/2)
	for i := range u16 {
		u16[i] = binary.LittleEndian.Uint16(b[i*2 : i*2+2])
	}
	for len(u16) > 0 && u16[len(u16)-1] == 0 {
		u16 = u16[:len(u16)-1]
	}
	return string(utf16.Decode(u16))
}

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 32
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 32
		}
		if ca != cb {
			return false
		}
	}
	return true
}
