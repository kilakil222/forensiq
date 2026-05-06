// Package shellbags parses Windows Shellbags from NTUSER.dat and UsrClass.dat.
// Shellbags record every folder a user browsed — including deleted folders,
// network shares, and removable drives — making them critical for DFIR.
//
// Sources:
//   NTUSER.dat  → Software\Microsoft\Windows\Shell\BagMRU
//   UsrClass.dat → Local Settings\Software\Microsoft\Windows\Shell\BagMRU
package shellbags

import (
	"database/sql"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf16"

	"forensiq/internal/parsers"
)

// ShellbagsParser reads BagMRU entries from a registry hive.
type ShellbagsParser struct {
	hiveType string // "NTUSER" or "UsrClass"
	user     string
}

func New(hiveType, user string) *ShellbagsParser {
	return &ShellbagsParser{hiveType: hiveType, user: user}
}

func (p *ShellbagsParser) Name() string { return "Shellbags" }

func (p *ShellbagsParser) Parse(r io.Reader, db *sql.DB, ch chan<- parsers.Progress) error {
	start := time.Now()

	data, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("shellbags: read: %w", err)
	}

	hive, err := openHive(data)
	if err != nil {
		return fmt.Errorf("shellbags: open hive: %w", err)
	}

	// Navigate to BagMRU key based on hive type.
	var bagMRUPath string
	switch p.hiveType {
	case "UsrClass":
		bagMRUPath = `Local Settings\Software\Microsoft\Windows\Shell\BagMRU`
	default: // NTUSER
		bagMRUPath = `Software\Microsoft\Windows\Shell\BagMRU`
	}

	bagKey := navigateTo(hive, bagMRUPath)
	if bagKey == nil {
		// Also try the "BagMRU" variant without parent (some collection tools trim root).
		bagKey = navigateTo(hive, `Software\Microsoft\Windows\ShellNoRoam\BagMRU`)
		if bagKey == nil {
			// Not an error — hive may just not have shellbags.
			if ch != nil {
				ch <- parsers.Progress{Parser: "Shellbags", Count: 0, Done: true, Elapsed: time.Since(start)}
			}
			return nil
		}
	}

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("shellbags: begin tx: %w", err)
	}
	stmt, err := tx.Prepare(`INSERT INTO shellbags
		(path, last_modified, "user", source, item_type) VALUES (?, ?, ?, ?, ?)`)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("shellbags: prepare: %w", err)
	}
	defer stmt.Close()

	count := 0
	walkBagMRU(hive, bagKey, "", stmt, p.user, p.hiveType, &count)

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("shellbags: commit: %w", err)
	}

	if ch != nil {
		ch <- parsers.Progress{Parser: "Shellbags", Count: int64(count), Done: true, Elapsed: time.Since(start)}
	}
	return nil
}

// walkBagMRU recursively walks BagMRU keys and inserts shellbag rows.
func walkBagMRU(hive *regfHive, key *nkNode, parentPath string, stmt *sql.Stmt, user, source string, count *int) {
	// Each numbered value (0, 1, 2, …) is a ShellItem binary blob.
	for _, val := range key.values {
		// Only numbered values represent ShellItems.
		if !isNumeric(val.name) {
			continue
		}
		if val.dataType != regTypeBinary || len(val.data) < 4 {
			continue
		}

		name, itemType := decodeBagName(val.data)
		if name == "" {
			continue
		}

		// Build full path.
		var fullPath string
		if parentPath == "" {
			fullPath = name
		} else {
			sep := `\`
			if strings.HasSuffix(parentPath, `\`) || strings.HasPrefix(name, `\`) || strings.HasPrefix(name, "//") {
				sep = ""
			}
			fullPath = parentPath + sep + name
		}

		// Timestamp from the subkey for this entry (more precise) or the parent key.
		ts := key.lastModified
		if sub := findSubKey(hive, key, val.name); sub != nil {
			ts = sub.lastModified
			// Recurse into subkey.
			walkBagMRU(hive, sub, fullPath, stmt, user, source, count)
		}

		var tsVal interface{}
		if !ts.IsZero() {
			tsVal = ts
		}

		stmt.Exec(fullPath, tsVal, user, source, itemType)
		*count++
	}
}

// ─── ShellItem binary decoder ──────────────────────────────────────────────

const (
	itemVirtual   = "virtual"
	itemDrive     = "drive"
	itemFolder    = "folder"
	itemFile      = "file"
	itemNetwork   = "network"
	itemUnknown   = "unknown"
)

// decodeBagName extracts a human-readable name and item type from a ShellItem blob.
func decodeBagName(data []byte) (name, itemType string) {
	if len(data) < 4 {
		return "", itemUnknown
	}

	t := data[2] // type byte

	switch {
	// Virtual folders: Desktop, Control Panel, My Computer, etc.
	case t == 0x1F:
		return "(virtual folder)", itemVirtual

	// Drive letter: C:\, D:\, etc.
	case t == 0x2F:
		if len(data) >= 7 {
			raw := strings.TrimRight(string(data[3:7]), "\x00 ")
			if len(raw) >= 2 {
				return raw, itemDrive
			}
		}
		return "(drive)", itemDrive

	// Filesystem items: 0x31=folder, 0x32=file, 0x34=folder(unicode), 0x35=file(unicode)
	// also 0xB1 (Win10 unicode folder variant)
	case t == 0x31 || t == 0x34 || t == 0xB1:
		name = extractFsName(data)
		if name == "" {
			return "", itemFolder
		}
		return name, itemFolder

	case t == 0x32 || t == 0x35:
		name = extractFsName(data)
		if name == "" {
			return "", itemFile
		}
		return name, itemFile

	// Network locations: 0x41=workgroup/server, 0x42=file, 0x46=share, 0x47=drive
	case t == 0x41 || t == 0x42 || t == 0x46 || t == 0x47:
		name = extractNetName(data)
		if name == "" {
			return "", itemNetwork
		}
		return name, itemNetwork

	// Network place (newer format)
	case t == 0xC3:
		if len(data) > 8 {
			name = readAnsi(data[8:])
			if name != "" {
				return name, itemNetwork
			}
		}
		return "(network)", itemNetwork
	}
	return "", itemUnknown
}

// extractFsName extracts the folder/file name from a filesystem ShellItem.
// Tries to get the Unicode long name from the extension block first,
// falls back to the ANSI short name.
func extractFsName(data []byte) string {
	// Unicode long name from BEEF extension block (Win Vista+).
	if u := extractBeefUnicodeName(data); u != "" {
		return u
	}
	// ANSI short name: try common offsets (16 for Vista+, 14 for XP).
	for _, off := range []int{16, 14, 12} {
		if len(data) > off+1 {
			s := readAnsi(data[off:])
			if len(s) >= 1 && isPrintableASCII(s) {
				return s
			}
		}
	}
	return ""
}

// extractBeefUnicodeName finds the "BEEF" extension block and extracts the Unicode name.
// The BEEF extension signature bytes are 0xEF 0xBE at positions [extOff+2:extOff+4].
func extractBeefUnicodeName(data []byte) string {
	// Walk extension blocks starting after ANSI name (~offset 20).
	i := 20
	for i+6 < len(data) {
		blockSize := int(binary.LittleEndian.Uint16(data[i : i+2]))
		if blockSize < 4 || i+blockSize > len(data) {
			break
		}
		sig := binary.LittleEndian.Uint16(data[i+2 : i+4])
		if sig == 0xBEEF { // BEEF extension block
			// Unicode name offset varies by version.
			// Version is at i+4 (uint16). Typical offsets: 28 (v3), 38 (v7+).
			version := uint16(0)
			if i+6 <= len(data) {
				version = binary.LittleEndian.Uint16(data[i+4 : i+6])
			}
			nameOff := i + 28
			if version >= 7 {
				nameOff = i + 38
			}
			if nameOff+2 < i+blockSize && nameOff < len(data) {
				u := readUTF16LE(data[nameOff : i+blockSize])
				if u != "" {
					return u
				}
			}
		}
		i += blockSize
	}
	return ""
}

// extractNetName extracts the server/share name from a network ShellItem.
func extractNetName(data []byte) string {
	// Network items: flags at [3], name starts after header.
	// Common offset: 5 for simple server names.
	for _, off := range []int{5, 8, 12} {
		if len(data) > off {
			s := readAnsi(data[off:])
			if len(s) >= 2 && (strings.HasPrefix(s, `\\`) || isPrintableASCII(s)) {
				return s
			}
		}
	}
	return ""
}

func readAnsi(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func readUTF16LE(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	n := len(b) / 2
	u := make([]uint16, n)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	// Trim at first null.
	for i, c := range u {
		if c == 0 {
			u = u[:i]
			break
		}
	}
	if len(u) == 0 {
		return ""
	}
	return string(utf16.Decode(u))
}

func isPrintableASCII(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, c := range s {
		if c < 0x20 || c > 0x7E {
			return false
		}
	}
	return true
}

func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// ─── Minimal REGF reader ───────────────────────────────────────────────────

const (
	regTypeBinary = 3
	hivBase       = 0x1000
)

type regfHive struct {
	data []byte
	root *nkNode
}

type nkNode struct {
	name         string
	lastModified time.Time
	subkeys      []*nkNode // lazily loaded
	values       []vkEntry
	subkeyOff    int
	subkeyCount  int
	hive         *regfHive
}

type vkEntry struct {
	name     string
	dataType uint32
	data     []byte
}

func openHive(data []byte) (*regfHive, error) {
	if len(data) < 0x1000+76 {
		return nil, fmt.Errorf("hive too small")
	}
	if string(data[0:4]) != "regf" {
		return nil, fmt.Errorf("bad hive signature")
	}
	rootRelOff := int(binary.LittleEndian.Uint32(data[36:40]))
	h := &regfHive{data: data}
	root, err := h.readNK(rootRelOff + hivBase)
	if err != nil {
		return nil, err
	}
	h.root = root
	return h, nil
}

func (h *regfHive) readNK(abs int) (*nkNode, error) {
	if abs < hivBase || abs+76 > len(h.data) {
		return nil, fmt.Errorf("NK out of range: 0x%x", abs)
	}
	if string(h.data[abs+4:abs+6]) != "nk" {
		return nil, fmt.Errorf("bad NK signature at 0x%x", abs)
	}

	flags := binary.LittleEndian.Uint16(h.data[abs+6 : abs+8])
	tsRaw := binary.LittleEndian.Uint64(h.data[abs+8 : abs+16])
	subkeyCount := int(binary.LittleEndian.Uint32(h.data[abs+24 : abs+28]))
	subkeyListRaw := binary.LittleEndian.Uint32(h.data[abs+32 : abs+36])
	valueCount := int(binary.LittleEndian.Uint32(h.data[abs+40 : abs+44]))
	valueListRaw := binary.LittleEndian.Uint32(h.data[abs+44 : abs+48])
	nameLen := int(binary.LittleEndian.Uint16(h.data[abs+72 : abs+74]))

	nameStart := abs + 76
	if nameStart+nameLen > len(h.data) {
		return nil, fmt.Errorf("NK name out of range at 0x%x", abs)
	}
	nameBytes := h.data[nameStart : nameStart+nameLen]
	var name string
	if flags&0x20 != 0 {
		name = string(nameBytes)
	} else {
		name = decodeUtf16le(nameBytes)
	}

	node := &nkNode{
		name:         name,
		lastModified: filetimeToTime(tsRaw),
		subkeyCount:  subkeyCount,
		hive:         h,
	}

	if subkeyCount > 0 && subkeyListRaw != 0xFFFFFFFF && subkeyListRaw != 0 {
		node.subkeyOff = int(subkeyListRaw) + hivBase
	}

	if valueCount > 0 && valueListRaw != 0xFFFFFFFF && valueListRaw != 0 {
		node.values = h.readValues(int(valueListRaw)+hivBase, valueCount)
	}

	return node, nil
}

func (h *regfHive) loadSubkeys(node *nkNode) {
	if node.subkeys != nil || node.subkeyOff == 0 {
		return
	}
	node.subkeys = h.readSubkeyList(node.subkeyOff, node.subkeyCount)
}

func (h *regfHive) readSubkeyList(abs, count int) []*nkNode {
	if abs < hivBase || abs+8 > len(h.data) {
		return nil
	}
	sig := string(h.data[abs+4 : abs+6])
	var offsets []int

	switch sig {
	case "lf", "lh": // leaf list
		n := int(binary.LittleEndian.Uint16(h.data[abs+6 : abs+8]))
		base := abs + 8
		for i := 0; i < n && base+i*8+4 <= len(h.data); i++ {
			offsets = append(offsets, int(binary.LittleEndian.Uint32(h.data[base+i*8:]))+hivBase)
		}
	case "ri": // root index
		n := int(binary.LittleEndian.Uint16(h.data[abs+6 : abs+8]))
		base := abs + 8
		for i := 0; i < n && base+i*4+4 <= len(h.data); i++ {
			subListOff := int(binary.LittleEndian.Uint32(h.data[base+i*4:]))+hivBase
			offsets = append(offsets, h.leafOffsets(subListOff)...)
		}
	case "li": // direct list
		n := int(binary.LittleEndian.Uint16(h.data[abs+6 : abs+8]))
		base := abs + 8
		for i := 0; i < n && base+i*4+4 <= len(h.data); i++ {
			offsets = append(offsets, int(binary.LittleEndian.Uint32(h.data[base+i*4:]))+hivBase)
		}
	}

	var nodes []*nkNode
	for _, off := range offsets {
		if n, err := h.readNK(off); err == nil {
			nodes = append(nodes, n)
		}
	}
	return nodes
}

func (h *regfHive) leafOffsets(abs int) []int {
	if abs < hivBase || abs+8 > len(h.data) {
		return nil
	}
	sig := string(h.data[abs+4 : abs+6])
	if sig != "lf" && sig != "lh" && sig != "li" {
		return nil
	}
	n := int(binary.LittleEndian.Uint16(h.data[abs+6 : abs+8]))
	base := abs + 8
	var offsets []int
	stride := 8
	if sig == "li" {
		stride = 4
	}
	for i := 0; i < n && base+i*stride+4 <= len(h.data); i++ {
		offsets = append(offsets, int(binary.LittleEndian.Uint32(h.data[base+i*stride:]))+hivBase)
	}
	return offsets
}

func (h *regfHive) readValues(abs, count int) []vkEntry {
	if abs < hivBase || abs+count*4 > len(h.data) {
		return nil
	}
	var entries []vkEntry
	for i := 0; i < count; i++ {
		vkOff := int(binary.LittleEndian.Uint32(h.data[abs+i*4:])) + hivBase
		if e, ok := h.readVK(vkOff); ok {
			entries = append(entries, e)
		}
	}
	return entries
}

func (h *regfHive) readVK(abs int) (vkEntry, bool) {
	if abs < hivBase || abs+24 > len(h.data) {
		return vkEntry{}, false
	}
	if string(h.data[abs+4:abs+6]) != "vk" {
		return vkEntry{}, false
	}

	nameLen := int(binary.LittleEndian.Uint16(h.data[abs+6 : abs+8]))
	dataLen := binary.LittleEndian.Uint32(h.data[abs+8 : abs+12])
	dataOff := binary.LittleEndian.Uint32(h.data[abs+12 : abs+16])
	dataType := binary.LittleEndian.Uint32(h.data[abs+16 : abs+20])
	flags := binary.LittleEndian.Uint16(h.data[abs+20 : abs+22])

	nameStart := abs + 24
	if nameStart+nameLen > len(h.data) {
		return vkEntry{}, false
	}
	nameBytes := h.data[nameStart : nameStart+nameLen]
	var name string
	if flags&0x01 != 0 {
		name = string(nameBytes)
	} else {
		name = decodeUtf16le(nameBytes)
	}

	// Inline data: high bit of dataLen set means data is stored in dataOff field itself.
	var data []byte
	const inlineFlag = uint32(0x80000000)
	realLen := dataLen &^ inlineFlag
	if dataLen&inlineFlag != 0 {
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, dataOff)
		data = b[:realLen]
	} else if realLen > 0 {
		off := int(dataOff) + hivBase
		if off >= hivBase && off+int(realLen) <= len(h.data) {
			data = h.data[off : off+int(realLen)]
		}
	}

	return vkEntry{name: name, dataType: dataType, data: data}, true
}

// navigateTo walks a key path like "A\B\C" from the hive root.
func navigateTo(hive *regfHive, path string) *nkNode {
	parts := strings.Split(path, `\`)
	cur := hive.root
	for _, part := range parts {
		if part == "" {
			continue
		}
		sub := findSubKey(hive, cur, part)
		if sub == nil {
			return nil
		}
		cur = sub
	}
	return cur
}

// findSubKey returns the subkey with the given name (case-insensitive).
func findSubKey(hive *regfHive, node *nkNode, name string) *nkNode {
	hive.loadSubkeys(node)
	lower := strings.ToLower(name)
	for _, sub := range node.subkeys {
		if strings.ToLower(sub.name) == lower {
			return sub
		}
	}
	return nil
}

func decodeUtf16le(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return string(utf16.Decode(u))
}

func filetimeToTime(ft uint64) time.Time {
	if ft == 0 {
		return time.Time{}
	}
	const epoch = int64(116444736000000000)
	ns := (int64(ft) - epoch) * 100
	if ns < 0 {
		return time.Time{}
	}
	return time.Unix(0, ns).UTC()
}
