// Package jumplists parses Windows JumpList files.
//
// AutomaticDestinations (.automaticDestinations-ms) are OLE2/CFBF compound
// documents. Each numbered stream contains a LNK file; "DestList" stream
// contains access metadata (target path, count, timestamps).
//
// CustomDestinations (.customDestinations-ms) are a simpler binary format:
// a sequence of LNK files preceded by a 4-byte type marker, terminated by
// a 4-byte footer (0xBABFFBAB).
package jumplists

import (
	"database/sql"
	"encoding/binary"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf16"

	"forensiq/internal/parsers"
)

type Parser struct{ filePath string }

func New(fp string) *Parser { return &Parser{filePath: fp} }
func (p *Parser) Name() string { return "JumpLists" }

func (p *Parser) Parse(r io.Reader, db *sql.DB, ch chan<- parsers.Progress) error {
	start := time.Now()
	data, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("read jumplists: %w", err)
	}

	appID := appIDFromPath(p.filePath)
	appName := knownAppID(appID)
	isAuto := strings.HasSuffix(strings.ToLower(p.filePath), ".automaticdestinations-ms")

	stmt, err := db.Prepare(`INSERT INTO jumplists
		(app_id, app_name, entry_type, target_path, created, modified, accessed, access_count, pin_status, entry_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare jumplists: %w", err)
	}
	defer stmt.Close()

	var entries []jlEntry
	if isAuto {
		entries, err = parseAutoDestinations(data)
	} else {
		entries, err = parseCustomDestinations(data)
	}
	if err != nil {
		return err
	}

	entryType := "custom"
	if isAuto {
		entryType = "automatic"
	}

	count := 0
	for _, e := range entries {
		if e.targetPath == "" {
			continue
		}
		pin := ""
		if e.pinned {
			pin = "pinned"
		}
		if _, err := stmt.Exec(appID, appName, entryType, e.targetPath,
			nullTime(e.created), nullTime(e.modified), nullTime(e.accessed),
			e.accessCount, pin, e.entryID); err == nil {
			count++
		}
	}

	ch <- parsers.Progress{Parser: p.Name(), Count: int64(count), Done: true, Elapsed: time.Since(start)}
	return nil
}

type jlEntry struct {
	entryID     string
	targetPath  string
	created     time.Time
	modified    time.Time
	accessed    time.Time
	accessCount int
	pinned      bool
}

// ─── AutomaticDestinations (OLE2/CFBF) ──────────────────────────────────────

func parseAutoDestinations(data []byte) ([]jlEntry, error) {
	if len(data) < 8 || string(data[:8]) != "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1" {
		return nil, fmt.Errorf("not a CFBF file")
	}

	streams, err := cfbStreams(data)
	if err != nil {
		return nil, err
	}

	// Parse DestList for metadata (path, access count, timestamps).
	var entries []jlEntry
	if dl, ok := streams["DestList"]; ok {
		entries = parseDestList(dl)
	}

	// Fall back to LNK-in-stream scan for any paths DestList missed.
	seen := make(map[string]bool)
	for _, e := range entries {
		seen[e.entryID] = true
	}
	for name, sdata := range streams {
		if name == "DestList" || name == "Root Entry" {
			continue
		}
		if seen[name] {
			continue
		}
		if e, ok := lnkEntry(name, sdata); ok {
			entries = append(entries, e)
		}
	}

	return entries, nil
}

// cfbStreams reads a CFBF document and returns all named streams as a map.
func cfbStreams(data []byte) (map[string][]byte, error) {
	sectorShift := int(binary.LittleEndian.Uint16(data[30:32]))
	sectorSize := 1 << sectorShift
	if sectorSize < 64 || sectorSize > 65536 {
		return nil, fmt.Errorf("cfb: bad sector size %d", sectorSize)
	}

	miniShift := int(binary.LittleEndian.Uint16(data[32:34]))
	miniSize := 1 << miniShift
	miniCutoff := int(binary.LittleEndian.Uint32(data[56:60]))
	numFATSectors := int(binary.LittleEndian.Uint32(data[44:48]))
	firstDirSector := binary.LittleEndian.Uint32(data[48:52])
	firstMiniFAT := binary.LittleEndian.Uint32(data[60:64])
	firstDIFAT := binary.LittleEndian.Uint32(data[68:72])
	numDIFAT := int(binary.LittleEndian.Uint32(data[72:76]))

	sectorAt := func(n uint32) []byte {
		off := 512 + int(n)*sectorSize
		if off+sectorSize > len(data) {
			return nil
		}
		return data[off : off+sectorSize]
	}

	// Collect FAT sector numbers from DIFAT.
	var fatNums []uint32
	// First 109 entries from header.
	for i := 0; i < 109 && len(fatNums) < numFATSectors; i++ {
		s := binary.LittleEndian.Uint32(data[76+i*4 : 80+i*4])
		if s < 0xFFFFFFF8 {
			fatNums = append(fatNums, s)
		}
	}
	// Additional DIFAT sectors.
	ds := firstDIFAT
	for i := 0; i < numDIFAT && ds < 0xFFFFFFF8; i++ {
		sd := sectorAt(ds)
		if sd == nil {
			break
		}
		n := sectorSize/4 - 1
		for j := 0; j < n && len(fatNums) < numFATSectors; j++ {
			s := binary.LittleEndian.Uint32(sd[j*4 : j*4+4])
			if s < 0xFFFFFFF8 {
				fatNums = append(fatNums, s)
			}
		}
		ds = binary.LittleEndian.Uint32(sd[sectorSize-4:])
	}

	// Build FAT array.
	fat := make([]uint32, 0, numFATSectors*(sectorSize/4))
	for _, n := range fatNums {
		sd := sectorAt(n)
		if sd == nil {
			continue
		}
		for i := 0; i+4 <= len(sd); i += 4 {
			fat = append(fat, binary.LittleEndian.Uint32(sd[i:i+4]))
		}
	}

	readChain := func(start uint32) []byte {
		var out []byte
		s := start
		for s < 0xFFFFFFF8 {
			sd := sectorAt(s)
			if sd == nil {
				break
			}
			out = append(out, sd...)
			if int(s) >= len(fat) {
				break
			}
			s = fat[s]
		}
		return out
	}

	// Build mini-FAT.
	var miniFAT []uint32
	ms := firstMiniFAT
	for ms < 0xFFFFFFF8 {
		sd := sectorAt(ms)
		if sd == nil {
			break
		}
		for i := 0; i+4 <= len(sd); i += 4 {
			miniFAT = append(miniFAT, binary.LittleEndian.Uint32(sd[i:i+4]))
		}
		if int(ms) >= len(fat) {
			break
		}
		ms = fat[ms]
	}

	// Read directory chain.
	dirData := readChain(firstDirSector)

	// Find root entry to get mini-stream.
	var miniStream []byte
	if len(dirData) >= 128 {
		rootStart := binary.LittleEndian.Uint32(dirData[116:120])
		if rootStart < 0xFFFFFFF8 {
			miniStream = readChain(rootStart)
		}
	}

	miniSectorAt := func(n uint32) []byte {
		off := int(n) * miniSize
		if off+miniSize > len(miniStream) {
			return nil
		}
		return miniStream[off : off+miniSize]
	}

	readMiniChain := func(start uint32, size uint64) []byte {
		var out []byte
		s := start
		for s < 0xFFFFFFF8 {
			sd := miniSectorAt(s)
			if sd == nil {
				break
			}
			out = append(out, sd...)
			if int(s) >= len(miniFAT) {
				break
			}
			s = miniFAT[s]
		}
		if uint64(len(out)) > size {
			out = out[:size]
		}
		return out
	}

	streams := make(map[string][]byte)

	// Parse directory entries (128 bytes each).
	for i := 0; i+128 <= len(dirData); i += 128 {
		entry := dirData[i : i+128]
		nameLen := int(binary.LittleEndian.Uint16(entry[64:66]))
		objType := entry[66]
		if objType == 0 || nameLen < 2 || nameLen > 64 {
			continue
		}
		nameUTF16 := entry[:nameLen-2] // strip null
		name := string(utf16.Decode(u16slice(nameUTF16)))

		startSect := binary.LittleEndian.Uint32(entry[116:120])
		size := uint64(binary.LittleEndian.Uint32(entry[120:124]))

		if objType == 2 { // stream
			var sd []byte
			if size < uint64(miniCutoff) && len(miniStream) > 0 {
				sd = readMiniChain(startSect, size)
			} else if startSect < 0xFFFFFFF8 {
				sd = readChain(startSect)
				if uint64(len(sd)) > size {
					sd = sd[:size]
				}
			}
			streams[name] = sd
		}
	}

	return streams, nil
}

// parseDestList decodes the DestList stream.
//
// v1 entry fixed header: 104 bytes
// v3 entry fixed header: 130 bytes (Windows 10)
func parseDestList(data []byte) []jlEntry {
	if len(data) < 32 {
		return nil
	}
	version := binary.LittleEndian.Uint32(data[0:4])
	count := int(binary.LittleEndian.Uint32(data[4:8]))
	if count <= 0 || count > 100000 {
		return nil
	}

	fixedSize := 104 // v1
	if version >= 3 {
		fixedSize = 130
	}

	var entries []jlEntry
	pos := 32 // skip header
	for i := 0; i < count && pos < len(data); i++ {
		if pos+fixedSize > len(data) {
			break
		}
		e := data[pos:]

		// hostname at offset 64, max 16 bytes
		hostname := cstring(e[64:80])
		_ = hostname

		entryID := fmt.Sprintf("%x", binary.LittleEndian.Uint64(e[80:88]))
		modified := filetimeAt(e, 88)
		pinStatus := binary.LittleEndian.Uint32(e[96:100])
		pathLen := int(binary.LittleEndian.Uint16(e[102:104]))

		if pathLen < 0 || pathLen > 4096 {
			break
		}
		pathEnd := 104 + pathLen*2
		if pathEnd > len(e) {
			break
		}
		targetPath := utf16LEString(e[104:pathEnd])

		var accessCount int
		var lastAccess time.Time
		tail := e[pathEnd:]
		if len(tail) >= 12 {
			accessCount = int(binary.LittleEndian.Uint32(tail[0:4]))
			lastAccess = filetimeAt(tail, 4)
		}

		entries = append(entries, jlEntry{
			entryID:     entryID,
			targetPath:  targetPath,
			modified:    modified,
			accessed:    lastAccess,
			accessCount: accessCount,
			pinned:      pinStatus == 1,
		})

		// Advance: fixed + path + 12 (access_count + last_access)
		advance := fixedSize + pathLen*2 + 12
		if version >= 3 {
			// v3 has extra fields after last_access
			if len(tail) >= 20 {
				extraLen := int(binary.LittleEndian.Uint16(tail[16:18]))
				advance += extraLen * 2
			}
		}
		pos += advance
	}
	return entries
}

// lnkEntry extracts timestamps and a synthetic path from an LNK stream.
func lnkEntry(streamName string, data []byte) (jlEntry, bool) {
	if len(data) < 76 {
		return jlEntry{}, false
	}
	// LNK header: bytes 4-19 must be the LNK CLSID.
	if data[4] != 0x01 || data[5] != 0x14 {
		return jlEntry{}, false
	}

	created := filetimeAt(data, 28)
	accessed := filetimeAt(data, 36)
	modified := filetimeAt(data, 44)

	// Try to get target path from StringData section.
	targetPath := lnkStringTarget(data)

	return jlEntry{
		entryID:    streamName,
		targetPath: targetPath,
		created:    created,
		modified:   modified,
		accessed:   accessed,
	}, true
}

// lnkStringTarget reads the RELATIVE_PATH or WORKING_DIR from LNK StringData.
func lnkStringTarget(data []byte) string {
	if len(data) < 76 {
		return ""
	}
	linkFlags := binary.LittleEndian.Uint32(data[20:24])
	pos := 76

	// Skip IDList if present (bit 0).
	if linkFlags&0x01 != 0 {
		if pos+2 > len(data) {
			return ""
		}
		idListSize := int(binary.LittleEndian.Uint16(data[pos : pos+2]))
		pos += 2 + idListSize
	}

	// Skip LinkInfo if present (bit 1).
	if linkFlags&0x02 != 0 {
		if pos+4 > len(data) {
			return ""
		}
		liSize := int(binary.LittleEndian.Uint32(data[pos : pos+4]))
		if liSize < 4 {
			return ""
		}
		pos += liSize
	}

	if pos >= len(data) {
		return ""
	}

	isUnicode := linkFlags&0x80 != 0

	readStr := func() string {
		if pos+2 > len(data) {
			return ""
		}
		count := int(binary.LittleEndian.Uint16(data[pos : pos+2]))
		pos += 2
		if isUnicode {
			end := pos + count*2
			if end > len(data) {
				return ""
			}
			s := utf16LEString(data[pos:end])
			pos = end
			return s
		}
		end := pos + count
		if end > len(data) {
			return ""
		}
		s := string(data[pos:end])
		pos = end
		return s
	}

	// StringData order: NAME_STRING, RELATIVE_PATH, WORKING_DIR, CMD_ARGS, ICON_LOC
	var name, rel string
	if linkFlags&0x04 != 0 { // HasName
		name = readStr()
	}
	if linkFlags&0x08 != 0 { // HasRelativePath
		rel = readStr()
	}

	if rel != "" {
		return rel
	}
	return name
}

// ─── CustomDestinations ──────────────────────────────────────────────────────

// CustomDestinations footer magic.
const customFooter = uint32(0xBABFFBAB)

func parseCustomDestinations(data []byte) ([]jlEntry, error) {
	var entries []jlEntry
	pos := 0
	idx := 0
	for pos+4 < len(data) {
		// Read type marker (4 bytes), then LNK data.
		marker := binary.LittleEndian.Uint32(data[pos : pos+4])
		if marker == customFooter {
			break
		}
		pos += 4

		// Find next LNK magic or footer.
		end := findNextEntry(data, pos)
		if end <= pos {
			break
		}
		lnkData := data[pos:end]
		if e, ok := lnkEntry(fmt.Sprintf("entry_%d", idx), lnkData); ok {
			entries = append(entries, e)
			idx++
		}
		pos = end
	}
	return entries, nil
}

// findNextEntry locates the next LNK header or footer after pos.
func findNextEntry(data []byte, pos int) int {
	for i := pos; i+4 < len(data); i++ {
		v := binary.LittleEndian.Uint32(data[i : i+4])
		if v == customFooter {
			return i
		}
		// LNK header starts with size=0x4C (type marker for LNK), not 0.
		// Rather: next entry starts with a 4-byte type marker that is not the LNK payload.
		// Use the footer as the only reliable delimiter.
	}
	return len(data)
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func appIDFromPath(path string) string {
	base := strings.ToLower(filepath.Base(path))
	if i := strings.IndexByte(base, '.'); i > 0 {
		return base[:i]
	}
	return base
}

func nullTime(t time.Time) interface{} {
	if t.IsZero() {
		return nil
	}
	return t
}

func filetimeAt(data []byte, offset int) time.Time {
	if offset+8 > len(data) {
		return time.Time{}
	}
	const epoch = uint64(116444736000000000)
	ft := binary.LittleEndian.Uint64(data[offset : offset+8])
	if ft == 0 || ft < epoch {
		return time.Time{}
	}
	return time.Unix(0, int64((ft-epoch)*100)).UTC()
}

func utf16LEString(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[i*2 : i*2+2])
	}
	// Strip null terminator.
	for len(u) > 0 && u[len(u)-1] == 0 {
		u = u[:len(u)-1]
	}
	return string(utf16.Decode(u))
}

func u16slice(b []byte) []uint16 {
	n := len(b) / 2
	u := make([]uint16, n)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[i*2 : i*2+2])
	}
	return u
}

func cstring(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// knownAppID maps well-known AppIDs to human-readable application names.
func knownAppID(id string) string {
	known := map[string]string{
		"1b4dd67f29cb1962": "Explorer",
		"5da8f9b674986c19": "Microsoft Office Word",
		"b8ab874f5e7b8f2e": "Microsoft Office Excel",
		"b08f8b06c67b42bf": "Microsoft Office PowerPoint",
		"ae12ea2a5be2a2d7": "Notepad",
		"9b9cdc69c1c24e2b": "Command Prompt",
		"b7cdf4c72bf6a75f": "Windows PowerShell",
		"7e4dca80246863e3": "Outlook",
		"3c9a590b03f18f14": "Internet Explorer",
		"9d61274eebee32ba": "Mozilla Firefox",
		"9a16f9f5e3aceb60": "Google Chrome",
		"7c5a40ef0a24a5c1": "Adobe Acrobat Reader",
		"f01b4d95cf55d32a": "Task Manager",
		"d65231b0d2a4c5b8": "Regedit",
		"50e70be46609e0b3": "Paint",
		"c7efcf1c2f5e3ef3": "WinRAR",
		"1c6b3b67889524de": "7-Zip",
		"4fce25e2da3e9869": "PuTTY",
		"9b2dde1a2aa84a19": "FileZilla",
		"6e4c2c8a26d98e40": "Total Commander",
	}
	if name, ok := known[strings.ToLower(id)]; ok {
		return name
	}
	return ""
}
