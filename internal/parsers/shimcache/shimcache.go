// Package shimcache parses the Windows Application Compatibility Cache
// (Shimcache) stored in the SYSTEM registry hive under:
//
//	ControlSet001\Control\Session Manager\AppCompatCache → AppCompatCache (REG_BINARY)
//
// Supported formats:
//   - Win7  (signature 0xDEADBEEF): 528-byte entries with FILETIME + path length + path
//   - Win8+ (signature 0x00000080): variable-length entries with FILETIME + path
package shimcache

import (
	"database/sql"
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"forensiq/internal/parsers"
)

// ShimcacheParser implements parsers.Parser for SYSTEM hive files.
type ShimcacheParser struct{}

// New returns a new ShimcacheParser.
func New() *ShimcacheParser { return &ShimcacheParser{} }

// Name returns "Shimcache".
func (p *ShimcacheParser) Name() string { return "Shimcache" }

// controlSetPaths lists the registry paths to try for AppCompatCache, in order.
var controlSetPaths = []string{
	`ControlSet001\Control\Session Manager\AppCompatCache`,
	`ControlSet002\Control\Session Manager\AppCompatCache`,
	`CurrentControlSet\Control\Session Manager\AppCompatCache`,
}

// Parse reads a SYSTEM hive from r, locates the AppCompatCache binary blob,
// parses Shimcache entries, and inserts them into the shimcache table.
func (p *ShimcacheParser) Parse(r io.Reader, db *sql.DB, ch chan<- parsers.Progress) error {
	start := time.Now()

	data, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("shimcache: read: %w", err)
	}

	hive, err := openRegf(data)
	if err != nil {
		return fmt.Errorf("shimcache: open hive: %w", err)
	}

	// Find AppCompatCache value by trying all known control-set paths.
	blob, err := p.findBlob(hive.root)
	if err != nil {
		return fmt.Errorf("shimcache: %w", err)
	}

	entries, err := parseBlob(blob)
	if err != nil {
		return fmt.Errorf("shimcache: parse blob: %w", err)
	}

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("shimcache: begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.Prepare(`INSERT INTO shimcache (path, last_modified, order_idx) VALUES (?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("shimcache: prepare insert: %w", err)
	}
	defer stmt.Close()

	var count int64
	for _, e := range entries {
		var modTime interface{}
		if !e.lastModified.IsZero() {
			modTime = e.lastModified
		}
		if _, err := stmt.Exec(e.path, modTime, e.orderIdx); err != nil {
			continue
		}
		count++
		if count%500 == 0 {
			select {
			case ch <- parsers.Progress{Parser: p.Name(), Count: count, Elapsed: time.Since(start)}:
			default:
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("shimcache: commit: %w", err)
	}

	ch <- parsers.Progress{
		Parser:  p.Name(),
		Count:   count,
		Done:    true,
		Elapsed: time.Since(start),
	}
	return nil
}

// findBlob locates the AppCompatCache REG_BINARY value.
func (p *ShimcacheParser) findBlob(root *nkCell) ([]byte, error) {
	var lastErr error
	for _, path := range controlSetPaths {
		key, err := root.openSubkey(path)
		if err != nil {
			lastErr = err
			continue
		}
		val, err := key.valueByName("AppCompatCache")
		if err != nil {
			lastErr = err
			continue
		}
		return val.data, nil
	}
	if lastErr != nil {
		return nil, fmt.Errorf("AppCompatCache not found: %w", lastErr)
	}
	return nil, fmt.Errorf("AppCompatCache not found")
}

// shimEntry holds one parsed Shimcache entry.
type shimEntry struct {
	path         string
	lastModified time.Time
	orderIdx     int
}

const (
	sigWin7     = 0xDEADBEEF
	sigWin8     = 0x00000080
	sigWin10    = 0x00000030 // Win10 RS1/RS2
	sigWin10v34 = 0x00000034 // Win10 RS3+ (1709 / 22H2)
)

// parseBlob dispatches to the correct format parser based on the header signature.
func parseBlob(blob []byte) ([]shimEntry, error) {
	if len(blob) < 4 {
		return nil, fmt.Errorf("blob too short (%d bytes)", len(blob))
	}
	sig := binary.LittleEndian.Uint32(blob[0:4])
	switch sig {
	case sigWin7:
		return parseWin7(blob)
	case sigWin8, sigWin10:
		return parseWin8Plus(blob)
	case sigWin10v34:
		return parseWin10RS3(blob)
	default:
		// Unknown signature — try newer format first, then fall back.
		entries, err := parseWin10RS3(blob)
		if err == nil && len(entries) > 0 {
			return entries, nil
		}
		entries, err = parseWin8Plus(blob)
		if err != nil {
			return nil, fmt.Errorf("unknown shimcache signature 0x%08X", sig)
		}
		return entries, nil
	}
}

// Win7 Shimcache layout:
//
//	Header: 4-byte sig (0xDEADBEEF) + 4-byte entry count + 8-byte padding = 16 bytes
//	Each entry: 528 bytes
//	  [0:2]   path length (uint16)
//	  [2:4]   max path length (uint16)
//	  [4:8]   path offset (uint32, relative to blob start)
//	  [8:16]  last-modified FILETIME (uint64)
//	  [16:24] file size (uint64)
//	  [24:32] last-updated FILETIME (uint64)
//
// NOTE: In the Win7 32-bit format the path is inline at offset 10 within the
// entry structure (different from 64-bit). We handle the 64-bit variant here
// which is most common on modern systems.
func parseWin7(blob []byte) ([]shimEntry, error) {
	if len(blob) < 16 {
		return nil, fmt.Errorf("win7: blob too short")
	}
	count := int(binary.LittleEndian.Uint32(blob[4:8]))
	if count <= 0 || count > 10000 {
		return nil, fmt.Errorf("win7: suspicious entry count %d", count)
	}

	const entrySize = 528
	var entries []shimEntry
	off := 16 // header size
	for i := 0; i < count; i++ {
		if off+entrySize > len(blob) {
			break
		}
		entry := blob[off : off+entrySize]
		pathLen := int(binary.LittleEndian.Uint16(entry[0:2]))
		pathOff := int(binary.LittleEndian.Uint32(entry[4:8]))
		ft := binary.LittleEndian.Uint64(entry[8:16])

		var path string
		if pathOff > 0 && pathOff+pathLen <= len(blob) {
			path = decodeUTF16LE(blob[pathOff : pathOff+pathLen])
		} else if pathLen <= 488 {
			// Some formats store path inline starting at entry offset 10.
			inlineOff := off + 10
			if inlineOff+pathLen <= len(blob) {
				path = decodeUTF16LE(blob[inlineOff : inlineOff+pathLen])
			}
		}

		entries = append(entries, shimEntry{
			path:         path,
			lastModified: filetimeToTime(ft),
			orderIdx:     i,
		})
		off += entrySize
	}
	return entries, nil
}

// Win8+ Shimcache layout:
//
//	Header: 4-byte sig + 4-byte padding = 8 bytes, then entries follow.
//	Each entry starts with tag "10ts" (Windows 8) or similar.
//	  [0:4]   tag "10ts"
//	  [4:8]   data size (uint32) — size of the rest of this entry
//	  [8:16]  last-modified FILETIME (uint64)
//	  [16:18] path length (uint16)
//	  [18:]   path (UTF-16LE, pathLength bytes)
//
// Win10 uses tag "10ts" as well but sometimes with extra fields before path.
func parseWin8Plus(blob []byte) ([]shimEntry, error) {
	if len(blob) < 8 {
		return nil, fmt.Errorf("win8+: blob too short")
	}

	// Scan for "10ts" tag — it appears right after the 128-byte header on some
	// builds, or right at offset 128.
	startOff := findTag(blob, []byte("10ts"))
	if startOff < 0 {
		return nil, fmt.Errorf("win8+: tag '10ts' not found in blob")
	}

	var entries []shimEntry
	off := startOff
	idx := 0
	for off+12 <= len(blob) {
		if string(blob[off:off+4]) != "10ts" {
			break
		}
		dataSize := int(binary.LittleEndian.Uint32(blob[off+4 : off+8]))
		if dataSize < 10 || off+8+dataSize > len(blob) {
			break
		}
		entryData := blob[off+8 : off+8+dataSize]

		ft := binary.LittleEndian.Uint64(entryData[0:8])
		pathLen := int(binary.LittleEndian.Uint16(entryData[8:10]))

		var path string
		if len(entryData) >= 10+pathLen {
			path = decodeUTF16LE(entryData[10 : 10+pathLen])
		}

		entries = append(entries, shimEntry{
			path:         path,
			lastModified: filetimeToTime(ft),
			orderIdx:     idx,
		})
		idx++
		off += 8 + dataSize
	}
	return entries, nil
}

// Win10 RS3+ (signature 0x34, builds 1709 / 22H2) Shimcache layout:
//
//	Each "10ts" entry:
//	  [0:4]   tag "10ts"
//	  [4:8]   path hash (uint32, ignored)
//	  [8:12]  data_size (uint32) — bytes of entry after this 12-byte header
//	  [12:14] path length (uint16)
//	  [14:]   path (UTF-16LE, pathLength bytes)
//	  [14+pathLen:] additional fields (insertion flags, timestamps — skipped)
//
// Advancement: off += 12 + data_size
func parseWin10RS3(blob []byte) ([]shimEntry, error) {
	if len(blob) < 12 {
		return nil, fmt.Errorf("win10rs3: blob too short")
	}
	startOff := findTag(blob, []byte("10ts"))
	if startOff < 0 {
		return nil, fmt.Errorf("win10rs3: tag '10ts' not found in blob")
	}

	var entries []shimEntry
	off := startOff
	idx := 0
	for off+12 <= len(blob) {
		if string(blob[off:off+4]) != "10ts" {
			break
		}
		dataSize := int(binary.LittleEndian.Uint32(blob[off+8 : off+12]))
		if dataSize < 2 || off+12+dataSize > len(blob) {
			break
		}
		pathLen := int(binary.LittleEndian.Uint16(blob[off+12 : off+14]))

		var path string
		if pathLen > 0 && off+14+pathLen <= len(blob) {
			path = decodeUTF16LE(blob[off+14 : off+14+pathLen])
		}

		entries = append(entries, shimEntry{
			path:     path,
			orderIdx: idx,
		})
		idx++
		off += 12 + dataSize
	}
	return entries, nil
}

// findTag searches for a 4-byte tag in blob and returns its offset, or -1.
func findTag(blob []byte, tag []byte) int {
	for i := 0; i <= len(blob)-4; i++ {
		if blob[i] == tag[0] && blob[i+1] == tag[1] && blob[i+2] == tag[2] && blob[i+3] == tag[3] {
			return i
		}
	}
	return -1
}

// filetimeToTime converts a Windows FILETIME to Go time.Time.
// Returns zero Time for zero or pre-Unix-epoch values.
func filetimeToTime(ft uint64) time.Time {
	const epoch = uint64(116444736000000000)
	if ft == 0 || ft < epoch {
		return time.Time{}
	}
	return time.Unix(0, int64((ft-epoch)*100)).UTC()
}
