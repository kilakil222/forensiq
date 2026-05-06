package recyclebin

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

// RecycleBinParser parses Windows $I recycle bin metadata files.
// Format: $Recycle.Bin\{SID}\$I<random>.<ext>
type RecycleBinParser struct {
	iFile string // original $I filename (e.g. "$Iabc123.txt")
	sid   string // SID extracted from path
}

func New(filePath string) *RecycleBinParser {
	base := filepath.Base(filePath)
	sid := sidFromPath(filePath)
	return &RecycleBinParser{iFile: base, sid: sid}
}

func (p *RecycleBinParser) Name() string { return "RecycleBin" }

func (p *RecycleBinParser) Parse(r io.Reader, db *sql.DB, ch chan<- parsers.Progress) error {
	start := time.Now()
	data, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("recyclebin: read: %w", err)
	}
	if len(data) < 28 {
		return fmt.Errorf("recyclebin: $I file too short: %d bytes", len(data))
	}

	version := int64(binary.LittleEndian.Uint64(data[0:8]))
	fileSize := int64(binary.LittleEndian.Uint64(data[8:16]))
	deletedAt := filetimeToTime(binary.LittleEndian.Uint64(data[16:24]))

	var origPath string
	switch version {
	case 1:
		// Fixed 520-byte UTF-16LE path at offset 24
		if len(data) < 24+520 {
			return fmt.Errorf("recyclebin: v1 file too short: %d bytes", len(data))
		}
		origPath = decodeUTF16LE(data[24 : 24+520])
	case 2:
		// 4-byte path length (in chars) at offset 24, then variable UTF-16LE
		if len(data) < 28 {
			return fmt.Errorf("recyclebin: v2 file too short: %d bytes", len(data))
		}
		pathLen := int(binary.LittleEndian.Uint32(data[24:28]))
		end := 28 + pathLen*2
		if len(data) < end {
			end = len(data)
		}
		origPath = decodeUTF16LE(data[28:end])
	default:
		return fmt.Errorf("recyclebin: unknown $I version %d", version)
	}

	// Derive $R filename from $I filename: replace leading $I with $R
	rFile := ""
	if strings.HasPrefix(strings.ToUpper(p.iFile), "$I") {
		rFile = "$R" + p.iFile[2:]
	}

	_, err = db.Exec(`INSERT INTO recycle_bin (original_path, deleted_at, size, sid, i_file, r_file)
		VALUES (?, ?, ?, ?, ?, ?)`,
		origPath, deletedAt, fileSize, p.sid, p.iFile, rFile,
	)
	if err != nil {
		return fmt.Errorf("recyclebin: insert: %w", err)
	}

	if ch != nil {
		ch <- parsers.Progress{Parser: "RecycleBin", Count: 1, Done: true, Elapsed: time.Since(start)}
	}
	return nil
}

// sidFromPath extracts the SID from a path like "$Recycle.Bin/S-1-5-21-xxx/$Iabc.txt"
func sidFromPath(path string) string {
	parts := strings.Split(filepath.ToSlash(path), "/")
	for _, part := range parts {
		if strings.HasPrefix(part, "S-1-") {
			return part
		}
	}
	// Also try backslash split
	parts = strings.Split(path, `\`)
	for _, part := range parts {
		if strings.HasPrefix(part, "S-1-") {
			return part
		}
	}
	return ""
}

func decodeUTF16LE(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	u16 := make([]uint16, len(b)/2)
	for i := range u16 {
		u16[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	// Trim at first null
	for i, c := range u16 {
		if c == 0 {
			u16 = u16[:i]
			break
		}
	}
	return string(utf16.Decode(u16))
}

func filetimeToTime(ft uint64) time.Time {
	if ft == 0 {
		return time.Time{}
	}
	const epoch = int64(116444736000000000)
	ns := (int64(ft) - epoch) * 100
	return time.Unix(0, ns).UTC()
}
