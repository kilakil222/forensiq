// Package usnjrnl parses NTFS $UsnJrnl:$J streams.
// The $J stream is a sparse file; each USN v2 record (variable length, ≥60 bytes)
// is preceded by zero-filled sparse gaps which are skipped automatically.
package usnjrnl

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

// UsnJrnlParser parses the $UsnJrnl:$J binary stream.
type UsnJrnlParser struct{}

func New() *UsnJrnlParser { return &UsnJrnlParser{} }
func (p *UsnJrnlParser) Name() string { return "UsnJrnl" }

// USN v2 record field offsets
const (
	offRecordLen        = 0
	offMajorVersion     = 4
	offMinorVersion     = 6
	offFileRef          = 8
	offParentRef        = 16
	offUsn              = 24
	offTimestamp        = 32
	offReason           = 40
	offSourceInfo       = 44
	offSecurityID       = 48
	offFileAttributes   = 52
	offFileNameLength   = 56
	offFileNameOffset   = 58
	offFileName         = 60
	minRecordSize       = 60
	blockSize           = 512 // granularity for skipping zero blocks
)

// USN reason flags
var reasonNames = []struct {
	bit  uint32
	name string
}{
	{0x00000001, "DATA_OVERWRITE"},
	{0x00000002, "DATA_EXTEND"},
	{0x00000004, "DATA_TRUNCATION"},
	{0x00000100, "FILE_CREATE"},
	{0x00000200, "FILE_DELETE"},
	{0x00000800, "SECURITY_CHANGE"},
	{0x00001000, "RENAME_OLD"},
	{0x00002000, "RENAME_NEW"},
	{0x00008000, "BASIC_INFO_CHANGE"},
	{0x80000000, "CLOSE"},
}

func reasonStr(r uint32) string {
	var parts []string
	for _, rn := range reasonNames {
		if r&rn.bit != 0 {
			parts = append(parts, rn.name)
		}
	}
	if len(parts) == 0 {
		return fmt.Sprintf("0x%08x", r)
	}
	return strings.Join(parts, "|")
}

func (p *UsnJrnlParser) Parse(r io.Reader, db *sql.DB, ch chan<- parsers.Progress) error {
	start := time.Now()

	data, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("usnjrnl: read: %w", err)
	}

	stmt, err := db.Prepare(`INSERT INTO usnjrnl (usn, path, reason, timestamp, file_attributes, source_info) VALUES (?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("usnjrnl: prepare: %w", err)
	}
	defer stmt.Close()

	var count int64
	pos := 0

	for pos < len(data) {
		// Skip zero-filled sparse blocks
		if pos+4 <= len(data) && binary.LittleEndian.Uint32(data[pos:pos+4]) == 0 {
			// Advance to next block boundary where data might start
			next := (pos/blockSize + 1) * blockSize
			if next <= pos {
				next = pos + blockSize
			}
			if next > len(data) {
				break
			}
			pos = next
			continue
		}

		if pos+minRecordSize > len(data) {
			break
		}

		recLen := int(binary.LittleEndian.Uint32(data[pos+offRecordLen:]))
		if recLen < minRecordSize || pos+recLen > len(data) {
			pos += 8 // try to re-sync on 8-byte boundary
			continue
		}

		major := binary.LittleEndian.Uint16(data[pos+offMajorVersion:])
		if major != 2 {
			pos += 8
			continue
		}

		rec := data[pos : pos+recLen]

		usn := int64(binary.LittleEndian.Uint64(rec[offUsn:]))
		ft := binary.LittleEndian.Uint64(rec[offTimestamp:])
		ts := filetimeToTime(ft)
		reason := binary.LittleEndian.Uint32(rec[offReason:])
		sourceInfo := binary.LittleEndian.Uint32(rec[offSourceInfo:])
		fileAttrs := binary.LittleEndian.Uint32(rec[offFileAttributes:])
		fnLen := int(binary.LittleEndian.Uint16(rec[offFileNameLength:]))
		fnOff := int(binary.LittleEndian.Uint16(rec[offFileNameOffset:]))

		var filename string
		if fnOff >= minRecordSize && fnOff+fnLen <= recLen && fnLen > 0 {
			filename = decodeUTF16LE(rec[fnOff : fnOff+fnLen])
		}

		sourceStr := ""
		if sourceInfo != 0 {
			sourceStr = fmt.Sprintf("0x%x", sourceInfo)
		}

		if _, err := stmt.Exec(usn, filename, reasonStr(reason), ts, int(fileAttrs), sourceStr); err == nil {
			count++
		}

		pos += recLen
		// Align to 8-byte boundary
		if pos%8 != 0 {
			pos += 8 - (pos % 8)
		}
	}

	ch <- parsers.Progress{Parser: p.Name(), Count: count, Done: true, Elapsed: time.Since(start)}
	return nil
}

func decodeUTF16LE(b []byte) string {
	u16 := make([]uint16, len(b)/2)
	for i := range u16 {
		u16[i] = binary.LittleEndian.Uint16(b[i*2 : i*2+2])
	}
	runes := utf16.Decode(u16)
	return string(runes)
}

const filetimeEpoch = uint64(116444736000000000) // 100ns intervals from 1601-01-01

func filetimeToTime(ft uint64) time.Time {
	if ft == 0 || ft < filetimeEpoch {
		return time.Time{}
	}
	return time.Unix(0, int64((ft-filetimeEpoch)*100)).UTC()
}
