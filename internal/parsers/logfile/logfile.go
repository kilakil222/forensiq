// Package logfile parses the NTFS $LogFile (LFS format) transaction log.
// It scans RCRD pages and extracts log record operation codes plus any
// embedded filenames (UTF-16LE) for forensic reconstruction of file activity.
package logfile

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

// Parser implements parsers.Parser for NTFS $LogFile.
type Parser struct{}

func New() *Parser { return &Parser{} }

func (p *Parser) Name() string { return "NTFS/$LogFile" }

// LFS page size is always 4096 bytes for $LogFile.
const pageSize = 4096

// Signatures.
var sigRCRD = [4]byte{'R', 'C', 'R', 'D'}
var sigRSTR = [4]byte{'R', 'S', 'T', 'R'}

// NTFS log record operation codes we care about.
var opNames = map[uint16]string{
	0x0001: "Noop",
	0x0002: "CompensationLogRecord",
	0x0003: "InitializeFileRecordSegment", // file created
	0x0004: "DeallocateFileRecordSegment", // file deleted
	0x0005: "WriteEndOfFileRecordSegment",
	0x0006: "CreateAttribute",
	0x0007: "DeleteAttribute",
	0x0008: "UpdateResidentValue",
	0x0009: "UpdateNonresidentValue",
	0x000A: "UpdateMappingPairs",
	0x000B: "DeleteDirtyClusters",
	0x000C: "SetNewAttributeSizes",
	0x000D: "AddIndexEntryRoot",       // dir entry added (create/rename)
	0x000E: "DeleteIndexEntryRoot",    // dir entry deleted (delete/rename from)
	0x000F: "AddIndexEntryAllocation", // same, non-resident index
	0x0010: "DeleteIndexEntryAllocation",
	0x001E: "SetIndexEntryVcnRoot",
	0x001F: "SetIndexEntryVcnAllocation",
	0x0028: "SetBitsInNonresidentBitMap",
	0x0029: "ClearBitsInNonresidentBitMap",
}

// fileActivityOps are the operation codes that indicate meaningful file activity.
var fileActivityOps = map[uint16]bool{
	0x0003: true,
	0x0004: true,
	0x000D: true,
	0x000E: true,
	0x000F: true,
	0x0010: true,
}

// logRecord holds decoded fields from a single LFS log record.
type logRecord struct {
	lsn           int64
	transactionID uint32
	redoOp        uint16
	undoOp        uint16
	targetAttr    uint16
	// offset and length of redo data within the page
	redoOffset uint16
	redoLength uint16
}

// Parse reads the $LogFile stream and inserts events into logfile_events.
func (p *Parser) Parse(r io.Reader, db *sql.DB, ch chan<- parsers.Progress) error {
	start := time.Now()

	data, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("logfile: read: %w", err)
	}

	count, err := parseLogFile(data, db, ch, start)
	if err != nil {
		ch <- parsers.Progress{Parser: p.Name(), Err: err, Done: true, Elapsed: time.Since(start)}
		return err
	}
	ch <- parsers.Progress{Parser: p.Name(), Count: count, Done: true, Elapsed: time.Since(start)}
	return nil
}

func parseLogFile(data []byte, db *sql.DB, ch chan<- parsers.Progress, start time.Time) (int64, error) {
	if len(data) < pageSize*3 {
		return 0, fmt.Errorf("logfile: file too short (%d bytes)", len(data))
	}

	tx, err := db.Begin()
	if err != nil {
		return 0, fmt.Errorf("logfile: begin tx: %w", err)
	}
	defer tx.Rollback() //nolint

	stmt, err := tx.Prepare(`INSERT INTO logfile_events
		(lsn, operation, op_code, transaction_id, target_attr, filename, timestamp)
		VALUES (?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return 0, fmt.Errorf("logfile: prepare: %w", err)
	}
	defer stmt.Close()

	var count int64
	numPages := len(data) / pageSize

	for pageIdx := 2; pageIdx < numPages; pageIdx++ {
		offset := pageIdx * pageSize
		page := data[offset : offset+pageSize]

		// Check RCRD signature.
		if page[0] != 'R' || page[1] != 'C' || page[2] != 'R' || page[3] != 'D' {
			continue
		}

		// Apply Update Sequence Array (USA) fixup.
		pageCopy := applyUSAFixup(page)
		if pageCopy == nil {
			continue
		}

		// Extract next_record_offset from page header (offset 24, 2 bytes).
		if len(pageCopy) < 32 {
			continue
		}
		nextRecOff := int(binary.LittleEndian.Uint16(pageCopy[24:26]))
		if nextRecOff < 28 || nextRecOff >= pageSize {
			nextRecOff = 40 // fallback: right after the page header
		}

		// Scan records starting at nextRecOff.
		pos := nextRecOff
		for pos+72 <= pageSize {
			rec, ok := decodeLogRecord(pageCopy, pos)
			if !ok {
				pos += 8 // advance and retry
				continue
			}

			opName, known := opNames[rec.redoOp]
			if !known {
				pos += 8
				continue
			}

			// Only record meaningful file activity operations.
			if !fileActivityOps[rec.redoOp] {
				// Still advance: compute record size or step minimally.
				pos += 72
				continue
			}

			// Try to extract a filename from the redo data embedded in this page.
			filename := ""
			if rec.redoLength > 0 && int(rec.redoOffset)+int(rec.redoLength) <= pageSize {
				redoData := pageCopy[rec.redoOffset : rec.redoOffset+rec.redoLength]
				filename = extractFilenameFromData(redoData)
				if filename == "" {
					// Also scan a wider window around the record offset.
					scanStart := pos + 72
					scanEnd := scanStart + 256
					if scanEnd > pageSize {
						scanEnd = pageSize
					}
					if scanStart < pageSize {
						filename = extractFilenameFromData(pageCopy[scanStart:scanEnd])
					}
				}
			}

			func() {
				defer func() { recover() }() //nolint
				_, execErr := stmt.Exec(
					rec.lsn,
					opName,
					int(rec.redoOp),
					int64(rec.transactionID),
					int(rec.targetAttr),
					nullString(filename),
					nil, // $LogFile has no per-record timestamp
				)
				if execErr == nil {
					count++
				}
			}()

			pos += 72 // minimum record size; real records are variable but we step forward
		}
	}

	if err := tx.Commit(); err != nil {
		return count, fmt.Errorf("logfile: commit: %w", err)
	}
	return count, nil
}

// applyUSAFixup applies the Update Sequence Array fixup to a page copy.
// Returns nil if the page is invalid.
func applyUSAFixup(page []byte) []byte {
	if len(page) < 8 {
		return nil
	}
	usaOffset := int(binary.LittleEndian.Uint16(page[4:6]))
	usaSize := int(binary.LittleEndian.Uint16(page[6:8]))

	if usaOffset < 4 || usaSize < 2 || usaOffset+usaSize*2 > len(page) {
		// Can't apply fixup — return copy as-is.
		cp := make([]byte, len(page))
		copy(cp, page)
		return cp
	}

	cp := make([]byte, len(page))
	copy(cp, page)

	// USA[0] is the sequence number to verify; USA[1..N] are the saved originals.
	// seqNum := binary.LittleEndian.Uint16(cp[usaOffset:]) // check value (unused)
	for i := 1; i < usaSize; i++ {
		sectorEnd := i*512 - 2
		if sectorEnd+1 >= len(cp) {
			break
		}
		savedLo := cp[usaOffset+i*2]
		savedHi := cp[usaOffset+i*2+1]
		cp[sectorEnd] = savedLo
		cp[sectorEnd+1] = savedHi
	}
	return cp
}

// decodeLogRecord tries to decode a log record at the given offset within a page.
func decodeLogRecord(page []byte, offset int) (logRecord, bool) {
	if offset+72 > len(page) {
		return logRecord{}, false
	}
	b := page[offset:]

	lsn := int64(binary.LittleEndian.Uint64(b[0:8]))
	// Basic sanity: LSN must be positive and reasonable.
	if lsn <= 0 || lsn > 0x00FFFFFFFFFFFFFF {
		return logRecord{}, false
	}

	transID := binary.LittleEndian.Uint32(b[24:28])
	// recordType := binary.LittleEndian.Uint32(b[28:32]) // 1=redo, 2=undo
	redoOp := binary.LittleEndian.Uint16(b[36:38])
	undoOp := binary.LittleEndian.Uint16(b[38:40])
	redoOffset := binary.LittleEndian.Uint16(b[40:42])
	redoLength := binary.LittleEndian.Uint16(b[42:44])
	targetAttr := binary.LittleEndian.Uint16(b[48:50])

	// Validate operation code range.
	if redoOp > 0x30 {
		return logRecord{}, false
	}

	return logRecord{
		lsn:           lsn,
		transactionID: transID,
		redoOp:        redoOp,
		undoOp:        undoOp,
		redoOffset:    redoOffset,
		redoLength:    redoLength,
		targetAttr:    targetAttr,
	}, true
}

// extractFilenameFromData scans a byte slice for UTF-16LE encoded filenames.
// NTFS filenames are stored as UTF-16LE; we look for printable ASCII/Latin characters
// in a UTF-16LE pattern (every other byte is 0x00 for ASCII chars).
func extractFilenameFromData(data []byte) string {
	if len(data) < 4 {
		return ""
	}

	// Try to find a UTF-16LE string: pairs where the high byte is 0 and
	// the low byte is a printable ASCII character.
	best := ""
	i := 0
	for i+1 < len(data) {
		// Detect start of UTF-16LE sequence.
		lo := data[i]
		hi := data[i+1]
		if hi == 0x00 && isPrintableASCII(lo) {
			// Collect the UTF-16LE sequence.
			start := i
			j := i
			u16chars := []uint16{}
			for j+1 < len(data) {
				c := binary.LittleEndian.Uint16(data[j:])
				if c == 0 {
					break
				}
				// Allow printable chars, dots, dashes, underscores, spaces.
				if c > 0x007E && c < 0x0020 {
					break
				}
				u16chars = append(u16chars, c)
				j += 2
			}
			if len(u16chars) >= 3 {
				runes := utf16.Decode(u16chars)
				var sb strings.Builder
				for _, r := range runes {
					if r < 0x20 || r > 0xFFFF {
						break
					}
					sb.WriteRune(r)
				}
				s := sb.String()
				// Must look like a filename: contains a dot or is mostly alphanumeric.
				if isLikelyFilename(s) && len(s) > len(best) {
					best = s
				}
				i = start + 2
				continue
			}
		}
		i++
		_ = sigRSTR // suppress unused var warning
	}
	return best
}

func isPrintableASCII(b byte) bool {
	return b >= 0x20 && b <= 0x7E
}

func isLikelyFilename(s string) bool {
	if len(s) < 3 || len(s) > 260 {
		return false
	}
	// Must contain at least one alphanumeric character.
	alphanum := 0
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			alphanum++
		}
	}
	if alphanum < 2 {
		return false
	}
	// Should not be all spaces.
	return strings.TrimSpace(s) != ""
}

func nullString(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}
