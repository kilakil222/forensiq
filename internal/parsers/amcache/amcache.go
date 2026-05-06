// Package amcache parses the Windows Amcache.hve registry hive.
// It extracts executed-file entries from InventoryApplicationFile (Win10+)
// or the legacy Root\File path (Win7/8) and inserts them into the amcache
// DuckDB table.
package amcache

import (
	"database/sql"
	"fmt"
	"io"
	"strings"
	"time"

	"forensiq/internal/parsers"
)

// parseLinkDateString parses a LinkDate string like "10/25/2022 12:56:08" or "2022-10-25T12:56:08".
func parseLinkDateString(s string) time.Time {
	s = strings.TrimSpace(s)
	fmts := []string{
		"01/02/2006 15:04:05",
		"1/2/2006 15:04:05",
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
	}
	for _, f := range fmts {
		if t, err := time.ParseInLocation(f, s, time.UTC); err == nil && !t.IsZero() {
			return t
		}
	}
	return time.Time{}
}

// AmcacheParser implements parsers.Parser for Amcache.hve files.
type AmcacheParser struct{}

// New returns a new AmcacheParser.
func New() *AmcacheParser { return &AmcacheParser{} }

// Name returns "Amcache".
func (p *AmcacheParser) Name() string { return "Amcache" }

// Parse reads an Amcache.hve from r, parses executed-file entries, and inserts
// rows into the amcache table.
func (p *AmcacheParser) Parse(r io.Reader, db *sql.DB, ch chan<- parsers.Progress) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("amcache: read: %w", err)
	}
	return p.parseHive(data, db, ch)
}

// ParseWithLogs reads the hive from r, applies LOG1/LOG2 transaction log dirty
// pages (either may be nil), then parses the merged hive.
func (p *AmcacheParser) ParseWithLogs(r io.Reader, log1, log2 []byte, db *sql.DB, ch chan<- parsers.Progress) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("amcache: read: %w", err)
	}
	return p.parseHive(MergeWithLogs(data, log1, log2), db, ch)
}

// parseHive parses raw REGF hive bytes and inserts amcache rows.
func (p *AmcacheParser) parseHive(data []byte, db *sql.DB, ch chan<- parsers.Progress) error {
	start := time.Now()

	hive, err := openRegf(data)
	if err != nil {
		return fmt.Errorf("amcache: open hive: %w", err)
	}

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("amcache: begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.Prepare(`INSERT INTO amcache (path, sha256, first_seen, publisher, version) VALUES (?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("amcache: prepare insert: %w", err)
	}
	defer stmt.Close()

	var count int64

	// Try Win10+ path first.
	count, err = p.parseInventoryApplicationFile(hive.root, stmt, ch, start, count)
	if err != nil {
		// Fall back to Win7/8 legacy path.
		count, err = p.parseLegacyFile(hive.root, stmt, ch, start, count)
	}
	if count == 0 {
		// Hive may be dirty (live system, LOG pending). Fall back to raw NK scan:
		// search all allocated cells for the target key by name and iterate its
		// children directly, bypassing the normal subkey-list navigation.
		for _, nk := range hive.scanNKByName("InventoryApplicationFile") {
			entries, serr := nk.subkeys()
			if serr != nil {
				continue
			}
			for _, entry := range entries {
				path, sha256, publisher, version, firstSeen := extractWin10Entry(entry)
				if _, serr2 := stmt.Exec(path, sha256, nullableTime(firstSeen), nullableStr(publisher), nullableStr(version)); serr2 != nil {
					continue
				}
				count++
			}
		}
		if count == 0 {
			for _, nk := range hive.scanNKByName("File") {
				vols, serr := nk.subkeys()
				if serr != nil {
					continue
				}
				for _, vol := range vols {
					entries, serr2 := vol.subkeys()
					if serr2 != nil {
						continue
					}
					for _, entry := range entries {
						path, sha256, firstSeen := extractWin7Entry(entry)
						if _, serr3 := stmt.Exec(path, sha256, nullableTime(firstSeen), nil, nil); serr3 != nil {
							continue
						}
						count++
					}
				}
			}
		}
		if count == 0 && err != nil {
			return fmt.Errorf("amcache: no valid layout found: %w", err)
		}
		err = nil
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("amcache: commit: %w", err)
	}

	ch <- parsers.Progress{
		Parser:  p.Name(),
		Count:   count,
		Done:    true,
		Elapsed: time.Since(start),
	}
	return nil
}

// parseInventoryApplicationFile handles Win10+ Amcache layout under
// Root\InventoryApplicationFile. Each subkey is one application file entry.
func (p *AmcacheParser) parseInventoryApplicationFile(
	root *nkCell,
	stmt *sql.Stmt,
	ch chan<- parsers.Progress,
	start time.Time,
	count int64,
) (int64, error) {
	parent, err := root.openSubkey("Root\\InventoryApplicationFile")
	if err != nil {
		parent, err = root.openSubkey("InventoryApplicationFile")
	}
	if err != nil {
		return count, err
	}

	entries, err := parent.subkeys()
	if err != nil {
		return count, fmt.Errorf("amcache: list InventoryApplicationFile subkeys: %w", err)
	}

	for _, entry := range entries {
		path, sha256, publisher, version, firstSeen := extractWin10Entry(entry)
		if _, err := stmt.Exec(path, sha256, nullableTime(firstSeen), nullableStr(publisher), nullableStr(version)); err != nil {
			continue
		}
		count++
		if count%500 == 0 {
			select {
			case ch <- parsers.Progress{Parser: "Amcache", Count: count, Elapsed: time.Since(start)}:
			default:
			}
		}
	}
	return count, nil
}

// parseLegacyFile handles Win7/8 Amcache layout under Root\File.
// Structure: Root\File\{VolumeGUID}\{sequence} with values like "0" = path, "101" = SHA1.
func (p *AmcacheParser) parseLegacyFile(
	root *nkCell,
	stmt *sql.Stmt,
	ch chan<- parsers.Progress,
	start time.Time,
	count int64,
) (int64, error) {
	fileKey, err := root.openSubkey("Root\\File")
	if err != nil {
		fileKey, err = root.openSubkey("File")
	}
	if err != nil {
		return count, err
	}

	volumes, err := fileKey.subkeys()
	if err != nil {
		return count, fmt.Errorf("amcache: list File subkeys: %w", err)
	}

	for _, vol := range volumes {
		entries, err := vol.subkeys()
		if err != nil {
			continue
		}
		for _, entry := range entries {
			path, sha256, firstSeen := extractWin7Entry(entry)
			if _, err := stmt.Exec(path, sha256, nullableTime(firstSeen), nil, nil); err != nil {
				continue
			}
			count++
			if count%500 == 0 {
				select {
				case ch <- parsers.Progress{Parser: "Amcache", Count: count, Elapsed: time.Since(start)}:
				default:
				}
			}
		}
	}
	return count, nil
}

// extractWin10Entry reads path, hash, publisher, version and first-seen from a
// Win10 InventoryApplicationFile subkey. Value names per Mandiant/Velociraptor:
//
//	"LowerCaseLongPath" → full file path
//	"FileId"            → "0000" + SHA-1 (40 hex) or SHA-256 (64 hex)
//	"LinkDate"          → compile timestamp as REG_QWORD (FILETIME) or REG_SZ
//	"Publisher"         → publisher name
//	"FileVersion"       → file version string
func extractWin10Entry(nk *nkCell) (path, sha256, publisher, version string, firstSeen time.Time) {
	vals, err := nk.values()
	if err != nil {
		return
	}
	for _, v := range vals {
		switch {
		case equalFold(v.name, "LowerCaseLongPath"):
			path = v.getString()
		case equalFold(v.name, "FileId"):
			raw := v.getString()
			raw = strings.TrimPrefix(raw, "0000")
			// Accept SHA-1 (40 hex chars) and SHA-256 (64 hex chars).
			if len(raw) == 40 || len(raw) == 64 {
				sha256 = raw
			}
		case equalFold(v.name, "LinkDate"):
			if v.dataType == 11 && len(v.data) >= 8 {
				// REG_QWORD: FILETIME (100-ns ticks since 1601-01-01).
				firstSeen = filetimeToTime(v.getUint64())
			} else if v.dataType == 1 || v.dataType == 2 {
				// REG_SZ: date string e.g. "10/25/2022 12:56:08".
				firstSeen = parseLinkDateString(v.getString())
			}
		case equalFold(v.name, "Publisher"):
			publisher = v.getString()
		case equalFold(v.name, "FileVersion"):
			version = v.getString()
		case equalFold(v.name, "BinProductVersion") && version == "":
			version = v.getString()
		}
	}
	return
}

// extractWin7Entry reads path, SHA-1 (stored as sha256 field) and first-seen
// from a Win7/8 legacy Amcache File entry.
// Key value names are numeric strings:
//
//	"0"   → full path
//	"f"   → first-seen FILETIME (REG_QWORD)
//	"101" → SHA-1 hash (stored in sha256 column for now)
func extractWin7Entry(nk *nkCell) (path, sha1 string, firstSeen time.Time) {
	vals, err := nk.values()
	if err != nil {
		return
	}
	for _, v := range vals {
		switch v.name {
		case "0":
			path = v.getString()
		case "101":
			raw := v.getString()
			// Strip leading "0000" prefix sometimes present.
			raw = strings.TrimPrefix(raw, "0000")
			sha1 = raw
		case "f":
			if v.dataType == 11 && len(v.data) >= 8 {
				firstSeen = filetimeToTime(v.getUint64())
			}
		}
	}
	return
}

// filetimeToTime converts a Windows FILETIME (100-ns ticks since 1601-01-01)
// to a Go time.Time. Returns zero Time for invalid or pre-Unix-epoch values.
func filetimeToTime(ft uint64) time.Time {
	const epoch = uint64(116444736000000000) // ticks from 1601 to 1970
	if ft == 0 || ft < epoch {
		return time.Time{}
	}
	return time.Unix(0, int64((ft-epoch)*100)).UTC()
}

// nullableTime returns nil for zero time, otherwise the time value.
func nullableTime(t time.Time) interface{} {
	if t.IsZero() {
		return nil
	}
	return t
}

// nullableStr returns nil for empty string, otherwise the string value.
func nullableStr(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}
