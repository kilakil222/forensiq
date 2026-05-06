// Package mft parses the NTFS Master File Table ($MFT).
// It reads the raw $MFT file from an io.Reader, writes it to a temp file
// (required for seekable access by go-ntfs), then iterates all MFT entries
// and inserts them into the mft DuckDB table.
package mft

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"io"
	"time"

	ntfsparser "www.velocidex.com/golang/go-ntfs/parser"

	"forensiq/internal/parsers"
)

// Standard NTFS constants used when the MFT is parsed standalone
// (without a disk boot sector to derive these from).
const (
	defaultClusterSize = 4096
	defaultRecordSize  = 1024
)

// MFTParser implements parsers.Parser for raw $MFT files.
type MFTParser struct{}

// New returns a new MFTParser.
func New() *MFTParser { return &MFTParser{} }

// Name returns "$MFT".
func (p *MFTParser) Name() string { return "$MFT" }

// Parse reads the raw $MFT bytes from r, parses all MFT entries using
// go-ntfs, and inserts rows into the mft table.
func (p *MFTParser) Parse(r io.Reader, db *sql.DB, ch chan<- parsers.Progress) error {
	start := time.Now()

	// Read the entire $MFT into memory so we have a seekable ReaderAt.
	data, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("mft: read: %w", err)
	}

	mftReader := bytes.NewReader(data)
	mftSize := int64(len(data))

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("mft: begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.Prepare(`INSERT INTO mft
		(inode, path, size, created, modified, accessed, mft_modified, is_dir, is_deleted)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("mft: prepare insert: %w", err)
	}
	defer stmt.Close()

	ctx := context.Background()
	rowCh := ntfsparser.ParseMFTFile(ctx, mftReader, mftSize, defaultClusterSize, defaultRecordSize)

	var count int64
	for row := range rowCh {
		fullPath := row.FullPath()
		isDeleted := !row.InUse

		created := nullableTime(row.Created0x10)
		modified := nullableTime(row.LastModified0x10)
		accessed := nullableTime(row.LastAccess0x10)
		mftModified := nullableTime(row.LastRecordChange0x10)

		if _, err := stmt.Exec(
			row.EntryNumber,
			fullPath,
			row.FileSize,
			created,
			modified,
			accessed,
			mftModified,
			row.IsDir,
			isDeleted,
		); err != nil {
			// Skip individual insert errors, continue processing.
			continue
		}

		count++
		if count%100000 == 0 {
			select {
			case ch <- parsers.Progress{Parser: p.Name(), Count: count, Elapsed: time.Since(start)}:
			default:
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("mft: commit: %w", err)
	}

	ch <- parsers.Progress{
		Parser:  p.Name(),
		Count:   count,
		Done:    true,
		Elapsed: time.Since(start),
	}
	return nil
}

// nullableTime returns nil for zero time so DuckDB stores NULL.
func nullableTime(t time.Time) interface{} {
	if t.IsZero() {
		return nil
	}
	return t
}
