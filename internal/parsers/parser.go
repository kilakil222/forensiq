package parsers

import (
	"database/sql"
	"io"
	"time"
)

// Parser extracts one artifact type and writes rows into DuckDB.
type Parser interface {
	// Name returns a human-readable label for progress display (e.g., "EVTX/Security").
	Name() string
	// Parse reads from r and inserts rows into db. Reports progress via ch.
	Parse(r io.Reader, db *sql.DB, ch chan<- Progress) error
}

// Progress is sent by parsers to report extraction progress.
type Progress struct {
	Parser  string
	Count   int64
	Done    bool
	Err     error
	Elapsed time.Duration
}

// Result summarises a completed parse run.
type Result struct {
	Parser  string
	Count   int64
	Elapsed time.Duration
	Err     error
}
