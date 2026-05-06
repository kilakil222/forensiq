package linux

import (
	"database/sql"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"time"

	"forensiq/internal/parsers"
)

// WtmpParser parses Linux wtmp and btmp binary files (utmpx format, 384 bytes/record).
// Records user logins, logouts, and system boot times.
type WtmpParser struct {
	source string // "wtmp" or "btmp"
}

func NewWtmp(source string) *WtmpParser { return &WtmpParser{source: source} }
func (p *WtmpParser) Name() string      { return "Linux/Wtmp" }

// utmpx record layout (Linux x86_64, 384 bytes total)
const (
	utmpxRecordSize = 384
	utmpxTypeOffset = 0
	utmpxPIDOffset  = 4
	utmpxLineOffset = 8   // char[32]
	utmpxUserOffset = 44  // char[32]
	utmpxHostOffset = 76  // char[256]
	utmpxTVSecOffset = 340 // int32
)

// ut_type values
const (
	utEmpty        = 0
	utRunLevel     = 1
	utBootTime     = 2
	utUserProcess  = 7
	utDeadProcess  = 8
)

func (p *WtmpParser) Parse(r io.Reader, db *sql.DB, ch chan<- parsers.Progress) error {
	start := time.Now()

	data, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("read wtmp: %w", err)
	}

	if len(data)%utmpxRecordSize != 0 && len(data) > utmpxRecordSize {
		// Some systems use 292-byte records (older utmp); skip gracefully
		ch <- parsers.Progress{Parser: p.Name(), Done: true, Elapsed: time.Since(start)}
		return nil
	}

	stmt, err := db.Prepare(`INSERT INTO linux_sessions ("user", terminal, login_time, logout_time, src_ip, source) VALUES (?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare linux_sessions: %w", err)
	}
	defer stmt.Close()

	var count int64
	nRecords := len(data) / utmpxRecordSize

	// Track open sessions by terminal to pair login/logout
	type session struct {
		user      string
		terminal  string
		loginTime time.Time
		srcIP     string
	}
	open := make(map[string]session)

	for i := 0; i < nRecords; i++ {
		rec := data[i*utmpxRecordSize : (i+1)*utmpxRecordSize]

		utType := int16(binary.LittleEndian.Uint16(rec[utmpxTypeOffset:]))
		tvSec := int32(binary.LittleEndian.Uint32(rec[utmpxTVSecOffset:]))
		ts := time.Unix(int64(tvSec), 0).UTC()

		user := nullTermStr(rec[utmpxUserOffset : utmpxUserOffset+32])
		terminal := nullTermStr(rec[utmpxLineOffset : utmpxLineOffset+32])
		host := nullTermStr(rec[utmpxHostOffset : utmpxHostOffset+256])

		switch utType {
		case utBootTime:
			if _, err := stmt.Exec("SYSTEM", "~", ts, nil, "", p.source+":boot"); err == nil {
				count++
			}

		case utUserProcess:
			// Login record — store in open sessions map
			open[terminal] = session{
				user:      user,
				terminal:  terminal,
				loginTime: ts,
				srcIP:     host,
			}

		case utDeadProcess:
			// Logout — pair with open session
			if s, ok := open[terminal]; ok {
				if _, err := stmt.Exec(s.user, s.terminal, s.loginTime, ts, s.srcIP, p.source); err == nil {
					count++
				}
				delete(open, terminal)
			}
		}
	}

	// Flush any sessions still open at end of file (no logout recorded)
	for _, s := range open {
		if s.user == "" || strings.HasPrefix(s.user, "LOGIN") {
			continue
		}
		if _, err := stmt.Exec(s.user, s.terminal, s.loginTime, nil, s.srcIP, p.source); err == nil {
			count++
		}
	}

	ch <- parsers.Progress{Parser: p.Name(), Count: count, Done: true, Elapsed: time.Since(start)}
	return nil
}

// nullTermStr extracts a null-terminated string from a byte slice.
func nullTermStr(b []byte) string {
	for i, v := range b {
		if v == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
