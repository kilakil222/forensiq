// Package anydesk parses AnyDesk forensic artifacts:
//   - connection_trace.txt  → anydesk_sessions
//   - ad_svc.trace / ad.trace / ad_user.trace → anydesk_events
//   - system.conf / user.conf → anydesk_config
package anydesk

import (
	"bufio"
	"database/sql"
	"encoding/binary"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"forensiq/internal/parsers"
)

// ─── connection_trace.txt ────────────────────────────────────────────────────

type ConnectionTraceParser struct{ source string }

func NewConnectionTrace(source string) *ConnectionTraceParser {
	return &ConnectionTraceParser{source: source}
}
func (p *ConnectionTraceParser) Name() string { return "AnyDesk/ConnectionTrace" }

func (p *ConnectionTraceParser) Parse(r io.Reader, db *sql.DB, ch chan<- parsers.Progress) error {
	start := time.Now()

	raw, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("anydesk/trace: read: %w", err)
	}

	// connection_trace.txt is always UTF-16LE with BOM
	text := decodeText(raw)

	stmt, err := db.Prepare(`INSERT INTO anydesk_sessions
		(direction, timestamp, auth_method, client_alias, anydesk_id, source_file)
		VALUES (?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("anydesk/trace: prepare: %w", err)
	}
	defer stmt.Close()

	var count int64
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		// Fields are separated by 2+ whitespace characters
		fields := splitWide(line)
		if len(fields) < 3 {
			continue
		}
		direction := fields[0]
		if direction != "Incoming" && direction != "Outgoing" {
			continue
		}

		// Date field may be "2021-10-04," or "2021-10-04, 12:01" depending on encoding
		var tsStr, authMethod, clientAlias, anyDeskID string
		switch {
		case len(fields) >= 6:
			// direction | "2021-10-04," | "12:01" | auth | alias | id
			dateStr := strings.TrimSuffix(fields[1], ",")
			tsStr = dateStr + " " + fields[2]
			authMethod = fields[3]
			clientAlias = fields[4]
			anyDeskID = fields[5]
		case len(fields) >= 5:
			// direction | "2021-10-04, 12:01" | auth | alias | id
			tsStr = strings.TrimSuffix(fields[1], ",")
			authMethod = fields[2]
			clientAlias = fields[3]
			anyDeskID = fields[4]
		case len(fields) >= 4:
			tsStr = fields[1]
			authMethod = fields[2]
			clientAlias = fields[3]
		}

		ts := parseAnyDeskTime(tsStr)
		if _, err := stmt.Exec(direction, nullTime(ts), authMethod, clientAlias, anyDeskID, p.source); err != nil {
			continue
		}
		count++
	}

	ch <- parsers.Progress{Parser: p.Name(), Count: count, Done: true, Elapsed: time.Since(start)}
	return nil
}

// ─── *.trace log files ───────────────────────────────────────────────────────

type TraceLogParser struct{ source string }

func NewTrace(source string) *TraceLogParser { return &TraceLogParser{source: source} }
func (p *TraceLogParser) Name() string       { return "AnyDesk/TraceLog" }

// reTrace matches:  level  YYYY-MM-DD HH:MM:SS.mmm  PID  TID  rest
var reTrace = regexp.MustCompile(
	`^(info|warn|err|error|debug)\s+` +
		`(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[.,]\d+)\s+` +
		`(\d+)\s+\d+\s+(.+)$`)

func (p *TraceLogParser) Parse(r io.Reader, db *sql.DB, ch chan<- parsers.Progress) error {
	start := time.Now()

	stmt, err := db.Prepare(`INSERT INTO anydesk_events
		(timestamp, pid, level, component, message, source_file)
		VALUES (?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("anydesk/log: prepare: %w", err)
	}
	defer stmt.Close()

	var count int64
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 512*1024), 512*1024)
	for sc.Scan() {
		m := reTrace.FindStringSubmatch(sc.Text())
		if m == nil {
			continue
		}
		level := m[1]
		ts := parseAnyDeskTime(strings.TrimSpace(m[2]))
		pid, _ := strconv.Atoi(m[3])
		rest := strings.TrimSpace(m[4])

		// rest = "COMPONENT - MESSAGE"  or just MESSAGE
		component, message := "", rest
		if idx := strings.Index(rest, " - "); idx > 0 {
			component = strings.TrimSpace(rest[:idx])
			message = strings.TrimSpace(rest[idx+3:])
		}

		if _, err := stmt.Exec(nullTime(ts), pid, level, component, message, p.source); err != nil {
			continue
		}
		count++
	}

	ch <- parsers.Progress{Parser: p.Name(), Count: count, Done: true, Elapsed: time.Since(start)}
	return nil
}

// ─── *.conf files ────────────────────────────────────────────────────────────

type ConfParser struct{ source string }

func NewConf(source string) *ConfParser { return &ConfParser{source: source} }
func (p *ConfParser) Name() string      { return "AnyDesk/Config" }

func (p *ConfParser) Parse(r io.Reader, db *sql.DB, ch chan<- parsers.Progress) error {
	start := time.Now()

	stmt, err := db.Prepare(`INSERT INTO anydesk_config (key, value, source_file) VALUES (?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("anydesk/conf: prepare: %w", err)
	}
	defer stmt.Close()

	var count int64
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == ';' || line[0] == '[' {
			continue
		}
		idx := strings.IndexByte(line, '=')
		if idx < 1 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		if _, err := stmt.Exec(key, val, p.source); err != nil {
			continue
		}
		count++
	}

	ch <- parsers.Progress{Parser: p.Name(), Count: count, Done: true, Elapsed: time.Since(start)}
	return nil
}

// ─── helpers ─────────────────────────────────────────────────────────────────

var reWide = regexp.MustCompile(`\s{2,}|\t+`)

// splitWide splits on 2+ consecutive whitespace (AnyDesk uses wide-spaced columns).
func splitWide(s string) []string {
	parts := reWide.Split(s, -1)
	out := parts[:0]
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func parseAnyDeskTime(s string) time.Time {
	s = strings.TrimSpace(s)
	// Normalize comma-decimal separator to dot
	s = strings.ReplaceAll(s, ",", ".")
	formats := []string{
		"2006-01-02 15:04:05.000",
		"2006-01-02 15:04:05.999",
		"2006-01-02 15:04:05",
		"2006-01-02 15:04",
	}
	for _, f := range formats {
		if t, err := time.Parse(f, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

func nullTime(t time.Time) interface{} {
	if t.IsZero() {
		return nil
	}
	return t
}

// decodeText converts raw bytes to UTF-8 string, handling UTF-16LE BOM.
func decodeText(data []byte) string {
	if len(data) >= 2 && data[0] == 0xFF && data[1] == 0xFE {
		return string(utf16LEToUTF8(data[2:]))
	}
	if looksUTF16LE(data) {
		return string(utf16LEToUTF8(data))
	}
	return string(data)
}

func utf16LEToUTF8(data []byte) []byte {
	if len(data)%2 != 0 {
		data = data[:len(data)-1]
	}
	u16 := make([]uint16, len(data)/2)
	for i := range u16 {
		u16[i] = binary.LittleEndian.Uint16(data[i*2:])
	}
	runes := utf16.Decode(u16)
	var sb strings.Builder
	sb.Grow(len(runes))
	buf := [4]byte{}
	for _, r := range runes {
		n := utf8.EncodeRune(buf[:], r)
		sb.Write(buf[:n])
	}
	return []byte(sb.String())
}

func looksUTF16LE(data []byte) bool {
	if len(data) < 8 {
		return false
	}
	limit := len(data)
	if limit > 64 {
		limit = 64
	}
	zeros := 0
	for i := 1; i < limit; i += 2 {
		if data[i] == 0 {
			zeros++
		}
	}
	return zeros >= limit/4
}
