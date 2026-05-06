package linux

import (
	"bufio"
	"database/sql"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"forensiq/internal/parsers"
)

// ShellHistoryParser parses .bash_history and .zsh_history files.
// Handles HISTTIMEFORMAT="#%s\n" timestamps (lines starting with #<epoch>).
type ShellHistoryParser struct {
	source string // e.g. "root" or "user" derived from path
	shell  string // "bash" or "zsh"
}

func NewShellHistory(source, shell string) *ShellHistoryParser {
	return &ShellHistoryParser{source: source, shell: shell}
}
func (p *ShellHistoryParser) Name() string { return "Linux/ShellHistory" }

func (p *ShellHistoryParser) Parse(r io.Reader, db *sql.DB, ch chan<- parsers.Progress) error {
	start := time.Now()

	stmt, err := db.Prepare(`INSERT INTO shell_history (command, timestamp, source, "user", shell) VALUES (?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare shell_history: %w", err)
	}
	defer stmt.Close()

	var count int64
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 1<<20), 1<<20)

	var pendingTS time.Time

	for scanner.Scan() {
		line := scanner.Text()

		// HISTTIMEFORMAT="#%s" produces comment lines like "#1234567890"
		if strings.HasPrefix(line, "#") {
			epoch, err := strconv.ParseInt(strings.TrimPrefix(line, "#"), 10, 64)
			if err == nil && epoch > 1000000000 {
				pendingTS = time.Unix(epoch, 0).UTC()
			}
			continue
		}

		if line == "" {
			continue
		}

		ts := pendingTS
		pendingTS = time.Time{}

		if _, err := stmt.Exec(line, ts, p.source, p.source, p.shell); err != nil {
			continue
		}
		count++
	}

	ch <- parsers.Progress{Parser: p.Name(), Count: count, Done: true, Elapsed: time.Since(start)}
	return scanner.Err()
}
