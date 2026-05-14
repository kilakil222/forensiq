package email

import (
	"bufio"
	"database/sql"
	"fmt"
	"io"
	"strings"

	"forensiq/internal/parsers"
)

// MBOXParser parses a Unix mbox file (multiple RFC 2822 messages separated by "From " lines).
type MBOXParser struct {
	sourceName string
	folder     string
}

func NewMBOX(sourceName, folder string) *MBOXParser {
	return &MBOXParser{sourceName: sourceName, folder: folder}
}

func (p *MBOXParser) Name() string { return "Email/MBOX" }

func (p *MBOXParser) Parse(r io.Reader, db *sql.DB, ch chan<- parsers.Progress) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 16*1024*1024), 16*1024*1024)

	var count int64
	var current strings.Builder
	inMessage := false

	flush := func() {
		if !inMessage || current.Len() == 0 {
			return
		}
		rec, attachments, urls, err := parseEMLBytes([]byte(current.String()), p.sourceName, p.folder)
		current.Reset()
		if err != nil {
			return
		}
		if err := insertEmailFull(db, rec, attachments, urls); err != nil {
			return
		}
		count++
	}

	for scanner.Scan() {
		line := scanner.Text()
		// "From " separator line (mbox envelope header)
		if strings.HasPrefix(line, "From ") && isFromLine(line) {
			flush()
			inMessage = true
			continue
		}
		if inMessage {
			// Un-escape mbox ">From " quoting
			if strings.HasPrefix(line, ">From ") {
				line = line[1:]
			}
			current.WriteString(line)
			current.WriteByte('\n')
		}
	}
	flush()

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("mbox scan: %w", err)
	}
	ch <- parsers.Progress{Parser: p.Name(), Count: count, Done: true}
	return nil
}

// isFromLine checks that the "From " line looks like a real mbox envelope,
// not a quoted line starting with "From " inside an email body.
// A valid mbox From line has at least 20 chars and no colon before position 10.
func isFromLine(line string) bool {
	if len(line) < 20 {
		return false
	}
	// "From address date" — no colon in the first part
	firstSpace := strings.Index(line[5:], " ")
	if firstSpace < 0 {
		return false
	}
	return true
}
