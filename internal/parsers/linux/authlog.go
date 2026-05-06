// Package linux contains parsers for Linux forensic artifacts.
package linux

import (
	"bufio"
	"database/sql"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"

	"forensiq/internal/parsers"
)

// AuthLogParser parses /var/log/auth.log (Debian/Ubuntu) and /var/log/secure (RHEL/CentOS).
type AuthLogParser struct{}

func NewAuthLog() *AuthLogParser { return &AuthLogParser{} }
func (p *AuthLogParser) Name() string { return "Linux/AuthLog" }

var (
	reRFC3339Prefix = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)`)
	reSyslogPrefix  = regexp.MustCompile(`^(\w{3}\s{1,2}\d{1,2}\s+\d{2}:\d{2}:\d{2})`)
	reProcEntry     = regexp.MustCompile(`^([\w][\w.-]*)\[(\d+)\]:\s*(.*)$`)

	reSSHAccepted = regexp.MustCompile(`Accepted (\S+) for (\S+) from ([\d.a-fA-F:]+)`)
	reSSHFailed   = regexp.MustCompile(`Failed \S+ for (?:invalid user )?(\S+) from ([\d.a-fA-F:]+)`)
	reSSHInvalid  = regexp.MustCompile(`Invalid user (\S+) from ([\d.a-fA-F:]+)`)
	reSudo        = regexp.MustCompile(`sudo:\s+(\S+)\s*:.*COMMAND=(.+)`)
	reUseradd     = regexp.MustCompile(`new user: name=(\S+)`)
)

func (p *AuthLogParser) Parse(r io.Reader, db *sql.DB, ch chan<- parsers.Progress) error {
	start := time.Now()

	stmt, err := db.Prepare(`INSERT INTO linux_auth (timestamp, event_type, "user", src_ip, method, pid, message) VALUES (?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare linux_auth: %w", err)
	}
	defer stmt.Close()

	var count int64
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 1<<20), 1<<20)
	year := time.Now().Year()

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		ts, afterTS := parseAuthTS(line, year)
		eventType, user, srcIP, method, pid, msg := classifyAuthLine(afterTS)
		if eventType == "" {
			continue
		}

		if _, err := stmt.Exec(ts, eventType, user, srcIP, method, pid, msg); err != nil {
			continue
		}
		count++
	}

	ch <- parsers.Progress{Parser: p.Name(), Count: count, Done: true, Elapsed: time.Since(start)}
	return scanner.Err()
}

// parseAuthTS strips the timestamp from the beginning of a syslog line.
// Returns zero time if unparseable.
func parseAuthTS(line string, year int) (time.Time, string) {
	if m := reRFC3339Prefix.FindStringIndex(line); m != nil {
		ts, err := time.Parse(time.RFC3339Nano, line[:m[1]])
		if err == nil {
			return ts.UTC(), strings.TrimSpace(line[m[1]:])
		}
	}
	if m := reSyslogPrefix.FindStringIndex(line); m != nil {
		raw := strings.TrimSpace(line[:m[1]])
		rest := strings.TrimSpace(line[m[1]:])
		ts, err := time.Parse("Jan _2 15:04:05", raw)
		if err == nil {
			ts = time.Date(year, ts.Month(), ts.Day(), ts.Hour(), ts.Minute(), ts.Second(), 0, time.UTC)
			return ts, rest
		}
	}
	return time.Time{}, line
}

// classifyAuthLine parses "hostname process[pid]: message" and returns event fields.
func classifyAuthLine(s string) (eventType, user, srcIP, method string, pid int, msg string) {
	// Strip hostname (first whitespace-separated token)
	spaceIdx := strings.IndexByte(s, ' ')
	if spaceIdx < 0 {
		return "", "", "", "", 0, ""
	}
	procAndMsg := strings.TrimSpace(s[spaceIdx+1:])

	m := reProcEntry.FindStringSubmatch(procAndMsg)
	if m == nil {
		return "", "", "", "", 0, ""
	}
	proc := m[1]
	pid, _ = strconv.Atoi(m[2])
	msg = m[3]

	switch {
	case proc == "sshd":
		if ma := reSSHAccepted.FindStringSubmatch(msg); ma != nil {
			return "ssh_login_success", ma[2], ma[3], ma[1], pid, msg
		}
		if ma := reSSHFailed.FindStringSubmatch(msg); ma != nil {
			return "ssh_login_failed", ma[1], ma[2], "password", pid, msg
		}
		if ma := reSSHInvalid.FindStringSubmatch(msg); ma != nil {
			return "ssh_invalid_user", ma[1], ma[2], "", pid, msg
		}
		if strings.Contains(msg, "Connection closed") || strings.Contains(msg, "Disconnected") {
			return "ssh_disconnect", "", "", "", pid, msg
		}
		return "ssh_other", "", "", "", pid, msg

	case proc == "sudo":
		if ma := reSudo.FindStringSubmatch(procAndMsg); ma != nil {
			return "sudo", ma[1], "", strings.TrimSpace(ma[2]), pid, msg
		}
		return "sudo", "", "", "", pid, msg

	case proc == "su":
		if strings.Contains(msg, "Successful") || strings.Contains(msg, "session opened for user root") {
			return "su_success", "", "", "", pid, msg
		}
		if strings.Contains(msg, "FAILED") || strings.Contains(msg, "authentication failure") {
			return "su_failed", "", "", "", pid, msg
		}
		return "", "", "", "", 0, ""

	case proc == "useradd":
		if ma := reUseradd.FindStringSubmatch(msg); ma != nil {
			return "useradd", ma[1], "", "", pid, msg
		}
		return "useradd", "", "", "", pid, msg

	case proc == "usermod":
		return "usermod", "", "", "", pid, msg

	case proc == "userdel":
		return "userdel", "", "", "", pid, msg

	case proc == "passwd":
		return "passwd_change", "", "", "", pid, msg

	default:
		return "", "", "", "", 0, ""
	}
}
