package linux

import (
	"bufio"
	"database/sql"
	"fmt"
	"io"
	"strings"
	"time"

	"forensiq/internal/parsers"
)

// PersistenceParser parses Linux persistence artifacts:
// crontabs, authorized_keys, /etc/passwd, /etc/sudoers.
type PersistenceParser struct {
	artifactType string // "crontab", "authorized_keys", "passwd", "sudoers"
	path         string // original file path for context
	user         string // owning user if determinable
}

func NewPersistence(artifactType, path, user string) *PersistenceParser {
	return &PersistenceParser{artifactType: artifactType, path: path, user: user}
}
func (p *PersistenceParser) Name() string { return "Linux/Persistence" }

func (p *PersistenceParser) Parse(r io.Reader, db *sql.DB, ch chan<- parsers.Progress) error {
	start := time.Now()

	stmt, err := db.Prepare(`INSERT INTO linux_persistence (type, path, command, "user", enabled, details) VALUES (?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare linux_persistence: %w", err)
	}
	defer stmt.Close()

	var count int64
	var parseErr error

	switch p.artifactType {
	case "crontab":
		count, parseErr = parseCrontab(r, stmt, p.path, p.user)
	case "authorized_keys":
		count, parseErr = parseAuthorizedKeys(r, stmt, p.path, p.user)
	case "passwd":
		count, parseErr = parsePasswd(r, stmt, p.path)
	case "sudoers":
		count, parseErr = parseSudoers(r, stmt, p.path)
	}

	ch <- parsers.Progress{Parser: p.Name(), Count: count, Done: true, Elapsed: time.Since(start)}
	return parseErr
}

func parseCrontab(r io.Reader, stmt *sql.Stmt, path, user string) (int64, error) {
	var count int64
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// System crontabs have 6 fields (min hour dom mon dow user cmd)
		// User crontabs have 5 fields (min hour dom mon dow cmd)
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		// Detect @reboot, @daily etc shorthand
		var schedule, command, lineUser string
		if strings.HasPrefix(fields[0], "@") {
			schedule = fields[0]
			if len(fields) >= 3 {
				lineUser = fields[1]
				command = strings.Join(fields[2:], " ")
			} else {
				command = strings.Join(fields[1:], " ")
			}
		} else if len(fields) >= 7 {
			// system crontab: 5 schedule fields + user + command
			schedule = strings.Join(fields[:5], " ")
			lineUser = fields[5]
			command = strings.Join(fields[6:], " ")
		} else {
			// user crontab: 5 schedule fields + command
			schedule = strings.Join(fields[:5], " ")
			lineUser = user
			command = strings.Join(fields[5:], " ")
		}
		if lineUser == "" {
			lineUser = user
		}
		if _, err := stmt.Exec("crontab", path, command, lineUser, true, schedule); err == nil {
			count++
		}
	}
	return count, scanner.Err()
}

func parseAuthorizedKeys(r io.Reader, stmt *sql.Stmt, path, user string) (int64, error) {
	var count int64
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 1<<20), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Format: [options] keytype base64key [comment]
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		// Extract key type and comment if present
		keyType := fields[0]
		comment := ""
		if len(fields) >= 3 {
			comment = strings.Join(fields[2:], " ")
		}
		details := "keytype=" + keyType
		if comment != "" {
			details += " comment=" + comment
		}
		// Store truncated key (first 40 chars) as command for identification
		key := fields[1]
		if len(key) > 40 {
			key = key[:40] + "..."
		}
		if _, err := stmt.Exec("authorized_key", path, key, user, true, details); err == nil {
			count++
		}
	}
	return count, scanner.Err()
}

func parsePasswd(r io.Reader, stmt *sql.Stmt, path string) (int64, error) {
	var count int64
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Format: user:password:uid:gid:gecos:home:shell
		parts := strings.Split(line, ":")
		if len(parts) < 7 {
			continue
		}
		username := parts[0]
		uid := parts[2]
		shell := parts[6]
		home := parts[5]

		// Only record interactive users (uid >= 1000 or UID=0) and non-nologin shells
		isInteractive := shell != "/usr/sbin/nologin" && shell != "/bin/false" && shell != "/sbin/nologin"
		details := fmt.Sprintf("uid=%s home=%s shell=%s", uid, home, shell)
		if _, err := stmt.Exec("passwd_entry", path, shell, username, isInteractive, details); err == nil {
			count++
		}
	}
	return count, scanner.Err()
}

func parseSudoers(r io.Reader, stmt *sql.Stmt, path string) (int64, error) {
	var count int64
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "Defaults") {
			continue
		}
		// Basic rule lines: user/group HOST = (runas) [NOPASSWD:] commands
		if strings.Contains(line, "=") {
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			subject := fields[0]
			user := subject
			if strings.HasPrefix(subject, "%") {
				user = subject // group
			}
			if _, err := stmt.Exec("sudoers_rule", path, line, user, true, ""); err == nil {
				count++
			}
		}
	}
	return count, scanner.Err()
}
