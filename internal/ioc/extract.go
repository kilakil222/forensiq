// Package ioc extracts indicators of compromise from all artifact tables.
package ioc

import (
	"database/sql"
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"
)

type scanTarget struct {
	table  string
	column string
	filter string // optional extra WHERE condition (AND-ed)
	limit  int    // 0 = use default (20000)
}

var targets = []scanTarget{
	{"prefetch", "path", "", 0},
	{"prefetch", "volume_paths", "", 0},
	{"amcache", "path", "", 0},
	{"shimcache", "path", "", 0},
	// MFT is huge — pre-filter to suspicious directories at SQL level
	{"mft", "path",
		`path ILIKE '%downloads%' OR path ILIKE '%appdata%' OR path ILIKE '%temp%' OR path ILIKE '%public%' OR path ILIKE '%programdata%'`,
		200000},
	{"usnjrnl", "path", "", 0},
	{"lnk_files", "target_path", "", 0},
	{"lnk_files", "args", "", 0},
	{"persistence", "command", "", 0},
	{"persistence", "key_path", "", 0},
	{"services", "binary_path", "", 0},
	{"scheduled_tasks", "command", "", 0},
	{"scheduled_tasks", "args", "", 0},
	{"evtx_events", "message", "", 20000},
	{"ps_scriptblock", "script_text", "", 0},
	{"ps_history", "command", "", 0},
	{"defender_events", "path", "", 0},
	{"proc_creation", "cmdline", "", 0},
	{"sysmon_process", "cmdline", "", 0},
	{"sysmon_process", "parent_cmdline", "", 0},
	{"sysmon_network", "dst_ip", "", 0},
	{"sysmon_network", "dst_host", "", 0},
	{"sysmon_dns", "query_name", "", 0},
	{"browser_history", "url", "", 0},
	{"browser_history", "title", "", 0},
	{"browser_downloads", "url", "", 0},
	{"browser_downloads", "local_path", "", 0},
	{"mem_cmdline", "cmdline", "", 0},
	{"registry_raw", "value_data", "", 0},
	{"linux_auth", "src_ip", "", 0},
	{"shell_history", "command", "", 0},
}

var (
	reIP      = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b`)
	reURL     = regexp.MustCompile(`(?i)https?://[^\s"'<>\x00-\x1f]{4,}`)
	reSHA256  = regexp.MustCompile(`\b[0-9a-fA-F]{64}\b`)
	reSHA1    = regexp.MustCompile(`\b[0-9a-fA-F]{40}\b`)
	reMD5     = regexp.MustCompile(`\b[0-9a-fA-F]{32}\b`)
	reDomain  = regexp.MustCompile(`(?i)\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|ru|cn|de|uk|gov|mil|edu|info|biz|xyz|top|pro|online|site|cc|tk|pw|app|dev|cloud|tech|me|co|us|ca|fr|jp|br|in|au|pl|nl|se|no|fi|dk|be|ch|at|es|it|pt|cz|hu|gr|ro|bg|tr|ua|kz|sa|ae|il|ir|eg|ma|ng|ke|th|ph|id|my|sg|hk|tw|kr)\b`)
	reRegKey   = regexp.MustCompile(`(?i)\b(HKEY_[A-Z_]+|HK[A-Z]{2,3})\\[^\s"'\n\r<>|*?]{3,}`)
	reBase64   = regexp.MustCompile(`[A-Za-z0-9+/]{40,}={0,2}`)
	reWinPath  = regexp.MustCompile(`(?i)[A-Za-z]:\\(?:[^\s"'\n\r<>|*?\\]+\\)*[^\s"'\n\r<>|*?\\]+`)
	reNTFSPath = regexp.MustCompile(`(?i)/(?:Users|Windows|ProgramData|Program Files[^/]*)(?:/[^\s"'<>|*?\n\r]+){1,}`)

	rePrivateIP = regexp.MustCompile(`^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|169\.254\.|0\.0\.0\.|255\.)`)
)

type iocEntry struct {
	iocType string
	value   string
	source  string
	context string
	count   int
}

// ExtractAll scans all artifact tables for IOC patterns and populates ioc_extracted.
func ExtractAll(db *sql.DB) {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS ioc_extracted (
		type TEXT, value TEXT, source TEXT, context TEXT,
		count INTEGER DEFAULT 1, first_seen TIMESTAMP
	)`); err != nil {
		log.Printf("ioc extract: create table: %v", err)
		return
	}

	existing := listTables(db)

	seen := make(map[string]*iocEntry, 2048)

	for _, t := range targets {
		if !existing[t.table] {
			continue
		}
		lim := 20000
		if t.limit > 0 {
			lim = t.limit
		}
		where := t.column + ` IS NOT NULL AND LENGTH(CAST(` + t.column + ` AS VARCHAR)) > 3`
		if t.filter != "" {
			where += ` AND (` + t.filter + `)`
		}
		q := `SELECT COALESCE(` + t.column + `,'') FROM ` + t.table + ` WHERE ` + where + fmt.Sprintf(` LIMIT %d`, lim)
		rows, err := db.Query(q)
		if err != nil {
			log.Printf("ioc extract: %s.%s: %v", t.table, t.column, err)
			continue
		}
		src := t.table + "." + t.column
		for rows.Next() {
			var text string
			if rows.Scan(&text) == nil && text != "" {
				extractFrom(text, src, seen)
			}
		}
		rows.Close()
	}

	if len(seen) == 0 {
		log.Print("ioc extract: no IOCs found")
		return
	}

	if _, err := db.Exec(`DELETE FROM ioc_extracted`); err != nil {
		log.Printf("ioc extract: clear: %v", err)
	}

	tx, err := db.Begin()
	if err != nil {
		log.Printf("ioc extract: begin: %v", err)
		return
	}
	stmt, err := tx.Prepare(
		`INSERT INTO ioc_extracted (type, value, source, context, count, first_seen) VALUES (?,?,?,?,?,?)`)
	if err != nil {
		tx.Rollback()
		log.Printf("ioc extract: prepare: %v", err)
		return
	}
	now := time.Now()
	for _, e := range seen {
		if _, err := stmt.Exec(e.iocType, e.value, e.source, e.context, e.count, now); err != nil {
			log.Printf("ioc extract: insert: %v", err)
		}
	}
	stmt.Close()
	if err := tx.Commit(); err != nil {
		log.Printf("ioc extract: commit: %v", err)
		return
	}
	log.Printf("ioc extract: %d unique IOCs extracted", len(seen))
}

func extractFrom(text, source string, seen map[string]*iocEntry) {
	track := func(iocType, value string) {
		if len(value) < 3 {
			return
		}
		key := iocType + ":" + strings.ToLower(value)
		if e, ok := seen[key]; ok {
			e.count++
		} else {
			ctx := text
			if len(ctx) > 200 {
				ctx = ctx[:200]
			}
			seen[key] = &iocEntry{iocType: iocType, value: value, source: source, context: ctx, count: 1}
		}
	}

	// SHA256 first (longest, most specific hash)
	for _, m := range reSHA256.FindAllString(text, -1) {
		track("sha256", strings.ToLower(m))
	}
	// Strip SHA256 matches so shorter patterns don't match substrings
	stripped := reSHA256.ReplaceAllString(text, "")
	for _, m := range reSHA1.FindAllString(stripped, -1) {
		track("sha1", strings.ToLower(m))
	}
	stripped2 := reSHA1.ReplaceAllString(stripped, "")
	for _, m := range reMD5.FindAllString(stripped2, -1) {
		track("md5", strings.ToLower(m))
	}

	// URLs before domains so full URL is captured
	for _, m := range reURL.FindAllString(text, -1) {
		m = strings.TrimRight(m, `.,;:)'"`)
		track("url", m)
	}

	// IPs (skip private/loopback/broadcast)
	for _, m := range reIP.FindAllString(text, -1) {
		if !rePrivateIP.MatchString(m) {
			track("ip", m)
		}
	}

	// Registry keys
	for _, m := range reRegKey.FindAllString(text, -1) {
		m = strings.TrimRight(m, `\.,;:)"'`)
		track("regkey", m)
	}

	// Suspicious Windows paths (backslash style: shimcache, lnk)
	for _, m := range reWinPath.FindAllString(text, -1) {
		m = strings.TrimRight(m, `.,;:)"'`)
		if isSuspiciousPath(m) {
			track("path", m)
		}
	}
	// NTFS paths in forward-slash form (MFT, amcache from disk image)
	for _, m := range reNTFSPath.FindAllString(text, -1) {
		m = strings.TrimRight(m, `.,;:)"'`)
		if isSuspiciousPath(m) {
			track("path", m)
		}
	}

	// Base64 only in scripting/command contexts to reduce noise
	if strings.Contains(source, "ps_") || strings.Contains(source, "script") || strings.Contains(source, "cmdline") {
		for _, m := range reBase64.FindAllString(text, -1) {
			if len(m) >= 40 {
				track("base64", m)
			}
		}
	}

	// Domains — strip URLs first to avoid partial re-extraction
	noURLText := reURL.ReplaceAllString(text, " ")
	for _, m := range reDomain.FindAllString(noURLText, -1) {
		m = strings.ToLower(m)
		if !isNoiseDomain(m) {
			track("domain", m)
		}
	}
}

var suspPathParts = []string{
	`/appdata/`, `/temp/`, `/tmp/`, `/public/`, `/downloads/`,
	`/programdata/`, `/recycle`, `/windows/debug`, `/users/all users`,
	`/perflogs/`, `/windows/tasks/`,
}

func isSuspiciousPath(p string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(p, `\`, `/`))
	for _, part := range suspPathParts {
		if strings.Contains(normalized, part) {
			return true
		}
	}
	return false
}

var noiseDomains = []string{
	"microsoft.com", "windows.com", "windowsupdate.com", "msftncsi.com",
	"google.com", "googleapis.com", "gstatic.com", "github.com",
	"localhost", "w3.org", "schemas.microsoft.com", "ctldl.windowsupdate.com",
	"ocsp.digicert.com", "crl.microsoft.com", "ns.adobe.com",
}

func isNoiseDomain(d string) bool {
	if len(d) < 6 {
		return true
	}
	for _, c := range noiseDomains {
		if d == c || strings.HasSuffix(d, "."+c) {
			return true
		}
	}
	return false
}

func listTables(db *sql.DB) map[string]bool {
	out := map[string]bool{}
	rows, err := db.Query(`SELECT table_name FROM information_schema.tables WHERE table_schema = 'main'`)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if rows.Scan(&name) == nil {
			out[name] = true
		}
	}
	return out
}
