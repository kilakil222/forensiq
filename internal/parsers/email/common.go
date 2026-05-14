// Package email parses EML, MBOX, and MSG email artifacts.
package email

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

var emailIDCounter int64

func nextID() int64 {
	return atomic.AddInt64(&emailIDCounter, 1)
}

type emailRecord struct {
	ID             int64
	SourceFile     string
	Folder         string
	MessageID      string
	FromAddr       string
	FromName       string
	ToAddrs        string
	CcAddrs        string
	BccAddrs       string
	Subject        string
	SentAt         *time.Time
	ReceivedAt     *time.Time
	BodyText       string
	BodyHTML       string
	HasAttachments bool
	XMailer        string
	XOriginatingIP string
	ReplyTo        string
	InReplyTo      string
	HeadersRaw     string
}

type emailAttachment struct {
	EmailID     int64
	Filename    string
	ContentType string
	SizeBytes   int64
	SHA256      string
	IsExec      bool
}

type emailURL struct {
	EmailID int64
	URL     string
	Domain  string
}

var (
	reURL    = regexp.MustCompile(`(?i)https?://[^\s"'<>\x00-\x1f]{4,}`)
	reDomain = regexp.MustCompile(`(?i)(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|ru|cn|de|uk|gov|mil|edu|info|biz|xyz|top|app|dev|tech|me|co|us|ca|fr|jp|br|in|au|pl|nl|se|no|fi|be|ch|at|es|it|pt|ua|sa|ae|il|ir|eg)`)
)

func extractURLs(emailID int64, text string) []emailURL {
	var out []emailURL
	seen := map[string]bool{}
	for _, u := range reURL.FindAllString(text, -1) {
		u = strings.TrimRight(u, `.,;:)'"`)
		if seen[u] {
			continue
		}
		seen[u] = true
		domain := ""
		if m := reDomain.FindString(u); m != "" {
			domain = strings.ToLower(m)
		}
		out = append(out, emailURL{EmailID: emailID, URL: u, Domain: domain})
	}
	return out
}

func hashBytes(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

var execExts = map[string]bool{
	".exe": true, ".dll": true, ".bat": true, ".cmd": true,
	".ps1": true, ".vbs": true, ".js": true, ".hta": true,
	".scr": true, ".com": true, ".msi": true, ".jar": true,
	".wsf": true, ".pif": true, ".reg": true, ".lnk": true,
}

func isExecutable(filename string) bool {
	idx := strings.LastIndex(filename, ".")
	if idx < 0 {
		return false
	}
	return execExts[strings.ToLower(filename[idx:])]
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for i := n; i > 0; i-- {
		if utf8.RuneStart(s[i]) {
			return s[:i]
		}
	}
	return s[:n]
}

func insertEmail(db *sql.DB, e *emailRecord) error {
	_, err := db.Exec(`INSERT INTO emails (
		id, source_file, folder, message_id, from_addr, from_name,
		to_addrs, cc_addrs, bcc_addrs, subject, sent_at, received_at,
		body_text, body_html, has_attachments, x_mailer, x_originating_ip,
		reply_to, in_reply_to, headers_raw
	) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		e.ID, e.SourceFile, e.Folder, e.MessageID, e.FromAddr, e.FromName,
		e.ToAddrs, e.CcAddrs, e.BccAddrs, e.Subject, e.SentAt, e.ReceivedAt,
		truncate(e.BodyText, 65536), truncate(e.BodyHTML, 131072),
		e.HasAttachments, e.XMailer, e.XOriginatingIP,
		e.ReplyTo, e.InReplyTo, truncate(e.HeadersRaw, 16384),
	)
	return err
}

func insertAttachment(db *sql.DB, a *emailAttachment) error {
	_, err := db.Exec(
		`INSERT INTO email_attachments (email_id, filename, content_type, size_bytes, sha256, is_executable) VALUES (?,?,?,?,?,?)`,
		a.EmailID, a.Filename, a.ContentType, a.SizeBytes, a.SHA256, a.IsExec,
	)
	return err
}

func insertURLs(db *sql.DB, urls []emailURL) {
	if len(urls) == 0 {
		return
	}
	tx, err := db.Begin()
	if err != nil {
		return
	}
	stmt, err := tx.Prepare(`INSERT INTO email_urls (email_id, url, domain) VALUES (?,?,?)`)
	if err != nil {
		tx.Rollback()
		return
	}
	defer stmt.Close()
	for _, u := range urls {
		stmt.Exec(u.EmailID, u.URL, u.Domain)
	}
	tx.Commit()
}

func timePtrToSQL(t *time.Time) interface{} {
	if t == nil {
		return nil
	}
	return *t
}

func ptr(t time.Time) *time.Time {
	return &t
}

func insertEmailFull(db *sql.DB, rec *emailRecord, attachments []emailAttachment, urls []emailURL) error {
	if err := insertEmail(db, rec); err != nil {
		return fmt.Errorf("insert email: %w", err)
	}
	for i := range attachments {
		insertAttachment(db, &attachments[i])
	}
	insertURLs(db, urls)
	return nil
}
