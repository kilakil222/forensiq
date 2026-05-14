package email

import (
	"database/sql"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"
	"time"

	"forensiq/internal/parsers"
)

// EMLParser parses a single .eml file (RFC 2822).
type EMLParser struct {
	sourceName string
	folder     string
}

func NewEML(sourceName, folder string) *EMLParser {
	return &EMLParser{sourceName: sourceName, folder: folder}
}

func (p *EMLParser) Name() string { return "Email/EML" }

func (p *EMLParser) Parse(r io.Reader, db *sql.DB, ch chan<- parsers.Progress) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("eml read: %w", err)
	}
	rec, attachments, urls, err := parseEMLBytes(data, p.sourceName, p.folder)
	if err != nil {
		ch <- parsers.Progress{Parser: p.Name(), Err: fmt.Errorf("%s: %w", p.sourceName, err), Done: true}
		return nil
	}
	if err := insertEmailFull(db, rec, attachments, urls); err != nil {
		return err
	}
	ch <- parsers.Progress{Parser: p.Name(), Count: 1, Done: true}
	return nil
}

func parseEMLBytes(data []byte, sourceName, folder string) (*emailRecord, []emailAttachment, []emailURL, error) {
	// Strip UTF-8 BOM if present (PowerShell and some MUAs add it)
	if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
		data = data[3:]
	}
	msg, err := mail.ReadMessage(strings.NewReader(string(data)))
	if err != nil {
		return nil, nil, nil, err
	}

	id := nextID()
	rec := &emailRecord{
		ID:             id,
		SourceFile:     sourceName,
		Folder:         folder,
		MessageID:      strings.Trim(msg.Header.Get("Message-ID"), "<> "),
		Subject:        decodeRFC2047(msg.Header.Get("Subject")),
		XMailer:        msg.Header.Get("X-Mailer"),
		XOriginatingIP: cleanIP(msg.Header.Get("X-Originating-IP")),
		ReplyTo:        flattenAddrs(msg.Header.Get("Reply-To")),
		InReplyTo:      strings.Trim(msg.Header.Get("In-Reply-To"), "<> "),
	}

	if from := msg.Header.Get("From"); from != "" {
		if addrs, err2 := mail.ParseAddressList(decodeRFC2047(from)); err2 == nil && len(addrs) > 0 {
			rec.FromName = addrs[0].Name
			rec.FromAddr = addrs[0].Address
		} else {
			rec.FromAddr = from
		}
	}

	rec.ToAddrs = flattenAddrs(msg.Header.Get("To"))
	rec.CcAddrs = flattenAddrs(msg.Header.Get("Cc"))
	rec.BccAddrs = flattenAddrs(msg.Header.Get("Bcc"))

	if d, err2 := msg.Header.Date(); err2 == nil {
		rec.SentAt = &d
	}
	if recv := parseReceivedDate(msg.Header.Get("Received")); recv != nil {
		rec.ReceivedAt = recv
	}

	var hb strings.Builder
	for k, vs := range msg.Header {
		for _, v := range vs {
			fmt.Fprintf(&hb, "%s: %s\n", k, v)
		}
	}
	rec.HeadersRaw = hb.String()

	ct := msg.Header.Get("Content-Type")
	if ct == "" {
		ct = "text/plain"
	}
	var attachments []emailAttachment
	walkPart(id, msg.Body, ct, msg.Header.Get("Content-Transfer-Encoding"), "", rec, &attachments)
	rec.HasAttachments = len(attachments) > 0

	urls := extractURLs(id, rec.BodyText+" "+rec.BodyHTML)
	return rec, attachments, urls, nil
}

func walkPart(emailID int64, r io.Reader, ct, cte, filename string, rec *emailRecord, attachments *[]emailAttachment) {
	mediaType, params, err := mime.ParseMediaType(ct)
	if err != nil {
		mediaType = "text/plain"
		params = map[string]string{}
	}

	switch {
	case strings.HasPrefix(mediaType, "multipart/"):
		boundary := params["boundary"]
		if boundary == "" {
			return
		}
		mr := multipart.NewReader(r, boundary)
		for {
			part, err2 := mr.NextPart()
			if err2 != nil {
				break
			}
			partCT := part.Header.Get("Content-Type")
			if partCT == "" {
				partCT = "text/plain"
			}
			disp := part.Header.Get("Content-Disposition")
			fname := partFilename(disp, partCT)
			walkPart(emailID, part, partCT, part.Header.Get("Content-Transfer-Encoding"), fname, rec, attachments)
		}

	case strings.HasPrefix(mediaType, "text/plain") && filename == "":
		if rec.BodyText == "" {
			data, _ := io.ReadAll(r)
			rec.BodyText = string(data)
		}

	case strings.HasPrefix(mediaType, "text/html") && filename == "":
		if rec.BodyHTML == "" {
			data, _ := io.ReadAll(r)
			rec.BodyHTML = string(data)
		}

	default:
		data, _ := io.ReadAll(r)
		if len(data) == 0 {
			return
		}
		name := filename
		if name == "" {
			if n, ok := params["name"]; ok {
				name = decodeRFC2047(n)
			}
		}
		*attachments = append(*attachments, emailAttachment{
			EmailID:     emailID,
			Filename:    name,
			ContentType: mediaType,
			SizeBytes:   int64(len(data)),
			SHA256:      hashBytes(data),
			IsExec:      isExecutable(name),
		})
	}
	_ = cte
}

func partFilename(disp, ct string) string {
	if disp != "" {
		_, params, err := mime.ParseMediaType(disp)
		if err == nil {
			if fn, ok := params["filename"]; ok {
				return decodeRFC2047(fn)
			}
		}
	}
	_, params, err := mime.ParseMediaType(ct)
	if err == nil {
		if n, ok := params["name"]; ok {
			return decodeRFC2047(n)
		}
	}
	return ""
}

func flattenAddrs(header string) string {
	if header == "" {
		return ""
	}
	decoded := decodeRFC2047(header)
	addrs, err := mail.ParseAddressList(decoded)
	if err != nil {
		return decoded
	}
	var out []string
	for _, a := range addrs {
		out = append(out, a.Address)
	}
	return strings.Join(out, ", ")
}

func decodeRFC2047(s string) string {
	decoded, err := new(mime.WordDecoder).DecodeHeader(s)
	if err != nil {
		return s
	}
	return decoded
}

func cleanIP(s string) string {
	return strings.Trim(strings.TrimSpace(s), "[]")
}

func parseReceivedDate(received string) *time.Time {
	if received == "" {
		return nil
	}
	if i := strings.LastIndex(received, ";"); i >= 0 {
		dateStr := strings.TrimSpace(received[i+1:])
		if t, err := mail.ParseDate(dateStr); err == nil {
			return &t
		}
	}
	return nil
}
