package email

import (
	"database/sql"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf16"

	"forensiq/internal/parsers"
)

// MSGParser parses Outlook .msg files (OLE2 Compound Binary Format).
type MSGParser struct {
	sourceName string
}

func NewMSG(sourceName string) *MSGParser {
	return &MSGParser{sourceName: sourceName}
}

func (p *MSGParser) Name() string { return "Email/MSG" }

func (p *MSGParser) Parse(r io.Reader, db *sql.DB, ch chan<- parsers.Progress) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("msg read: %w", err)
	}
	rec, attachments, urls, err := parseMSG(data, p.sourceName)
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

// ── MSG property tag constants ────────────────────────────────────────────────

const (
	prSubject           = "0037"
	prSenderName        = "0C1A"
	prSenderSMTP        = "0C1F"
	prSenderEmail       = "0076" // PR_RECEIVED_REPRESENTING_SMTP_ADDRESS fallback
	prDisplayTo         = "0E04"
	prDisplayCC         = "0E03"
	prDisplayBCC        = "0E02"
	prClientSubmitTime  = "0039"
	prDeliveryTime      = "0E06"
	prBodyText          = "1000"
	prBodyHTML          = "1013"
	prInternetMsgID     = "1035"
	prReplyTo           = "1042"
	prSentRepName       = "0042" // PR_SENT_REPRESENTING_NAME
	prSentRepEmail      = "0065" // PR_SENT_REPRESENTING_SMTP_ADDRESS
	prXHeader           = "007D" // PR_TRANSPORT_MESSAGE_HEADERS

	prAttachFilename    = "3704"
	prAttachLongFilename = "3707"
	prAttachData        = "3701"
	prAttachContentType = "370E"
	prAttachMimeTag     = "370B"

	typUnicode = "001F"
	typString8 = "001E"
	typBinary  = "0102"
	typSysTime = "0040"
)

func parseMSG(data []byte, sourceName string) (*emailRecord, []emailAttachment, []emailURL, error) {
	cfb, err := openCFB(data)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("cfb: %w", err)
	}

	id := nextID()
	rec := &emailRecord{
		ID:         id,
		SourceFile: sourceName,
	}

	// Helper: read a string property (try Unicode first, fall back to ASCII)
	readStr := func(tag string) string {
		if s := cfbReadString(cfb, 0, tag+typUnicode); s != "" {
			return s
		}
		return cfbReadString(cfb, 0, tag+typString8)
	}

	rec.Subject = readStr(prSubject)
	rec.FromName = readStr(prSenderName)
	rec.FromAddr = readStr(prSenderSMTP)
	if rec.FromAddr == "" {
		rec.FromAddr = readStr(prSenderEmail)
	}
	if rec.FromAddr == "" {
		rec.FromAddr = readStr(prSentRepEmail)
	}
	if rec.FromName == "" {
		rec.FromName = readStr(prSentRepName)
	}
	rec.ToAddrs = readStr(prDisplayTo)
	rec.CcAddrs = readStr(prDisplayCC)
	rec.BccAddrs = readStr(prDisplayBCC)
	rec.ReplyTo = readStr(prReplyTo)
	rec.MessageID = strings.Trim(readStr(prInternetMsgID), "<> ")

	// Parse transport headers for X-Mailer / X-Originating-IP
	if headers := readStr(prXHeader); headers != "" {
		rec.HeadersRaw = headers
		rec.XMailer = extractHeader(headers, "X-Mailer")
		rec.XOriginatingIP = cleanIP(extractHeader(headers, "X-Originating-IP"))
	}

	// Timestamps (FILETIME: 100ns intervals since 1601-01-01 UTC)
	if ft := cfbReadBinary(cfb, 0, prClientSubmitTime+typSysTime); len(ft) == 8 {
		rec.SentAt = filetime2Time(binary.LittleEndian.Uint64(ft))
	}
	if ft := cfbReadBinary(cfb, 0, prDeliveryTime+typSysTime); len(ft) == 8 {
		rec.ReceivedAt = filetime2Time(binary.LittleEndian.Uint64(ft))
	}

	// Body
	rec.BodyText = readStr(prBodyText)
	if html := cfbReadBinary(cfb, 0, prBodyHTML+typBinary); len(html) > 0 {
		rec.BodyHTML = string(html)
	}
	if rec.BodyHTML == "" {
		rec.BodyHTML = readStr(prBodyHTML)
	}

	// Attachments: sub-storages "__attach_#XXXXXXXX"
	var attachments []emailAttachment
	for _, child := range cfb.listChildren(0) {
		if !strings.HasPrefix(strings.ToUpper(child.name), "__ATTACH_") {
			continue
		}
		att := parseAttachment(cfb, child.idx, id)
		if att != nil {
			attachments = append(attachments, *att)
		}
	}
	rec.HasAttachments = len(attachments) > 0

	urls := extractURLs(id, rec.BodyText+" "+rec.BodyHTML)
	return rec, attachments, urls, nil
}

func parseAttachment(cfb *cfbFile, storageIdx uint32, emailID int64) *emailAttachment {
	readStr := func(tag string) string {
		if s := cfbReadString(cfb, storageIdx, tag+typUnicode); s != "" {
			return s
		}
		return cfbReadString(cfb, storageIdx, tag+typString8)
	}

	filename := readStr(prAttachLongFilename)
	if filename == "" {
		filename = readStr(prAttachFilename)
	}

	ct := readStr(prAttachContentType)
	if ct == "" {
		ct = readStr(prAttachMimeTag)
	}

	attData := cfbReadBinary(cfb, storageIdx, prAttachData+typBinary)
	if len(attData) == 0 {
		return nil
	}

	return &emailAttachment{
		EmailID:     emailID,
		Filename:    filename,
		ContentType: ct,
		SizeBytes:   int64(len(attData)),
		SHA256:      hashBytes(attData),
		IsExec:      isExecutable(filename),
	}
}

// ── Minimal OLE2/CFB reader ───────────────────────────────────────────────────

var cfbMagic = []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}

const (
	secFree    = uint32(0xFFFFFFFF)
	secEOC     = uint32(0xFFFFFFFE)
	secFAT     = uint32(0xFFFFFFFD)
	secDIFAT   = uint32(0xFFFFFFFC)
	miniCutoff = uint32(4096)
)

type cfbDirEntry struct {
	name  string
	typ   uint8 // 0=empty,1=storage,2=stream,5=root
	start uint32
	size  uint32
	child uint32
	left  uint32
	right uint32
}

type cfbFile struct {
	data           []byte
	secSize        int
	miniSecSize    int
	fat            []uint32
	miniFAT        []uint32
	dir            []cfbDirEntry
	miniStreamStart uint32
}

type cfbChildRef struct {
	idx  uint32
	name string
}

func openCFB(data []byte) (*cfbFile, error) {
	if len(data) < 512 {
		return nil, fmt.Errorf("file too small")
	}
	for i, b := range cfbMagic {
		if data[i] != b {
			return nil, fmt.Errorf("bad magic")
		}
	}

	le := binary.LittleEndian
	secShift := le.Uint16(data[30:32])
	miniShift := le.Uint16(data[32:34])
	secSize := 1 << secShift
	miniSecSize := 1 << miniShift

	numFAT := le.Uint32(data[44:48])
	firstDir := le.Uint32(data[48:52])
	firstMiniFAT := le.Uint32(data[60:64])
	numMiniFAT := le.Uint32(data[64:68])
	firstDIFAT := le.Uint32(data[68:72])

	f := &cfbFile{
		data:        data,
		secSize:     secSize,
		miniSecSize: miniSecSize,
	}

	// Collect FAT sector numbers from header DIFAT (first 109 entries at offset 76)
	var fatSecs []uint32
	for i := 0; i < 109; i++ {
		s := le.Uint32(data[76+i*4:])
		if s == secFree || s == secEOC {
			break
		}
		if s == secFAT || s == secDIFAT {
			continue
		}
		fatSecs = append(fatSecs, s)
		if uint32(len(fatSecs)) >= numFAT {
			break
		}
	}

	// Follow DIFAT chain
	difSec := firstDIFAT
	for difSec != secEOC && difSec != secFree && uint32(len(fatSecs)) < numFAT {
		sd := f.secData(difSec)
		if sd == nil {
			break
		}
		perSec := secSize/4 - 1
		for i := 0; i < perSec && uint32(len(fatSecs)) < numFAT; i++ {
			s := le.Uint32(sd[i*4:])
			if s == secFree || s == secEOC {
				break
			}
			fatSecs = append(fatSecs, s)
		}
		difSec = le.Uint32(sd[secSize-4:])
	}

	// Build FAT
	f.fat = make([]uint32, len(fatSecs)*secSize/4)
	for i, s := range fatSecs {
		sd := f.secData(s)
		if sd == nil {
			continue
		}
		base := i * secSize / 4
		for j := 0; j < secSize/4; j++ {
			f.fat[base+j] = le.Uint32(sd[j*4:])
		}
	}

	// Build mini FAT
	if firstMiniFAT != secEOC && firstMiniFAT != secFree && numMiniFAT > 0 {
		md := f.readChain(firstMiniFAT)
		f.miniFAT = make([]uint32, len(md)/4)
		for i := range f.miniFAT {
			f.miniFAT[i] = le.Uint32(md[i*4:])
		}
	}

	// Read directory entries
	dd := f.readChain(firstDir)
	for i := 0; i+128 <= len(dd); i += 128 {
		e := dd[i : i+128]
		nameLen := le.Uint16(e[64:66])
		if nameLen > 64 {
			nameLen = 64
		}
		name := ""
		if nameLen >= 2 {
			runes := make([]uint16, (nameLen-2)/2)
			for j := range runes {
				runes[j] = le.Uint16(e[j*2:])
			}
			name = string(utf16.Decode(runes))
		}
		f.dir = append(f.dir, cfbDirEntry{
			name:  name,
			typ:   e[66],
			start: le.Uint32(e[116:120]),
			size:  le.Uint32(e[120:124]),
			child: le.Uint32(e[100:104]),
			left:  le.Uint32(e[92:96]),
			right: le.Uint32(e[96:100]),
		})
	}

	// Root entry provides mini stream location
	if len(f.dir) > 0 {
		f.miniStreamStart = f.dir[0].start
	}

	return f, nil
}

func (f *cfbFile) secData(sec uint32) []byte {
	off := (int(sec) + 1) * f.secSize
	if off+f.secSize > len(f.data) {
		return nil
	}
	return f.data[off : off+f.secSize]
}

func (f *cfbFile) readChain(start uint32) []byte {
	if start == secEOC || start == secFree {
		return nil
	}
	var out []byte
	seen := make(map[uint32]bool)
	s := start
	for s != secEOC && s != secFree {
		if seen[s] || int(s) >= len(f.fat) {
			break
		}
		seen[s] = true
		sd := f.secData(s)
		if sd == nil {
			break
		}
		out = append(out, sd...)
		s = f.fat[s]
	}
	return out
}

func (f *cfbFile) readMiniChain(start, size uint32) []byte {
	if start == secEOC || start == secFree || len(f.miniFAT) == 0 {
		return nil
	}
	ms := f.readChain(f.miniStreamStart)
	var out []byte
	seen := make(map[uint32]bool)
	s := start
	for s != secEOC && s != secFree {
		if seen[s] || int(s) >= len(f.miniFAT) {
			break
		}
		seen[s] = true
		off := int(s) * f.miniSecSize
		if off+f.miniSecSize > len(ms) {
			break
		}
		out = append(out, ms[off:off+f.miniSecSize]...)
		s = f.miniFAT[s]
	}
	if uint32(len(out)) > size {
		out = out[:size]
	}
	return out
}

func (f *cfbFile) streamData(e *cfbDirEntry) []byte {
	if e.typ != 2 {
		return nil
	}
	if e.size < miniCutoff && len(f.miniFAT) > 0 {
		return f.readMiniChain(e.start, e.size)
	}
	d := f.readChain(e.start)
	if uint32(len(d)) > e.size {
		d = d[:e.size]
	}
	return d
}

// findChild searches the red-black tree of children under parentIdx for a named entry.
func (f *cfbFile) findChild(parentIdx uint32, name string) *cfbDirEntry {
	if int(parentIdx) >= len(f.dir) {
		return nil
	}
	parent := f.dir[parentIdx]
	return f.searchTree(parent.child, strings.ToUpper(name))
}

func (f *cfbFile) searchTree(idx uint32, upperName string) *cfbDirEntry {
	if idx == 0xFFFFFFFF || int(idx) >= len(f.dir) {
		return nil
	}
	e := &f.dir[idx]
	upper := strings.ToUpper(e.name)
	if upper == upperName {
		return e
	}
	if l := f.searchTree(e.left, upperName); l != nil {
		return l
	}
	return f.searchTree(e.right, upperName)
}

// listChildren returns all direct children of a storage entry.
func (f *cfbFile) listChildren(parentIdx uint32) []cfbChildRef {
	if int(parentIdx) >= len(f.dir) {
		return nil
	}
	var out []cfbChildRef
	f.collectTree(f.dir[parentIdx].child, &out)
	return out
}

func (f *cfbFile) collectTree(idx uint32, out *[]cfbChildRef) {
	if idx == 0xFFFFFFFF || int(idx) >= len(f.dir) {
		return
	}
	e := &f.dir[idx]
	*out = append(*out, cfbChildRef{idx: idx, name: e.name})
	f.collectTree(e.left, out)
	f.collectTree(e.right, out)
}

// ── Property stream helpers ───────────────────────────────────────────────────

// streamName returns the standard MSG property stream name.
func streamName(propTag string) string {
	return "__substg1.0_" + strings.ToUpper(propTag)
}

// cfbReadBinary reads a binary/SYSTIME property from within a given storage.
// parentIdx=0 means root storage.
func cfbReadBinary(cfb *cfbFile, parentIdx uint32, propTag string) []byte {
	name := streamName(propTag)
	var entry *cfbDirEntry
	if parentIdx == 0 {
		entry = cfb.searchTree(cfb.dir[0].child, strings.ToUpper(name))
	} else {
		entry = cfb.findChild(parentIdx, name)
	}
	if entry == nil {
		return nil
	}
	return cfb.streamData(entry)
}

// cfbReadString reads a string property (001F=Unicode UTF-16LE, 001E=ANSI).
func cfbReadString(cfb *cfbFile, parentIdx uint32, propTag string) string {
	d := cfbReadBinary(cfb, parentIdx, propTag)
	if len(d) == 0 {
		return ""
	}
	if strings.HasSuffix(strings.ToUpper(propTag), typUnicode) {
		return decodeUTF16LE(d)
	}
	// ANSI — strip trailing null
	s := strings.TrimRight(string(d), "\x00")
	return s
}

func decodeUTF16LE(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	u16 := make([]uint16, len(b)/2)
	for i := range u16 {
		u16[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	// Strip BOM and null terminator
	if len(u16) > 0 && u16[0] == 0xFEFF {
		u16 = u16[1:]
	}
	for len(u16) > 0 && u16[len(u16)-1] == 0 {
		u16 = u16[:len(u16)-1]
	}
	return string(utf16.Decode(u16))
}

// filetime2Time converts Windows FILETIME to *time.Time.
// FILETIME = 100-nanosecond intervals since 1601-01-01 00:00:00 UTC.
func filetime2Time(ft uint64) *time.Time {
	if ft == 0 {
		return nil
	}
	// Convert to Unix time: subtract 116444736000000000 (100ns intervals 1601→1970)
	const epochDiff = uint64(116444736000000000)
	if ft < epochDiff {
		return nil
	}
	ns := int64((ft - epochDiff) * 100)
	t := time.Unix(0, ns).UTC()
	return &t
}

func extractHeader(headers, name string) string {
	for _, line := range strings.Split(headers, "\n") {
		if strings.HasPrefix(strings.ToLower(line), strings.ToLower(name)+":") {
			return strings.TrimSpace(line[len(name)+1:])
		}
	}
	return ""
}
