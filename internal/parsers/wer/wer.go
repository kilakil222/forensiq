// Package wer parses Windows Error Reporting .wer report files.
// WER files are INI-style text; some may be UTF-16LE encoded.
// Extracts crash metadata into the wer_crashes table.
package wer

import (
	"bufio"
	"bytes"
	"database/sql"
	"encoding/binary"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"forensiq/internal/parsers"
)

type Parser struct{ source string }

func New(source string) *Parser { return &Parser{source: source} }
func (p *Parser) Name() string  { return "WER/CrashReport" }

func (p *Parser) Parse(r io.Reader, db *sql.DB, ch chan<- parsers.Progress) error {
	start := time.Now()

	data, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("wer: read: %w", err)
	}

	// Handle UTF-16LE BOM
	if len(data) >= 2 && data[0] == 0xFF && data[1] == 0xFE {
		data = utf16LEToUTF8(data[2:])
	} else if looksUTF16LE(data) {
		data = utf16LEToUTF8(data)
	}

	// Attempt LZNT1 decompression if the first 2 bytes look like a compressed chunk header
	if looksLZNT1(data) {
		if dec, derr := lznt1Decompress(data); derr == nil && len(dec) > len(data) {
			data = dec
		}
	}

	rec := parseINI(data)
	appName := pick(rec, "Sig[0].Value", "AppName")
	if appName == "" {
		ch <- parsers.Progress{Parser: p.Name(), Count: 0, Done: true, Elapsed: time.Since(start)}
		return nil
	}

	stmt, err := db.Prepare(`INSERT INTO wer_crashes
		(app_name, app_path, app_version, app_timestamp, crash_time,
		 fault_module, fault_module_version, exception_code, exception_offset, bucket_id, source_file)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("wer: prepare: %w", err)
	}
	defer stmt.Close()

	var crashTime time.Time
	if et := rec["EventTime"]; et != "" {
		if ft, perr := strconv.ParseUint(et, 10, 64); perr == nil {
			crashTime = filetimeToUTC(ft)
		}
	}

	_, err = stmt.Exec(
		appName,
		pick(rec, "AppPath"),
		pick(rec, "Sig[1].Value"),
		pick(rec, "Sig[2].Value"),
		nullTime(crashTime),
		pick(rec, "Sig[3].Value"),
		pick(rec, "Sig[4].Value"),
		pick(rec, "Sig[6].Value"),
		pick(rec, "Sig[7].Value"),
		rec["Bucket"],
		p.source,
	)
	if err != nil {
		return fmt.Errorf("wer: insert: %w", err)
	}

	ch <- parsers.Progress{Parser: p.Name(), Count: 1, Done: true, Elapsed: time.Since(start)}
	return nil
}

func nullTime(t time.Time) interface{} {
	if t.IsZero() {
		return nil
	}
	return t
}

func pick(m map[string]string, keys ...string) string {
	for _, k := range keys {
		if v := m[k]; v != "" {
			return v
		}
	}
	return ""
}

func parseINI(data []byte) map[string]string {
	m := make(map[string]string)
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if idx := strings.IndexByte(line, '='); idx > 0 {
			m[strings.TrimSpace(line[:idx])] = strings.TrimSpace(line[idx+1:])
		}
	}
	return m
}

// filetimeToUTC converts a Windows FILETIME (100ns intervals since 1601-01-01) to UTC.
func filetimeToUTC(ft uint64) time.Time {
	const windowsEpoch = int64(116444736000000000) // 100-ns ticks between 1601 and 1970
	nsec := (int64(ft) - windowsEpoch) * 100
	return time.Unix(0, nsec).UTC()
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
	var buf bytes.Buffer
	buf.Grow(len(runes) * 2)
	b := [4]byte{}
	for _, r := range runes {
		n := utf8.EncodeRune(b[:], r)
		buf.Write(b[:n])
	}
	return buf.Bytes()
}

func looksUTF16LE(data []byte) bool {
	if len(data) < 8 {
		return false
	}
	zeros := 0
	check := len(data)
	if check > 64 {
		check = 64
	}
	for i := 1; i < check; i += 2 {
		if data[i] == 0 {
			zeros++
		}
	}
	return zeros >= check/4
}

func looksLZNT1(data []byte) bool {
	if len(data) < 2 {
		return false
	}
	hdr := binary.LittleEndian.Uint16(data)
	return hdr&0x8000 != 0 && hdr&0x0FFF > 0
}

// lznt1Decompress decompresses LZNT1-compressed data (Windows kernel compression type 2).
func lznt1Decompress(data []byte) ([]byte, error) {
	var out []byte
	i := 0
	for i+2 <= len(data) {
		hdr := binary.LittleEndian.Uint16(data[i:])
		i += 2
		if hdr == 0 {
			break
		}
		compressed := hdr&0x8000 != 0
		chunkPayload := int(hdr&0x0FFF) + 1 // payload bytes after header

		end := i + chunkPayload
		if end > len(data) {
			end = len(data)
		}
		chunk := data[i:end]
		i = end

		if !compressed {
			out = append(out, chunk...)
			continue
		}
		dec, err := decompressChunk(chunk)
		if err != nil {
			return nil, err
		}
		out = append(out, dec...)
	}
	return out, nil
}

func decompressChunk(data []byte) ([]byte, error) {
	var out []byte
	i := 0
	for i < len(data) {
		flags := data[i]
		i++
		for bit := 0; bit < 8 && i < len(data); bit++ {
			if flags&(1<<uint(bit)) != 0 {
				if i+2 > len(data) {
					return nil, fmt.Errorf("lznt1: truncated back-ref at %d", i)
				}
				ref := binary.LittleEndian.Uint16(data[i:])
				i += 2

				lb := lenFieldBits(len(out))
				length := int(ref&((1<<uint(lb))-1)) + 3
				disp := int(ref>>uint(lb)) + 1
				if disp > len(out) {
					return nil, fmt.Errorf("lznt1: disp %d > out %d", disp, len(out))
				}
				base := len(out) - disp
				for j := 0; j < length; j++ {
					out = append(out, out[base+j%disp])
				}
			} else {
				out = append(out, data[i])
				i++
			}
		}
	}
	return out, nil
}

// lenFieldBits returns how many low bits of a back-reference encode length,
// which varies with current output position (LZNT1 spec §2.6).
func lenFieldBits(pos int) int {
	bits := 4
	for mask := 0x10; mask <= pos && bits < 12; mask <<= 1 {
		bits++
	}
	return bits
}
