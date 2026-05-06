package prefetch

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

type PrefetchParser struct{}

func New() *PrefetchParser { return &PrefetchParser{} }

func (p *PrefetchParser) Name() string { return "Prefetch" }

func (p *PrefetchParser) Parse(r io.Reader, db *sql.DB, ch chan<- parsers.Progress) error {
	start := time.Now()
	data, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("read prefetch: %w", err)
	}
	if len(data) < 8 {
		return fmt.Errorf("prefetch too short: %d bytes", len(data))
	}

	// Win10+ prefetch files are MAM (LZXPRESS Huffman) compressed
	if data[0] == 'M' && data[1] == 'A' && data[2] == 'M' {
		decompressed, err := decompressMAM(data)
		if err != nil {
			return fmt.Errorf("prefetch MAM decompression: %w", err)
		}
		data = decompressed
	}

	if len(data) < 84 {
		return fmt.Errorf("prefetch too short after decompression: %d bytes", len(data))
	}

	version := binary.LittleEndian.Uint32(data[0:4])
	if string(data[4:8]) != "SCCA" {
		return fmt.Errorf("invalid signature: %q", string(data[4:8]))
	}

	// Filename at offset 16: 30 UTF-16LE characters = 60 bytes
	// (Hash follows immediately at offset 76, confirmed against real Win10 .pf files)
	if len(data) < 76 {
		return fmt.Errorf("prefetch too short for filename: %d bytes", len(data))
	}
	filename := strings.TrimRight(parseUTF16(data[16:76]), "\x00")

	var runCount uint32
	var lastRunTS time.Time
	var execPath string
	var volumePaths string

	switch version {
	case 17: // WinXP — offsets vary, basic support
		if len(data) < 148 {
			return fmt.Errorf("WinXP prefetch too short")
		}
		runCount = binary.LittleEndian.Uint32(data[144:148])
		lastRunTS = filetimeToTime(binary.LittleEndian.Uint64(data[100:108]))
	case 23, 26: // Win7/Win8
		if len(data) < 156 {
			return fmt.Errorf("Win7/8 prefetch too short: %d bytes", len(data))
		}
		runCount = binary.LittleEndian.Uint32(data[152:156])
		lastRunTS = filetimeToTime(binary.LittleEndian.Uint64(data[100:108]))
	case 30: // Win10 (may be MAM-compressed)
		// run_count at 120, last_run_time[0] at 128 (up to 8 run times × 8 bytes each)
		// filenames_offset at 100, filenames_size at 104
		// volumes_info_offset at 108, volumes_count at 112
		if len(data) < 136 {
			return fmt.Errorf("Win10 prefetch too short or compressed")
		}
		runCount = binary.LittleEndian.Uint32(data[120:124])
		lastRunTS = filetimeToTime(binary.LittleEndian.Uint64(data[128:136]))
		execPath, volumePaths = parseV30Sections(data)
	default:
		return fmt.Errorf("unsupported prefetch version: %d", version)
	}

	var fileRefs []string
	if version == 23 || version == 26 || version == 30 {
		fileRefs = extractFileRefs(data)
	}

	stmt, err := db.Prepare(`INSERT INTO prefetch (filename, path, run_count, last_run, volume_paths, file_refs) VALUES (?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare prefetch insert: %w", err)
	}
	defer stmt.Close()

	var pathArg, volArg, refsArg any
	if execPath != "" {
		pathArg = execPath
	}
	if volumePaths != "" {
		volArg = volumePaths
	}
	if len(fileRefs) > 0 {
		refsArg = strings.Join(fileRefs, "\n")
	}
	if _, err := stmt.Exec(filename, pathArg, runCount, lastRunTS, volArg, refsArg); err != nil {
		return fmt.Errorf("insert prefetch: %w", err)
	}

	ch <- parsers.Progress{
		Parser:  p.Name(),
		Count:   1,
		Done:    true,
		Elapsed: time.Since(start),
	}
	return nil
}

func parseUTF16(b []byte) string {
	u16 := make([]uint16, len(b)/2)
	for i := range u16 {
		u16[i] = binary.LittleEndian.Uint16(b[i*2 : i*2+2])
	}
	return string(utf16.Decode(u16))
}

// parseV30Sections extracts the executable path and volume device paths from a
// decompressed Win10 (version 30) prefetch file.
func parseV30Sections(data []byte) (execPath, volumePaths string) {
	if len(data) < 120 {
		return
	}

	// Filenames section C: offset at [100], byte-size at [104].
	// We scan it once to extract both the exe path and the unique volume roots.
	fnOff := int(binary.LittleEndian.Uint32(data[100:104]))
	fnSize := int(binary.LittleEndian.Uint32(data[104:108]))
	if fnOff <= 0 || fnSize < 2 || fnOff+fnSize > len(data) {
		return
	}
	exeName := strings.ToLower(strings.TrimRight(parseUTF16(data[16:76]), "\x00"))
	fnData := data[fnOff : fnOff+fnSize]
	seenVol := map[string]bool{}
	var vols []string
	i := 0
	for i+1 < len(fnData) {
		j := i
		for j+1 < len(fnData) && !(fnData[j] == 0 && fnData[j+1] == 0) {
			j += 2
		}
		if j > i {
			s := parseUTF16(fnData[i:j])
			// Extract exe path: match base name against SCCA header name.
			if execPath == "" && isASCIIPath(s) && strings.ContainsRune(s, '\\') {
				lastSlash := strings.LastIndexByte(s, '\\')
				base := strings.ToLower(s[lastSlash+1:])
				if base == exeName || (len(base) > len(exeName) && strings.HasPrefix(base, exeName)) {
					execPath = s
				}
			}
			// Extract unique volume root from each path in section C.
			// Only accept roots that are clean ASCII (garbled decompression artifacts
			// can produce invalid Unicode codepoints in otherwise-correct paths).
			volRoot := volumeRoot(s)
			if volRoot != "" && isASCIIPath(volRoot) && !seenVol[volRoot] {
				seenVol[volRoot] = true
				vols = append(vols, volRoot)
			}
		}
		i = j + 2
	}
	volumePaths = strings.Join(vols, ";")
	return
}

// volumeRoot extracts the volume device root from a full prefetch path string.
// e.g. "\VOLUME{guid}\foo\bar" → "\VOLUME{guid}"
//
//	"\Device\HarddiskVolume3\foo" → "\Device\HarddiskVolume3"
func volumeRoot(s string) string {
	if strings.HasPrefix(s, `\VOLUME{`) {
		end := strings.IndexByte(s, '}')
		if end <= 8 {
			return ""
		}
		inner := s[8:end]
		for _, r := range inner {
			if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') || r == '-') {
				return ""
			}
		}
		return s[:end+1]
	}
	if strings.HasPrefix(s, `\Device\`) {
		// e.g. \Device\HarddiskVolume3 — find the next \ after the volume name
		idx := strings.Index(s[8:], `\`)
		if idx >= 0 {
			return s[:8+idx]
		}
		return s
	}
	return ""
}

// isASCIIPath returns true if every rune in s is printable ASCII (0x20–0x7E)
// or a backslash. Garbled decompression output produces codepoints > 0x7F.
func isASCIIPath(s string) bool {
	for _, r := range s {
		if r > 0x7E {
			return false
		}
	}
	return true
}

// extractFileRefs returns all file paths from Section C (filename strings section).
// Section C offset is at header[100:104], size at header[104:108] for all versions.
// Each entry is a null-terminated UTF-16LE string; strings are concatenated sequentially.
func extractFileRefs(data []byte) []string {
	if len(data) < 108 {
		return nil
	}
	fnOff := int(binary.LittleEndian.Uint32(data[100:104]))
	fnSize := int(binary.LittleEndian.Uint32(data[104:108]))
	if fnOff <= 0 || fnSize < 2 || fnOff+fnSize > len(data) {
		return nil
	}
	fnData := data[fnOff : fnOff+fnSize]
	var refs []string
	i := 0
	for i+1 < len(fnData) {
		j := i
		for j+1 < len(fnData) && !(fnData[j] == 0 && fnData[j+1] == 0) {
			j += 2
		}
		if j > i {
			s := parseUTF16(fnData[i:j])
			if isASCIIPath(s) {
				refs = append(refs, s)
			}
		}
		i = j + 2
	}
	return refs
}

// firstUTF16String returns the first null-terminated UTF-16LE string from b.
func firstUTF16String(b []byte) string {
	for i := 0; i+1 < len(b); i += 2 {
		if b[i] == 0 && b[i+1] == 0 {
			return parseUTF16(b[:i])
		}
	}
	return parseUTF16(b)
}

func filetimeToTime(ft uint64) time.Time {
	const epoch = uint64(116444736000000000) // 100ns intervals from 1601-01-01 to Unix epoch
	if ft == 0 || ft < epoch {
		return time.Time{}
	}
	return time.Unix(0, int64((ft-epoch)*100)).UTC()
}
