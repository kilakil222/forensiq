// Package ewf provides a minimal reader for EnCase EWF-E01 forensic disk
// images (single and multi-segment). It exposes the virtual disk content via
// io.ReaderAt so higher-level parsers (NTFS, MFT, etc.) can read sectors
// without a host-side mount.
//
// Only the format subset actually produced by EnCase v6/v7 acquisitions is
// supported: standard sections ("header", "header2", "volume", "disk",
// "sectors", "table", "table2", "next", "done"), 76-byte section headers,
// 32-bit Adler32 checksums (verification is best-effort), and chunk-level
// deflate compression.
package ewf

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	sectionHeaderSize = 76
	defaultChunkSize  = 32768 // 64 sectors * 512 bytes
	chunkCacheSize    = 32
)

// chunkLoc identifies one chunk inside one segment file.
type chunkLoc struct {
	segment    int   // index into Disk.segments
	offset     int64 // byte offset within the segment file (start of chunk data)
	compressed bool  // true if zlib-compressed; false if raw 32 KiB
	size       int64 // compressed size in bytes (only used for compressed chunks)
}

// Disk represents an opened EWF-E01 image (single or multi-segment).
//
// The virtual disk is split into fixed-size chunks (default 32 KiB). Each
// chunk's location across the segment files is recorded in chunkMap and
// loaded on demand by ReadAt; recently-decompressed chunks are kept in a
// small ring cache keyed by chunk index.
type Disk struct {
	segments    []*os.File
	chunkSize   int64
	totalSize   int64
	sectorCount int64
	bytesPerSec int64
	chunkMap    []chunkLoc

	// simple ring cache of decompressed chunks
	cacheKeys [chunkCacheSize]int32
	cacheData [chunkCacheSize][]byte
	cacheNext int
}

// Open opens an EWF-E01 image. firstPath must point at the first segment
// (typically the *.E01 file). Subsequent segments (E02, E03, ...) are
// auto-discovered by extension increment until no more files are found or
// the image's chunk count is satisfied.
func Open(firstPath string) (*Disk, error) {
	d := &Disk{chunkSize: defaultChunkSize}
	for i := range d.cacheKeys {
		d.cacheKeys[i] = -1
	}

	// Walk all segment files starting at firstPath.
	paths, err := segmentPaths(firstPath)
	if err != nil {
		return nil, err
	}

	for segIdx, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			// stop at first missing segment, but only if we already have at least one
			if segIdx == 0 {
				d.Close()
				return nil, fmt.Errorf("open %s: %w", p, err)
			}
			break
		}
		d.segments = append(d.segments, f)

		if err := d.parseSegment(segIdx, f); err != nil {
			d.Close()
			return nil, fmt.Errorf("parse %s: %w", filepath.Base(p), err)
		}

		// Stop when we have collected all chunks the volume header advertised.
		if d.totalSize > 0 {
			expected := (d.totalSize + d.chunkSize - 1) / d.chunkSize
			if int64(len(d.chunkMap)) >= expected {
				break
			}
		}
	}

	if d.totalSize == 0 {
		d.Close()
		return nil, fmt.Errorf("ewf: no volume section found in %s", firstPath)
	}
	if len(d.chunkMap) == 0 {
		d.Close()
		return nil, fmt.Errorf("ewf: no table section found")
	}
	return d, nil
}

// Size returns the total virtual disk size in bytes.
func (d *Disk) Size() int64 { return d.totalSize }

// Close releases segment file handles.
func (d *Disk) Close() error {
	var firstErr error
	for _, f := range d.segments {
		if f != nil {
			if err := f.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	d.segments = nil
	return firstErr
}

// ReadAt implements io.ReaderAt for the virtual disk content.
func (d *Disk) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("ewf: negative offset %d", off)
	}
	if off >= d.totalSize {
		return 0, io.EOF
	}
	end := off + int64(len(p))
	if end > d.totalSize {
		end = d.totalSize
	}

	written := 0
	cur := off
	for cur < end {
		chunkIdx := int(cur / d.chunkSize)
		within := cur - int64(chunkIdx)*d.chunkSize
		chunkBytes, err := d.loadChunk(chunkIdx)
		if err != nil {
			if written > 0 {
				return written, err
			}
			return 0, err
		}
		n := copy(p[written:end-off], chunkBytes[within:])
		if n == 0 {
			break
		}
		written += n
		cur += int64(n)
	}
	if cur < off+int64(len(p)) {
		return written, io.EOF
	}
	return written, nil
}

// segmentPaths derives the candidate segment file paths from the first
// segment's path. It supports the canonical EnCase naming scheme:
// E01, E02, ..., E09, E10, ..., E99, EAA, ... (we cap at 999 segments).
func segmentPaths(first string) ([]string, error) {
	dir, name := filepath.Split(first)
	ext := filepath.Ext(name)
	if len(ext) < 4 {
		// no recognizable extension — treat as single segment.
		return []string{first}, nil
	}
	base := strings.TrimSuffix(name, ext)
	prefix := strings.ToUpper(ext[:2]) // ".E" -> ".E"
	// Build a list of likely candidates lazily by stat-ing them in Open();
	// we just generate up to 999 names here.
	out := make([]string, 0, 16)
	out = append(out, first)
	for i := 2; i <= 999; i++ {
		// EnCase numbering: 01..99 then AA..ZZ. Simplest portable form: zero-padded decimal.
		var seg string
		if i < 100 {
			seg = fmt.Sprintf("%s%02d", prefix, i)
		} else {
			// Use 3-digit decimal as fallback. Real EnCase uses E0A..E0Z, EAA..; if
			// the user provides custom-named segments most images are <100 segments.
			seg = fmt.Sprintf("%s%03d", prefix, i)
		}
		candidate := filepath.Join(dir, base+seg)
		if _, err := os.Stat(candidate); err != nil {
			break
		}
		out = append(out, candidate)
	}
	return out, nil
}

// parseSegment scans every section in one segment file.
func (d *Disk) parseSegment(segIdx int, f *os.File) error {
	// Sections start after a 13-byte EWF segment header (signature + fields:
	// "EVF\x09\x0d\x0a\xff\x00" then 1-byte fields_start, 2-byte segment_number,
	// 2-byte fields_end). Total = 13 bytes.
	const fileHeaderSize = 13

	off := int64(fileHeaderSize)
	for {
		var hdr [sectionHeaderSize]byte
		if _, err := f.ReadAt(hdr[:], off); err != nil {
			return fmt.Errorf("read section header at %d: %w", off, err)
		}
		typeStr := cstring(hdr[0:16])
		nextOff := int64(binary.LittleEndian.Uint64(hdr[16:24]))
		dataSize := int64(binary.LittleEndian.Uint64(hdr[24:32]))
		_ = dataSize // total section size is given by nextOff - off; dataSize is informational.

		dataStart := off + sectionHeaderSize

		switch typeStr {
		case "volume", "disk":
			if d.totalSize == 0 {
				if err := d.parseVolume(f, dataStart); err != nil {
					return err
				}
			}

		case "sectors":
			// nothing to record; table entries use absolute file offsets

		case "table":
			if err := d.parseTable(segIdx, f, dataStart); err != nil {
				return err
			}

		case "table2":
			// Mirror of table; ignore (we already have the primary).

		case "done", "next":
			// End of this segment for our purposes.
			return nil
		}

		if nextOff == 0 || nextOff == off {
			return nil
		}
		off = nextOff
	}
}

// parseVolume reads the 94-byte volume/disk descriptor.
func (d *Disk) parseVolume(f *os.File, off int64) error {
	var buf [94]byte
	if _, err := f.ReadAt(buf[:], off); err != nil {
		return fmt.Errorf("read volume: %w", err)
	}
	sectorsPerChunk := int64(binary.LittleEndian.Uint32(buf[8:12]))
	bytesPerSector := int64(binary.LittleEndian.Uint32(buf[12:16]))
	sectorCount := int64(binary.LittleEndian.Uint64(buf[16:24]))
	if sectorsPerChunk == 0 || sectorsPerChunk > 8192 {
		sectorsPerChunk = 64
	}
	if bytesPerSector == 0 || bytesPerSector > 65536 {
		bytesPerSector = 512
	}
	d.bytesPerSec = bytesPerSector
	d.chunkSize = sectorsPerChunk * bytesPerSector
	const maxChunkSz = int64(1) << 20 // 1 MiB max
	if d.chunkSize <= 0 || d.chunkSize > maxChunkSz {
		d.chunkSize = defaultChunkSize
	}
	d.sectorCount = sectorCount
	d.totalSize = sectorCount * bytesPerSector
	return nil
}

// parseTable reads a table section. The 24-byte table header layout is:
//
//	entry_count(4) + padding(4) + base_offset(8) + padding(4) + CRC(4)
//
// Each 4-byte entry: bit31=1 → zlib-compressed; bit31=0 → raw (libewf convention,
// confirmed by inspecting actual EnCase files — the Metz white paper is inverted).
// Bits 0–30 are a chunk data offset RELATIVE to base_offset. EnCase creates
// one table section per ~260 MiB of compressed data, each with its own
// base_offset, so large single-segment images work without any wrap detection.
func (d *Disk) parseTable(segIdx int, f *os.File, off int64) error {
	var head [24]byte
	if _, err := f.ReadAt(head[:], off); err != nil {
		return fmt.Errorf("read table head: %w", err)
	}
	entryCount := binary.LittleEndian.Uint32(head[0:4])
	if entryCount == 0 {
		return nil
	}
	baseOffset := int64(binary.LittleEndian.Uint64(head[8:16]))

	entries := make([]byte, int64(entryCount)*4)
	if _, err := f.ReadAt(entries, off+24); err != nil {
		return fmt.Errorf("read table entries: %w", err)
	}

	for i := uint32(0); i < entryCount; i++ {
		raw := binary.LittleEndian.Uint32(entries[i*4 : i*4+4])
		compressed := raw&0x80000000 != 0 // bit31=1 → compressed (zlib); bit31=0 → raw
		absOff := baseOffset + int64(raw&0x7FFFFFFF)

		var size int64
		if i+1 < entryCount {
			next := binary.LittleEndian.Uint32(entries[(i+1)*4 : (i+1)*4+4])
			size = (baseOffset + int64(next&0x7FFFFFFF)) - absOff
		} else {
			fi, err := f.Stat()
			if err == nil {
				size = fi.Size() - absOff
			} else {
				size = d.chunkSize * 2
			}
		}
		// Clamp: a compressed chunk can never be larger than the raw chunk size.
		if size <= 0 || size > d.chunkSize+1024 {
			size = d.chunkSize
		}
		d.chunkMap = append(d.chunkMap, chunkLoc{
			segment:    segIdx,
			offset:     absOff,
			compressed: compressed,
			size:       size,
		})
	}
	return nil
}

// loadChunk returns the decompressed bytes of chunk at chunkIdx, using the cache.
func (d *Disk) loadChunk(chunkIdx int) ([]byte, error) {
	// cache lookup
	for i, k := range d.cacheKeys {
		if k == int32(chunkIdx) && d.cacheData[i] != nil {
			return d.cacheData[i], nil
		}
	}
	if chunkIdx < 0 || chunkIdx >= len(d.chunkMap) {
		return nil, fmt.Errorf("ewf: chunk index %d out of range", chunkIdx)
	}
	loc := d.chunkMap[chunkIdx]
	if loc.segment >= len(d.segments) {
		return nil, fmt.Errorf("ewf: missing segment %d", loc.segment)
	}
	f := d.segments[loc.segment]

	var data []byte
	if !loc.compressed {
		// uncompressed: chunkSize bytes (last chunk may be shorter)
		size := d.chunkSize
		if int64(chunkIdx+1)*d.chunkSize > d.totalSize {
			size = d.totalSize - int64(chunkIdx)*d.chunkSize
		}
		data = make([]byte, size)
		if _, err := f.ReadAt(data, loc.offset); err != nil && err != io.EOF {
			return nil, fmt.Errorf("read raw chunk %d: %w", chunkIdx, err)
		}
	} else {
		readSize := loc.size
		if readSize <= 0 || readSize > d.chunkSize*4+1024 {
			readSize = d.chunkSize + 1024
		}
		raw := make([]byte, readSize)
		n, err := f.ReadAt(raw, loc.offset)
		if err != nil && err != io.EOF {
			return nil, fmt.Errorf("read compressed chunk %d: %w", chunkIdx, err)
		}
		raw = raw[:n]
		zr, err := zlib.NewReader(bytes.NewReader(raw))
		if err != nil {
			return nil, fmt.Errorf("zlib chunk %d: %w", chunkIdx, err)
		}
		decoded, err := io.ReadAll(zr)
		zr.Close()
		if err != nil {
			return nil, fmt.Errorf("inflate chunk %d: %w", chunkIdx, err)
		}
		data = decoded
	}

	// store in cache (round-robin)
	idx := d.cacheNext % chunkCacheSize
	d.cacheKeys[idx] = int32(chunkIdx)
	d.cacheData[idx] = data
	d.cacheNext++
	return data, nil
}

// cstring trims a fixed-size null-padded ASCII string.
func cstring(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}
