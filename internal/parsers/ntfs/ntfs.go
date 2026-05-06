// Package ntfs implements a minimal, read-only NTFS volume walker that
// extracts forensic artifacts from a disk image presented as io.ReaderAt.
//
// The walker:
//  1. Parses the NTFS boot sector to discover MFT location and cluster size.
//  2. Reads MFT record 0 to obtain the data runs of the $MFT itself.
//  3. Iterates every MFT record sequentially, applying the Update Sequence
//     Array fixup, and indexes (recordNo -> name, parentRef) for path
//     reconstruction.
//  4. For each record whose $FILE_NAME matches one of the requested patterns,
//     reconstructs its full path and exposes its $DATA stream via an
//     io.Reader to the caller's callback.
//
// Compression, encryption, and ADS streams are intentionally not handled.
// Edge cases (sparse runs in $DATA, attribute lists for huge files) are
// skipped gracefully rather than aborting the scan.
package ntfs

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"path"
	"strings"
	"unicode/utf16"
)

const (
	mftRecordSize = 1024
	rootRef       = 5
)

// Volume represents a parsed NTFS volume.
type Volume struct {
	r              io.ReaderAt
	partitionStart int64

	bytesPerSector       int64
	sectorsPerCluster    int64
	clusterSize          int64
	mftLCN               int64
	clustersPerFileRec   int64 // resolved size in bytes
	mftRecordSize        int64
	mftRuns              []dataRun
	mftSize              int64

	// in-memory index built during scan: MFT record number -> entry
	index map[uint64]indexEntry

	// transient: set by extractDataRef per-record, consumed immediately by walker.
	// Only safe under single-goroutine scan.
	lastCompressed bool
	lastCompUnit   int64 // 1<<CompressionUnit (clusters per compression unit)
}

type indexEntry struct {
	name     string
	parent   uint64
	isDir    bool
}

// FileEntry describes a file located inside the NTFS volume.
type FileEntry struct {
	Name     string // basename
	Path     string // full path from volume root, slash-separated
	Size     int64
	IsDir    bool
	MFTRecNo uint64
}

// dataRun describes one fragment of a non-resident attribute.
type dataRun struct {
	lcn     int64 // logical cluster number; -1 for sparse
	length  int64 // run length in clusters
}

// dataAttr describes a non-resident $DATA attribute (incl. compression hints).
type dataAttr struct {
	runs             []dataRun
	size             int64
	compressed       bool  // FILE_ATTRIBUTE_COMPRESSED on the attribute
	compUnitClusters int64 // 1 << CompressionUnit (typically 16); 0 if not compressed
}

// attrListEntry is one entry from an $ATTRIBUTE_LIST (typeID 0x20).
type attrListEntry struct {
	typeID   uint32
	startVCN int64
	mftRef   uint64 // lower 48 bits = MFT record number
}

// OpenVolume parses the NTFS boot sector at the given byte offset within r.
func OpenVolume(r io.ReaderAt, offset int64) (*Volume, error) {
	var boot [512]byte
	if _, err := r.ReadAt(boot[:], offset); err != nil {
		return nil, fmt.Errorf("ntfs: read boot sector: %w", err)
	}
	if string(boot[3:11]) != "NTFS    " {
		return nil, fmt.Errorf("ntfs: not an NTFS volume (oem=%q)", string(boot[3:11]))
	}
	v := &Volume{r: r, partitionStart: offset}
	v.bytesPerSector = int64(binary.LittleEndian.Uint16(boot[11:13]))
	v.sectorsPerCluster = int64(boot[13])
	if v.bytesPerSector == 0 {
		v.bytesPerSector = 512
	}
	if v.sectorsPerCluster == 0 {
		v.sectorsPerCluster = 1
	}
	v.clusterSize = v.bytesPerSector * v.sectorsPerCluster
	v.mftLCN = int64(binary.LittleEndian.Uint64(boot[48:56]))

	cpfr := int8(boot[64])
	if cpfr > 0 {
		v.mftRecordSize = int64(cpfr) * v.clusterSize
	} else {
		v.mftRecordSize = 1 << uint(-cpfr)
	}
	if v.mftRecordSize == 0 {
		v.mftRecordSize = mftRecordSize
	}

	// Read MFT record 0 to extract MFT data runs.
	rec0Off := offset + v.mftLCN*v.clusterSize
	rec0 := make([]byte, v.mftRecordSize)
	if _, err := r.ReadAt(rec0, rec0Off); err != nil {
		return nil, fmt.Errorf("ntfs: read MFT record 0: %w", err)
	}
	if err := applyFixup(rec0, int(v.bytesPerSector)); err != nil {
		return nil, fmt.Errorf("ntfs: $MFT fixup: %w", err)
	}
	runs, dataSize, err := extractDataRuns(rec0)
	if err != nil {
		return nil, fmt.Errorf("ntfs: $MFT data runs: %w", err)
	}
	v.mftRuns = runs
	if dataSize == 0 {
		// sum up runs
		for _, run := range runs {
			dataSize += run.length * v.clusterSize
		}
	}
	v.mftSize = dataSize
	return v, nil
}

// WalkTargetFiles iterates every MFT record. For each record whose primary
// $FILE_NAME matches any pattern in patterns (case-insensitive glob), it
// reconstructs the full path and invokes fn with a FileEntry and an
// io.Reader over the file's primary $DATA stream.
//
// fn must consume (or discard) the data reader before returning; the
// underlying buffer is not retained after fn returns.
//
// Pass 1 builds the full parent-name index and collects data runs for matched
// files — no file content is read yet. Pass 2 streams each file's content one
// at a time, keeping peak memory bounded to a single file rather than all
// matched files simultaneously.
func (v *Volume) WalkTargetFiles(patterns []string, fn func(entry FileEntry, data io.Reader) error) error {
	v.index = make(map[uint64]indexEntry, 1<<14)
	if v.mftSize == 0 {
		return fmt.Errorf("ntfs: empty MFT")
	}

	totalRecords := v.mftSize / v.mftRecordSize

	type pending struct {
		recNo            uint64
		name             string
		size             int64
		isDir            bool
		resident         []byte    // non-nil for small resident $DATA
		runs             []dataRun // non-nil for non-resident $DATA; streamed in pass 2
		compressed       bool      // NTFS-compressed (LZNT1)
		compUnitClusters int64     // clusters per compression unit (e.g. 16)
	}
	var pendings []pending
	var statsScanned, statsInUse, statsAttrList, statsMatched int64

	buf := make([]byte, v.mftRecordSize)
	for recNo := int64(0); recNo < totalRecords; recNo++ {
		if err := v.readMFTRecord(recNo, buf); err != nil {
			continue
		}
		if string(buf[0:4]) != "FILE" {
			continue
		}
		statsScanned++
		if err := applyFixup(buf, int(v.bytesPerSector)); err != nil {
			continue
		}
		// Skip extension records (attribute overflow storage; base ref != 0 means this
		// is not an independent file entry — its attributes live in the base record).
		baseRef := binary.LittleEndian.Uint64(buf[32:40]) & 0x0000FFFFFFFFFFFF
		if baseRef != 0 {
			continue
		}
		flags := binary.LittleEndian.Uint16(buf[22:24])
		inUse := flags&0x01 != 0
		isDir := flags&0x02 != 0

		name, parent, _ := primaryFileName(buf)
		if name == "" {
			// Large files store $FILE_NAME in extension records via $ATTRIBUTE_LIST.
			if entries := v.readAttrList(buf); len(entries) > 0 {
				statsAttrList++
				name, parent, _ = v.fileNameFromExtRecs(entries, uint64(recNo))
			}
		}
		if name != "" {
			v.index[uint64(recNo)] = indexEntry{name: name, parent: parent, isDir: isDir}
		}
		if !inUse || name == "" {
			continue
		}
		statsInUse++
		if !matchesAny(name, patterns) {
			continue
		}
		statsMatched++

		// Collect data reference (runs) without reading file content.
		resident, runs, dataSize, hasAttrList, err := v.extractDataRef(buf, uint64(recNo))
		if err != nil {
			log.Printf("ntfs: extractDataRef error for %q (rec %d): %v", name, recNo, err)
			continue
		}
		if hasAttrList {
			entries := v.readAttrList(buf)
			runs, dataSize, _ = v.collectExtDataRuns(entries, uint64(recNo))
		}
		pendings = append(pendings, pending{
			recNo:            uint64(recNo),
			name:             name,
			size:             dataSize,
			isDir:            isDir,
			resident:         resident,
			compressed:       v.lastCompressed,
			compUnitClusters: v.lastCompUnit,
			runs:     runs,
		})
	}

	log.Printf("ntfs: scanned=%d inUse=%d attrList=%d matched=%d pending=%d",
		statsScanned, statsInUse, statsAttrList, statsMatched, int64(len(pendings)))

	for _, p := range pendings {
		fullPath := v.buildPath(p.recNo)
		entry := FileEntry{
			Name:     p.name,
			Path:     fullPath,
			Size:     p.size,
			IsDir:    p.isDir,
			MFTRecNo: p.recNo,
		}
		// Filter $I* matches to $Recycle.Bin path only.
		if strings.HasPrefix(strings.ToLower(p.name), "$i") &&
			!strings.Contains(strings.ToLower(fullPath), "recycle") {
			continue
		}
		var r io.Reader
		if p.resident != nil {
			r = bytes.NewReader(p.resident)
		} else if len(p.runs) > 0 {
			if p.compressed && p.compUnitClusters > 0 {
				r = &compressedRunStreamReader{
					v:           v,
					runs:        p.runs,
					size:        p.size,
					unitBytes:   p.compUnitClusters * v.clusterSize,
				}
			} else {
				r = &runStreamReader{v: v, runs: p.runs, size: p.size}
			}
		} else {
			r = bytes.NewReader(nil)
		}
		if err := fn(entry, r); err != nil {
			return err
		}
	}
	return nil
}

// readMFTRecord reads MFT record number n into buf (buf must be exactly
// mftRecordSize bytes). It maps the logical MFT offset to the underlying
// disk offset via the MFT's own data runs.
func (v *Volume) readMFTRecord(n int64, buf []byte) error {
	logical := n * v.mftRecordSize
	// translate logical offset -> physical disk offset using v.mftRuns
	cluster := logical / v.clusterSize
	within := logical % v.clusterSize

	var seen int64
	for _, run := range v.mftRuns {
		if cluster < seen+run.length {
			if run.lcn < 0 {
				return fmt.Errorf("sparse MFT run")
			}
			physCluster := run.lcn + (cluster - seen)
			physOff := v.partitionStart + physCluster*v.clusterSize + within
			_, err := v.r.ReadAt(buf, physOff)
			return err
		}
		seen += run.length
	}
	return io.EOF
}

// extractData returns the primary unnamed $DATA stream for a fixed-up MFT
// record. For resident data the bytes are returned directly. For non-resident
// data the function reads the data runs from the underlying volume.
// selfRecNo is the MFT record number of rec (used for ATTRIBUTE_LIST loop prevention).
func (v *Volume) extractData(rec []byte, selfRecNo uint64) ([]byte, int64, error) {
	first := binary.LittleEndian.Uint16(rec[20:22])
	off := int(first)

	for off+16 <= len(rec) {
		typeID := binary.LittleEndian.Uint32(rec[off : off+4])
		if typeID == 0xFFFFFFFF {
			break
		}
		length := binary.LittleEndian.Uint32(rec[off+4 : off+8])
		if length == 0 || int(length) > len(rec)-off {
			break
		}
		nonResident := rec[off+8] == 1
		nameLen := int(rec[off+9])
		nameOff := int(binary.LittleEndian.Uint16(rec[off+10:off+12]))

		if typeID == 0x80 && nameLen == 0 {
			if !nonResident {
				if off+24 > len(rec) {
					break
				}
				vlen := binary.LittleEndian.Uint32(rec[off+16 : off+20])
				vof := binary.LittleEndian.Uint16(rec[off+20 : off+22])
				start := off + int(vof)
				end := start + int(vlen)
				if start < 0 || end > len(rec) || start > end {
					break
				}
				out := make([]byte, end-start)
				copy(out, rec[start:end])
				return out, int64(len(out)), nil
			}
			// non-resident
			if off+64 > len(rec) {
				break
			}
			runsOff := int(binary.LittleEndian.Uint16(rec[off+32 : off+34]))
			dataSize := int64(binary.LittleEndian.Uint64(rec[off+48 : off+56]))
			if runsOff < 64 || off+runsOff > off+int(length) {
				break
			}
			runs, err := decodeRuns(rec[off+runsOff : off+int(length)])
			if err != nil {
				return nil, 0, err
			}
			data, err := v.readRuns(runs, dataSize)
			if err != nil {
				return nil, 0, err
			}
			return data, dataSize, nil
		}
		_ = nameOff
		off += int(length)
	}
	// $DATA not found in base record — follow $ATTRIBUTE_LIST to extension records.
	if entries := v.readAttrList(rec); len(entries) > 0 {
		return v.dataFromExtRecs(entries, selfRecNo)
	}
	return nil, 0, nil
}

// readRuns reads dataSize bytes from the volume across the given runs.
func (v *Volume) readRuns(runs []dataRun, dataSize int64) ([]byte, error) {
	if dataSize <= 0 {
		return nil, nil
	}
	// Cap to a sane upper bound (16 GiB) to protect against corrupted runs.
	const maxFile = int64(16) << 30
	if dataSize > maxFile {
		return nil, fmt.Errorf("ntfs: file too large (%d)", dataSize)
	}
	out := make([]byte, dataSize)
	var written int64
	for _, run := range runs {
		if written >= dataSize {
			break
		}
		runBytes := run.length * v.clusterSize
		want := dataSize - written
		if want > runBytes {
			want = runBytes
		}
		if run.lcn < 0 {
			// sparse: zero-fill (already zero)
			written += want
			continue
		}
		physOff := v.partitionStart + run.lcn*v.clusterSize
		if _, err := v.r.ReadAt(out[written:written+want], physOff); err != nil && err != io.EOF {
			return out[:written], err
		}
		written += want
	}
	return out, nil
}

// buildPath walks the parent chain of recNo using v.index, producing a
// slash-separated path rooted at the volume root.
func (v *Volume) buildPath(recNo uint64) string {
	parts := make([]string, 0, 8)
	cur := recNo
	for i := 0; i < 64; i++ {
		entry, ok := v.index[cur]
		if !ok {
			break
		}
		parts = append([]string{entry.name}, parts...)
		if entry.parent == rootRef || entry.parent == cur || entry.parent == 0 {
			break
		}
		cur = entry.parent
	}
	return path.Join(parts...)
}

// extractDataRuns returns the data runs and total data size from MFT record 0.
func extractDataRuns(rec []byte) ([]dataRun, int64, error) {
	first := binary.LittleEndian.Uint16(rec[20:22])
	off := int(first)
	for off+16 <= len(rec) {
		typeID := binary.LittleEndian.Uint32(rec[off : off+4])
		if typeID == 0xFFFFFFFF {
			break
		}
		length := binary.LittleEndian.Uint32(rec[off+4 : off+8])
		if length == 0 || int(length) > len(rec)-off {
			break
		}
		nonResident := rec[off+8] == 1
		nameLen := int(rec[off+9])

		if typeID == 0x80 && nameLen == 0 && nonResident && off+64 <= len(rec) {
			runsOff := int(binary.LittleEndian.Uint16(rec[off+32 : off+34]))
			dataSize := int64(binary.LittleEndian.Uint64(rec[off+48 : off+56]))
			if runsOff >= 64 && off+runsOff <= off+int(length) {
				runs, err := decodeRuns(rec[off+runsOff : off+int(length)])
				if err != nil {
					return nil, 0, err
				}
				return runs, dataSize, nil
			}
		}
		off += int(length)
	}
	return nil, 0, fmt.Errorf("no $DATA non-resident attribute in MFT record")
}

// ReadNamedStream returns the contents of a named $DATA stream (e.g., "J" for
// $UsnJrnl:$J) from the MFT record with the given record number.
// Returns (nil, 0, nil) when the named stream does not exist.
func (v *Volume) ReadNamedStream(recNo uint64, streamName string) ([]byte, int64, error) {
	buf := make([]byte, v.mftRecordSize)
	if err := v.readMFTRecord(int64(recNo), buf); err != nil {
		return nil, 0, err
	}
	if string(buf[0:4]) != "FILE" {
		return nil, 0, fmt.Errorf("ntfs: record %d: not a FILE record", recNo)
	}
	applyFixup(buf, int(v.bytesPerSector)) //nolint:errcheck
	data, size, err := v.extractNamedData(buf, streamName)
	if err != nil || data != nil {
		return data, size, err
	}
	// Fall back to ATTRIBUTE_LIST for large named streams.
	if entries := v.readAttrList(buf); len(entries) > 0 {
		return v.namedDataFromExtRecs(entries, streamName, recNo)
	}
	return nil, 0, nil
}

// extractNamedData returns the contents of a named $DATA stream from a fixed-up
// MFT record. Returns (nil, 0, nil) if the named stream is not in this record.
func (v *Volume) extractNamedData(rec []byte, streamName string) ([]byte, int64, error) {
	first := binary.LittleEndian.Uint16(rec[20:22])
	off := int(first)
	for off+16 <= len(rec) {
		typeID := binary.LittleEndian.Uint32(rec[off : off+4])
		if typeID == 0xFFFFFFFF {
			break
		}
		length := binary.LittleEndian.Uint32(rec[off+4 : off+8])
		if length == 0 || int(length) > len(rec)-off {
			break
		}
		nonResident := rec[off+8] == 1
		nameLen := int(rec[off+9])
		nameOff := int(binary.LittleEndian.Uint16(rec[off+10 : off+12]))

		if typeID == 0x80 && nameLen > 0 {
			nStart := off + nameOff
			nEnd := nStart + nameLen*2
			if nStart >= 0 && nEnd <= len(rec) {
				if strings.EqualFold(decodeUTF16(rec[nStart:nEnd]), streamName) {
					if !nonResident {
						vlen := binary.LittleEndian.Uint32(rec[off+16 : off+20])
						vof := binary.LittleEndian.Uint16(rec[off+20 : off+22])
						start := off + int(vof)
						end := start + int(vlen)
						if start >= 0 && end <= len(rec) {
							out := make([]byte, end-start)
							copy(out, rec[start:end])
							return out, int64(len(out)), nil
						}
					} else if off+64 <= len(rec) {
						runsOff := int(binary.LittleEndian.Uint16(rec[off+32 : off+34]))
						dataSize := int64(binary.LittleEndian.Uint64(rec[off+48 : off+56]))
						if runsOff >= 64 && off+runsOff <= off+int(length) {
							runs, err := decodeRuns(rec[off+runsOff : off+int(length)])
							if err != nil {
								return nil, 0, err
							}
							data, err := v.readRuns(runs, dataSize)
							return data, dataSize, err
						}
					}
				}
			}
		}
		off += int(length)
	}
	return nil, 0, nil
}

// namedDataFromExtRecs assembles a named $DATA stream from extension MFT records.
func (v *Volume) namedDataFromExtRecs(entries []attrListEntry, streamName string, selfRecNo uint64) ([]byte, int64, error) {
	type extSegment struct {
		startVCN int64
		runs     []dataRun
		dataSize int64
	}
	var segments []extSegment
	seen := map[uint64]bool{selfRecNo: true}

	for _, e := range entries {
		if e.typeID != 0x80 || seen[e.mftRef] {
			continue
		}
		seen[e.mftRef] = true
		extBuf := make([]byte, v.mftRecordSize)
		if err := v.readMFTRecord(int64(e.mftRef), extBuf); err != nil {
			continue
		}
		if string(extBuf[0:4]) != "FILE" {
			continue
		}
		applyFixup(extBuf, int(v.bytesPerSector)) //nolint:errcheck

		first := binary.LittleEndian.Uint16(extBuf[20:22])
		off := int(first)
		for off+16 <= len(extBuf) {
			tid := binary.LittleEndian.Uint32(extBuf[off : off+4])
			if tid == 0xFFFFFFFF {
				break
			}
			elen := binary.LittleEndian.Uint32(extBuf[off+4 : off+8])
			if elen == 0 || int(elen) > len(extBuf)-off {
				break
			}
			nameLen := int(extBuf[off+9])
			nameOff := int(binary.LittleEndian.Uint16(extBuf[off+10 : off+12]))
			if tid == 0x80 && nameLen > 0 && extBuf[off+8] == 1 && off+64 <= len(extBuf) {
				nStart := off + nameOff
				nEnd := nStart + nameLen*2
				if nStart >= 0 && nEnd <= len(extBuf) &&
					strings.EqualFold(decodeUTF16(extBuf[nStart:nEnd]), streamName) {
					startVCN := int64(binary.LittleEndian.Uint64(extBuf[off+16 : off+24]))
					dataSize := int64(binary.LittleEndian.Uint64(extBuf[off+56 : off+64]))
					runsOff := int(binary.LittleEndian.Uint16(extBuf[off+32 : off+34]))
					if runsOff >= 64 && off+runsOff <= off+int(elen) {
						if runs, err := decodeRuns(extBuf[off+runsOff : off+int(elen)]); err == nil {
							segments = append(segments, extSegment{startVCN: startVCN, runs: runs, dataSize: dataSize})
						}
					}
				}
			}
			off += int(elen)
		}
	}

	if len(segments) == 0 {
		return nil, 0, nil
	}
	for i := 1; i < len(segments); i++ {
		for j := i; j > 0 && segments[j].startVCN < segments[j-1].startVCN; j-- {
			segments[j], segments[j-1] = segments[j-1], segments[j]
		}
	}
	var allRuns []dataRun
	var totalSize int64
	for _, s := range segments {
		allRuns = append(allRuns, s.runs...)
		if s.startVCN == 0 && s.dataSize > 0 {
			totalSize = s.dataSize
		}
	}
	if totalSize == 0 {
		for _, r := range allRuns {
			if r.lcn >= 0 {
				totalSize += r.length * v.clusterSize
			}
		}
	}
	data, err := v.readRuns(allRuns, totalSize)
	return data, totalSize, err
}

// parseAttrListData parses the raw payload of an $ATTRIBUTE_LIST attribute.
func parseAttrListData(data []byte) []attrListEntry {
	var result []attrListEntry
	i := 0
	for i+26 <= len(data) {
		typeID := binary.LittleEndian.Uint32(data[i : i+4])
		recLen := int(binary.LittleEndian.Uint16(data[i+4 : i+6]))
		startVCN := int64(binary.LittleEndian.Uint64(data[i+8 : i+16]))
		mftRef := binary.LittleEndian.Uint64(data[i+16:i+24]) & 0x0000FFFFFFFFFFFF
		result = append(result, attrListEntry{typeID: typeID, startVCN: startVCN, mftRef: mftRef})
		if recLen < 26 {
			break
		}
		i += recLen
	}
	return result
}

// readAttrList scans rec for $ATTRIBUTE_LIST (0x20) and returns its parsed entries.
// Handles both resident and non-resident attribute lists.
func (v *Volume) readAttrList(rec []byte) []attrListEntry {
	first := binary.LittleEndian.Uint16(rec[20:22])
	off := int(first)
	for off+16 <= len(rec) {
		typeID := binary.LittleEndian.Uint32(rec[off : off+4])
		if typeID == 0xFFFFFFFF {
			break
		}
		length := binary.LittleEndian.Uint32(rec[off+4 : off+8])
		if length == 0 || int(length) > len(rec)-off {
			break
		}
		if typeID == 0x20 {
			nonResident := rec[off+8] == 1
			var data []byte
			if !nonResident {
				vlen := binary.LittleEndian.Uint32(rec[off+16 : off+20])
				vof := binary.LittleEndian.Uint16(rec[off+20 : off+22])
				start := off + int(vof)
				end := start + int(vlen)
				if start >= 0 && end <= len(rec) {
					data = rec[start:end]
				}
			} else if off+64 <= len(rec) {
				runsOff := int(binary.LittleEndian.Uint16(rec[off+32 : off+34]))
				dataSize := int64(binary.LittleEndian.Uint64(rec[off+48 : off+56]))
				if runsOff >= 64 && off+runsOff <= off+int(length) {
					if runs, err := decodeRuns(rec[off+runsOff : off+int(length)]); err == nil {
						data, _ = v.readRuns(runs, dataSize)
					}
				}
			}
			return parseAttrListData(data)
		}
		off += int(length)
	}
	return nil
}

// fileNameFromExtRecs follows $ATTRIBUTE_LIST entries to find $FILE_NAME (0x30)
// in extension MFT records. Used for large files whose $FILE_NAME is not in the
// base MFT record.
func (v *Volume) fileNameFromExtRecs(entries []attrListEntry, selfRecNo uint64) (string, uint64, bool) {
	seen := map[uint64]bool{selfRecNo: true}
	for _, e := range entries {
		if e.typeID != 0x30 || seen[e.mftRef] {
			continue
		}
		seen[e.mftRef] = true
		extBuf := make([]byte, v.mftRecordSize)
		if err := v.readMFTRecord(int64(e.mftRef), extBuf); err != nil {
			continue
		}
		if string(extBuf[0:4]) != "FILE" {
			continue
		}
		applyFixup(extBuf, int(v.bytesPerSector)) //nolint:errcheck
		if name, parent, ok := primaryFileName(extBuf); ok {
			return name, parent, true
		}
	}
	return "", 0, false
}

// dataFromExtRecs collects $DATA (0x80) runs from extension MFT records referenced
// in $ATTRIBUTE_LIST entries, assembles them in VCN order, and returns the data.
func (v *Volume) dataFromExtRecs(entries []attrListEntry, selfRecNo uint64) ([]byte, int64, error) {
	type extSegment struct {
		startVCN int64
		runs     []dataRun
		dataSize int64 // only set on the segment with startVCN == 0
	}
	var segments []extSegment
	seen := map[uint64]bool{selfRecNo: true}

	for _, e := range entries {
		if e.typeID != 0x80 || seen[e.mftRef] {
			continue
		}
		seen[e.mftRef] = true
		extBuf := make([]byte, v.mftRecordSize)
		if err := v.readMFTRecord(int64(e.mftRef), extBuf); err != nil {
			continue
		}
		if string(extBuf[0:4]) != "FILE" {
			continue
		}
		applyFixup(extBuf, int(v.bytesPerSector)) //nolint:errcheck

		first := binary.LittleEndian.Uint16(extBuf[20:22])
		off := int(first)
		for off+16 <= len(extBuf) {
			tid := binary.LittleEndian.Uint32(extBuf[off : off+4])
			if tid == 0xFFFFFFFF {
				break
			}
			elen := binary.LittleEndian.Uint32(extBuf[off+4 : off+8])
			if elen == 0 || int(elen) > len(extBuf)-off {
				break
			}
			nameLen := int(extBuf[off+9])
			if tid == 0x80 && nameLen == 0 && extBuf[off+8] == 1 && off+64 <= len(extBuf) {
				startVCN := int64(binary.LittleEndian.Uint64(extBuf[off+16 : off+24]))
				dataSize := int64(binary.LittleEndian.Uint64(extBuf[off+56 : off+64]))
				runsOff := int(binary.LittleEndian.Uint16(extBuf[off+32 : off+34]))
				if runsOff >= 64 && off+runsOff <= off+int(elen) {
					if runs, err := decodeRuns(extBuf[off+runsOff : off+int(elen)]); err == nil {
						segments = append(segments, extSegment{startVCN: startVCN, runs: runs, dataSize: dataSize})
					}
				}
			}
			off += int(elen)
		}
	}

	if len(segments) == 0 {
		return nil, 0, nil
	}
	// Sort by startVCN (insertion sort; segment count is small).
	for i := 1; i < len(segments); i++ {
		for j := i; j > 0 && segments[j].startVCN < segments[j-1].startVCN; j-- {
			segments[j], segments[j-1] = segments[j-1], segments[j]
		}
	}
	var allRuns []dataRun
	var totalSize int64
	for _, s := range segments {
		allRuns = append(allRuns, s.runs...)
		if s.startVCN == 0 && s.dataSize > 0 {
			totalSize = s.dataSize
		}
	}
	if totalSize == 0 {
		for _, r := range allRuns {
			if r.lcn >= 0 {
				totalSize += r.length * v.clusterSize
			}
		}
	}
	data, err := v.readRuns(allRuns, totalSize)
	return data, totalSize, err
}

// decodeRuns parses NTFS data run encoding. lcn is delta-encoded against the
// previous run's lcn (signed); length is unsigned.
func decodeRuns(b []byte) ([]dataRun, error) {
	var runs []dataRun
	var prevLCN int64
	for i := 0; i < len(b); {
		hdr := b[i]
		if hdr == 0 {
			break
		}
		i++
		lenSize := int(hdr & 0x0F)
		offSize := int((hdr >> 4) & 0x0F)
		if lenSize == 0 || i+lenSize+offSize > len(b) {
			return runs, nil
		}
		length := readUnsigned(b[i : i+lenSize])
		i += lenSize
		var lcn int64
		var sparse bool
		if offSize == 0 {
			sparse = true
		} else {
			delta := readSigned(b[i : i+offSize])
			i += offSize
			lcn = prevLCN + delta
			prevLCN = lcn
		}
		run := dataRun{length: length}
		if sparse {
			run.lcn = -1
		} else {
			run.lcn = lcn
		}
		runs = append(runs, run)
	}
	return runs, nil
}

func readUnsigned(b []byte) int64 {
	var v uint64
	for i := len(b) - 1; i >= 0; i-- {
		v = (v << 8) | uint64(b[i])
	}
	return int64(v)
}

func readSigned(b []byte) int64 {
	if len(b) == 0 {
		return 0
	}
	var v int64
	for i := len(b) - 1; i >= 0; i-- {
		v = (v << 8) | int64(b[i])
	}
	// sign-extend from len(b)*8 bits
	shift := 64 - len(b)*8
	v = (v << uint(shift)) >> uint(shift)
	return v
}

// applyFixup applies the NTFS Update Sequence Array correction to a record.
func applyFixup(rec []byte, sectorSize int) error {
	if len(rec) < 8 {
		return fmt.Errorf("record too short")
	}
	usaOff := int(binary.LittleEndian.Uint16(rec[4:6]))
	usaCount := int(binary.LittleEndian.Uint16(rec[6:8]))
	if usaCount == 0 || usaOff+usaCount*2 > len(rec) {
		return fmt.Errorf("invalid USA")
	}
	usn := rec[usaOff : usaOff+2]
	for i := 1; i < usaCount; i++ {
		sectorEnd := i*sectorSize - 2
		if sectorEnd+2 > len(rec) {
			return nil
		}
		if !bytes.Equal(rec[sectorEnd:sectorEnd+2], usn) {
			// mismatch — skip fixup for this sector but keep going; record may still be usable.
			continue
		}
		repl := rec[usaOff+i*2 : usaOff+i*2+2]
		copy(rec[sectorEnd:sectorEnd+2], repl)
	}
	return nil
}

// primaryFileName returns the best $FILE_NAME (preferring Win32 / POSIX over
// DOS-only namespaces) along with the parent reference.
func primaryFileName(rec []byte) (string, uint64, bool) {
	first := binary.LittleEndian.Uint16(rec[20:22])
	off := int(first)
	var bestName string
	var bestParent uint64
	var bestNS uint8 = 255
	found := false

	for off+16 <= len(rec) {
		typeID := binary.LittleEndian.Uint32(rec[off : off+4])
		if typeID == 0xFFFFFFFF {
			break
		}
		length := binary.LittleEndian.Uint32(rec[off+4 : off+8])
		if length == 0 || int(length) > len(rec)-off {
			break
		}
		nonResident := rec[off+8] == 1
		if typeID == 0x30 && !nonResident {
			vlen := binary.LittleEndian.Uint32(rec[off+16 : off+20])
			vof := binary.LittleEndian.Uint16(rec[off+20 : off+22])
			start := off + int(vof)
			end := start + int(vlen)
			if start >= 0 && end <= len(rec) && end-start >= 66 {
				val := rec[start:end]
				parent := binary.LittleEndian.Uint64(val[0:8]) & 0x0000FFFFFFFFFFFF
				nameLen := int(val[64])
				ns := val[65]
				nameBytes := val[66:]
				if 2*nameLen <= len(nameBytes) {
					name := decodeUTF16(nameBytes[:2*nameLen])
					// prefer Win32(1) / Win32&DOS(3) / POSIX(0) over DOS(2)
					rank := nsRank(ns)
					if !found || rank < nsRank(bestNS) {
						bestName = name
						bestParent = parent
						bestNS = ns
						found = true
					}
				}
			}
		}
		off += int(length)
	}
	return bestName, bestParent, found
}

func nsRank(ns uint8) uint8 {
	// lower is better
	switch ns {
	case 1, 3: // Win32, Win32&DOS
		return 0
	case 0: // POSIX
		return 1
	case 2: // DOS-only
		return 3
	default:
		return 2
	}
}

func decodeUTF16(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[i*2 : i*2+2])
	}
	return string(utf16.Decode(u))
}

// matchesAny reports whether name matches any pattern (case-insensitive,
// supports leading "*." suffix wildcards and the "$I*" prefix wildcard).
func matchesAny(name string, patterns []string) bool {
	lower := strings.ToLower(name)
	for _, pat := range patterns {
		p := strings.ToLower(pat)
		if matchOne(lower, p) {
			return true
		}
	}
	return false
}

func matchOne(name, pat string) bool {
	switch {
	case pat == name:
		return true
	case strings.HasPrefix(pat, "*.") && strings.HasSuffix(name, pat[1:]):
		return true
	case strings.HasSuffix(pat, "*") && !strings.Contains(pat[:len(pat)-1], "*"):
		return strings.HasPrefix(name, pat[:len(pat)-1])
	case strings.HasPrefix(pat, "*") && !strings.Contains(pat[1:], "*"):
		return strings.HasSuffix(name, pat[1:])
	}
	return false
}

// runStreamReader implements io.Reader over NTFS data runs without buffering
// the entire file in memory. Each Read call issues at most one ReadAt against
// the underlying volume.
type runStreamReader struct {
	v    *Volume
	runs []dataRun
	size int64
	pos  int64
}

func (r *runStreamReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if r.pos >= r.size {
		return 0, io.EOF
	}
	want := int64(len(p))
	if r.pos+want > r.size {
		want = r.size - r.pos
	}
	n, err := r.readAt(p[:want], r.pos)
	r.pos += int64(n)
	if err == nil && n == 0 {
		return 0, io.EOF
	}
	return n, err
}

func (r *runStreamReader) readAt(p []byte, off int64) (int, error) {
	var runStart int64
	for _, run := range r.runs {
		runBytes := run.length * r.v.clusterSize
		if off < runStart+runBytes {
			within := off - runStart
			canRead := runBytes - within
			if int64(len(p)) < canRead {
				canRead = int64(len(p))
			}
			if run.lcn < 0 {
				for i := int64(0); i < canRead; i++ {
					p[i] = 0
				}
				return int(canRead), nil
			}
			physOff := r.v.partitionStart + run.lcn*r.v.clusterSize + within
			return r.v.r.ReadAt(p[:canRead], physOff)
		}
		runStart += runBytes
	}
	return 0, io.EOF
}

// extractDataRef extracts the $DATA attribute reference from a fixed-up MFT
// record without reading file content. For resident data it copies the bytes
// (always small). For non-resident data it returns the decoded data runs.
// hasAttrList is true when $DATA lives in extension records referenced by
// $ATTRIBUTE_LIST; the caller should then use collectExtDataRuns.
func (v *Volume) extractDataRef(rec []byte, selfRecNo uint64) (resident []byte, runs []dataRun, dataSize int64, hasAttrList bool, err error) {
	// Pass 1: read FILE_ATTRIBUTE_COMPRESSED from STANDARD_INFORMATION so the
	// flag is set even for files whose $DATA lives in extension records (e.g.
	// huge SOFTWARE/SYSTEM hives that overflow into $ATTRIBUTE_LIST).
	stdCompressed := false
	{
		first := binary.LittleEndian.Uint16(rec[20:22])
		so := int(first)
		for so+16 <= len(rec) {
			tid := binary.LittleEndian.Uint32(rec[so : so+4])
			if tid == 0xFFFFFFFF {
				break
			}
			alen := binary.LittleEndian.Uint32(rec[so+4 : so+8])
			if alen == 0 || int(alen) > len(rec)-so {
				break
			}
			if tid == 0x10 && rec[so+8] == 0 && so+72 <= len(rec) {
				vof := binary.LittleEndian.Uint16(rec[so+20 : so+22])
				stdOff := so + int(vof)
				if stdOff+36 <= len(rec) {
					fileAttrs := binary.LittleEndian.Uint32(rec[stdOff+32 : stdOff+36])
					if fileAttrs&0x00000800 != 0 { // FILE_ATTRIBUTE_COMPRESSED
						stdCompressed = true
					}
				}
				break
			}
			so += int(alen)
		}
	}

	first := binary.LittleEndian.Uint16(rec[20:22])
	off := int(first)
	for off+16 <= len(rec) {
		typeID := binary.LittleEndian.Uint32(rec[off : off+4])
		if typeID == 0xFFFFFFFF {
			break
		}
		length := binary.LittleEndian.Uint32(rec[off+4 : off+8])
		if length == 0 || int(length) > len(rec)-off {
			break
		}
		nonResident := rec[off+8] == 1
		nameLen := int(rec[off+9])

		if typeID == 0x80 && nameLen == 0 {
			if !nonResident {
				if off+24 > len(rec) {
					break
				}
				vlen := binary.LittleEndian.Uint32(rec[off+16 : off+20])
				vof := binary.LittleEndian.Uint16(rec[off+20 : off+22])
				start := off + int(vof)
				end := start + int(vlen)
				if start < 0 || end > len(rec) || start > end {
					break
				}
				out := make([]byte, end-start)
				copy(out, rec[start:end])
				return out, nil, int64(len(out)), false, nil
			}
			if off+64 > len(rec) {
				break
			}
			attrFlags := binary.LittleEndian.Uint16(rec[off+12 : off+14])
			compressed := attrFlags&0x0001 != 0
			compUnitLog2 := uint16(rec[off+34]) // CompressionUnit field
			runsOff := int(binary.LittleEndian.Uint16(rec[off+32 : off+34]))
			size := int64(binary.LittleEndian.Uint64(rec[off+48 : off+56]))
			if runsOff < 64 || off+runsOff > off+int(length) {
				break
			}
			dr, decErr := decodeRuns(rec[off+runsOff : off+int(length)])
			if decErr != nil {
				return nil, nil, 0, false, decErr
			}
			if compressed && compUnitLog2 > 0 {
				v.lastCompUnit = int64(1) << compUnitLog2
				v.lastCompressed = true
			} else {
				v.lastCompUnit = 0
				v.lastCompressed = false
			}
			return nil, dr, size, false, nil
		}
		off += int(length)
	}
	v.lastCompUnit = 0
	v.lastCompressed = false
	if entries := v.readAttrList(rec); len(entries) > 0 {
		// $DATA is in extension records; carry compression hint from STANDARD_INFO.
		if stdCompressed {
			v.lastCompressed = true
			v.lastCompUnit = 16 // default compression unit (2^4 clusters)
		}
		return nil, nil, 0, true, nil
	}
	return nil, nil, 0, false, nil
}

// collectExtDataRuns collects $DATA runs from extension MFT records listed in
// $ATTRIBUTE_LIST entries, returning them in VCN order. Unlike dataFromExtRecs
// it does not read file content — the caller streams data via runStreamReader.
func (v *Volume) collectExtDataRuns(entries []attrListEntry, selfRecNo uint64) ([]dataRun, int64, error) {
	type extSegment struct {
		startVCN int64
		runs     []dataRun
		dataSize int64
	}
	var segments []extSegment
	seen := map[uint64]bool{selfRecNo: true}

	for _, e := range entries {
		if e.typeID != 0x80 || seen[e.mftRef] {
			continue
		}
		seen[e.mftRef] = true
		extBuf := make([]byte, v.mftRecordSize)
		if err := v.readMFTRecord(int64(e.mftRef), extBuf); err != nil {
			continue
		}
		if string(extBuf[0:4]) != "FILE" {
			continue
		}
		applyFixup(extBuf, int(v.bytesPerSector)) //nolint:errcheck

		first := binary.LittleEndian.Uint16(extBuf[20:22])
		off := int(first)
		for off+16 <= len(extBuf) {
			tid := binary.LittleEndian.Uint32(extBuf[off : off+4])
			if tid == 0xFFFFFFFF {
				break
			}
			elen := binary.LittleEndian.Uint32(extBuf[off+4 : off+8])
			if elen == 0 || int(elen) > len(extBuf)-off {
				break
			}
			nameLen := int(extBuf[off+9])
			if tid == 0x80 && nameLen == 0 && extBuf[off+8] == 1 && off+64 <= len(extBuf) {
				startVCN := int64(binary.LittleEndian.Uint64(extBuf[off+16 : off+24]))
				dataSize := int64(binary.LittleEndian.Uint64(extBuf[off+56 : off+64]))
				runsOff := int(binary.LittleEndian.Uint16(extBuf[off+32 : off+34]))
				if runsOff >= 64 && off+runsOff <= off+int(elen) {
					if dr, dErr := decodeRuns(extBuf[off+runsOff : off+int(elen)]); dErr == nil {
						segments = append(segments, extSegment{startVCN: startVCN, runs: dr, dataSize: dataSize})
					}
				}
			}
			off += int(elen)
		}
	}

	if len(segments) == 0 {
		return nil, 0, nil
	}
	for i := 1; i < len(segments); i++ {
		for j := i; j > 0 && segments[j].startVCN < segments[j-1].startVCN; j-- {
			segments[j], segments[j-1] = segments[j-1], segments[j]
		}
	}
	var allRuns []dataRun
	var totalSize int64
	for _, s := range segments {
		allRuns = append(allRuns, s.runs...)
		if s.startVCN == 0 && s.dataSize > 0 {
			totalSize = s.dataSize
		}
	}
	if totalSize == 0 {
		for _, run := range allRuns {
			if run.lcn >= 0 {
				totalSize += run.length * v.clusterSize
			}
		}
	}
	return allRuns, totalSize, nil
}
