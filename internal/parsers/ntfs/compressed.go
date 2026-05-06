// Compressed-data reader for NTFS files with FILE_ATTRIBUTE_COMPRESSED.
//
// NTFS compresses files in fixed-size compression units (typically 16 clusters
// = 64 KiB). The runs of a compressed $DATA stream cover one unit at a time.
// Within each unit some clusters hold actual compressed bytes followed by one
// or more sparse runs that pad the unit to its full logical size. To
// reconstruct the original file we read the non-sparse bytes of each unit and
// pass them through LZNT1Decompress.

package ntfs

import (
	"fmt"
	"io"
)

type compressedRunStreamReader struct {
	v         *Volume
	runs      []dataRun
	size      int64 // logical (decompressed) file size
	unitBytes int64 // compression unit size in bytes (e.g. 65536)
	pos       int64 // logical read position

	cachedUnit int64 // compression-unit index of cachedData; -1 = none
	cachedData []byte
}

func (r *compressedRunStreamReader) Read(p []byte) (int, error) {
	if r.pos >= r.size {
		return 0, io.EOF
	}
	if len(p) == 0 {
		return 0, nil
	}
	unitIdx := r.pos / r.unitBytes
	unitOff := r.pos - unitIdx*r.unitBytes
	if r.cachedUnit != unitIdx || r.cachedData == nil {
		data, err := r.loadUnit(unitIdx)
		if err != nil && len(data) == 0 {
			return 0, err
		}
		r.cachedUnit = unitIdx
		r.cachedData = data
	}
	if int64(len(r.cachedData)) <= unitOff {
		// short unit (file ends mid-unit) — nothing left
		r.pos = r.size
		return 0, io.EOF
	}
	avail := int64(len(r.cachedData)) - unitOff
	if avail > r.size-r.pos {
		avail = r.size - r.pos
	}
	if avail > int64(len(p)) {
		avail = int64(len(p))
	}
	n := copy(p, r.cachedData[unitOff:unitOff+avail])
	r.pos += int64(n)
	return n, nil
}

// loadUnit reads the raw on-disk bytes for one compression unit and returns
// the decompressed bytes. If the unit is fully populated by data runs (no
// sparse padding) the bytes are stored uncompressed and returned verbatim.
func (r *compressedRunStreamReader) loadUnit(unitIdx int64) ([]byte, error) {
	unitClusters := r.unitBytes / r.v.clusterSize
	startVCN := unitIdx * unitClusters
	endVCN := startVCN + unitClusters

	rawBuf := make([]byte, 0, r.unitBytes)
	hasSparse := false
	var vcn int64
	for _, run := range r.runs {
		runEnd := vcn + run.length
		if runEnd <= startVCN {
			vcn = runEnd
			continue
		}
		if vcn >= endVCN {
			break
		}
		overlapStart := vcn
		if overlapStart < startVCN {
			overlapStart = startVCN
		}
		overlapEnd := runEnd
		if overlapEnd > endVCN {
			overlapEnd = endVCN
		}
		overlapClusters := overlapEnd - overlapStart
		overlapBytes := overlapClusters * r.v.clusterSize
		if run.lcn < 0 {
			hasSparse = true
		} else {
			withinRun := overlapStart - vcn
			physOff := r.v.partitionStart + (run.lcn+withinRun)*r.v.clusterSize
			tmp := make([]byte, overlapBytes)
			n, err := r.v.r.ReadAt(tmp, physOff)
			if err != nil && err != io.EOF {
				return nil, fmt.Errorf("ntfs: read compressed unit %d: %w", unitIdx, err)
			}
			rawBuf = append(rawBuf, tmp[:n]...)
		}
		vcn = runEnd
	}
	if len(rawBuf) == 0 {
		// fully sparse unit — return zero-filled unit
		out := make([]byte, r.unitBytes)
		return out, nil
	}
	if !hasSparse {
		// No sparse padding ⇒ unit is stored uncompressed (NTFS only writes the
		// raw bytes when the data didn't compress, OR this is the partial trailing
		// unit at the end of the file). Return what we read verbatim.
		if int64(len(rawBuf)) > r.unitBytes {
			return rawBuf[:r.unitBytes], nil
		}
		return rawBuf, nil
	}
	// Has sparse padding ⇒ NTFS compressed unit; decompress with LZNT1.
	out, err := LZNT1Decompress(rawBuf)
	if err != nil {
		return out, fmt.Errorf("ntfs: lznt1 unit %d: %w", unitIdx, err)
	}
	return out, nil
}
