package vmdk

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

const (
	vmdkMagic  = 0x564d444b
	sectorSize = 512
	gtCacheMax = 512

	markerEOS    = 1
	markerGT     = 2
	markerGD     = 3
	markerFooter = 4
)

type sparseHeader struct {
	Magic              uint32
	Version            uint32
	Flags              uint32
	Capacity           uint64
	GrainSize          uint64
	DescriptorOffset   uint64
	DescriptorSize     uint64
	NumGTEsPerGT       uint32
	RgdOffset          uint64
	GdOffset           uint64
	OverHead           uint64
	UncleanShutdown    uint8
	SingleEndLineChar  uint8
	NonEndLineChar     uint8
	DoubleEndLineChar1 uint8
	DoubleEndLineChar2 uint8
	CompressAlgorithm  uint16
	_                  [433]byte
}

type streamEntry struct {
	offset int64  // byte offset of compressed data in file
	size   uint32 // compressed size in bytes
}

// Disk is an open VMDK image (monolithic-sparse or stream-optimized).
type Disk struct {
	f          *os.File
	size       int64
	grainBytes int64

	// monolithic-sparse
	numGTEs uint32
	gd      []uint32
	gtCache map[uint32][]uint32

	// stream-optimized (non-nil when CompressAlgorithm != 0)
	streamIndex map[uint64]streamEntry // grain LBA → compressed location
	grainCache  map[uint64][]byte      // grain LBA → decompressed data
}

// Open opens a VMDK image at path. Both monolithic-sparse (uncompressed) and
// stream-optimized (zlib-compressed, produced by ESXi/OVA export) are supported.
func Open(path string) (*Disk, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	var hdr sparseHeader
	if err := binary.Read(f, binary.LittleEndian, &hdr); err != nil {
		f.Close()
		return nil, fmt.Errorf("read vmdk header: %w", err)
	}

	if hdr.Magic != vmdkMagic {
		var first [1]byte
		f.ReadAt(first[:], 0)
		f.Close()
		if first[0] == '#' {
			return nil, fmt.Errorf("descriptor-only VMDK — provide the -flat.vmdk data file instead")
		}
		return nil, fmt.Errorf("not a VMDK sparse image")
	}

	if hdr.GrainSize == 0 {
		hdr.GrainSize = 128
	}

	grainBytes := int64(hdr.GrainSize) * sectorSize
	size := int64(hdr.Capacity) * sectorSize

	d := &Disk{
		f:          f,
		size:       size,
		grainBytes: grainBytes,
	}

	if hdr.CompressAlgorithm != 0 {
		d.streamIndex = make(map[uint64]streamEntry)
		d.grainCache = make(map[uint64][]byte)
		startOff := int64(hdr.OverHead) * sectorSize
		if startOff < sectorSize {
			startOff = sectorSize
		}
		if err := d.buildStreamIndex(startOff); err != nil {
			f.Close()
			return nil, fmt.Errorf("vmdk stream index: %w", err)
		}
		return d, nil
	}

	// Monolithic-sparse: load grain directory eagerly.
	d.numGTEs = hdr.NumGTEsPerGT
	if d.numGTEs == 0 {
		d.numGTEs = 512
	}
	d.gtCache = make(map[uint32][]uint32)

	numGrains := (hdr.Capacity + hdr.GrainSize - 1) / hdr.GrainSize
	numGDEntries := (numGrains + uint64(d.numGTEs) - 1) / uint64(d.numGTEs)
	gdBuf := make([]byte, numGDEntries*4)
	if _, err := f.ReadAt(gdBuf, int64(hdr.GdOffset)*sectorSize); err != nil && err != io.EOF {
		f.Close()
		return nil, fmt.Errorf("read grain directory: %w", err)
	}
	d.gd = make([]uint32, numGDEntries)
	for i := range d.gd {
		d.gd[i] = binary.LittleEndian.Uint32(gdBuf[i*4 : i*4+4])
	}
	return d, nil
}

// Size returns the virtual disk size in bytes.
func (d *Disk) Size() int64 { return d.size }

// Close closes the underlying file.
func (d *Disk) Close() error { return d.f.Close() }

// ReadAt implements io.ReaderAt.
func (d *Disk) ReadAt(p []byte, off int64) (int, error) {
	if off >= d.size {
		return 0, io.EOF
	}
	if off+int64(len(p)) > d.size {
		p = p[:d.size-off]
	}
	if d.streamIndex != nil {
		return d.readStreamAt(p, off)
	}
	return d.readSparseAt(p, off)
}

// ── monolithic-sparse ──────────────────────────────────────────────────────

func (d *Disk) readSparseAt(p []byte, off int64) (int, error) {
	total := 0
	for len(p) > 0 {
		grainIdx := uint64(off) / uint64(d.grainBytes)
		inGrain := off % d.grainBytes
		gdIdx := uint32(grainIdx / uint64(d.numGTEs))
		gtIdx := uint32(grainIdx % uint64(d.numGTEs))

		want := d.grainBytes - inGrain
		if want > int64(len(p)) {
			want = int64(len(p))
		}

		if gdIdx >= uint32(len(d.gd)) || d.gd[gdIdx] == 0 {
			clearSlice(p[:want])
			p, off, total = p[want:], off+want, total+int(want)
			continue
		}

		gt, err := d.loadGT(d.gd[gdIdx])
		if err != nil {
			return total, err
		}

		if gtIdx >= uint32(len(gt)) || gt[gtIdx] <= 1 {
			clearSlice(p[:want])
			p, off, total = p[want:], off+want, total+int(want)
			continue
		}

		n, err := d.f.ReadAt(p[:want], int64(gt[gtIdx])*sectorSize+inGrain)
		total += n
		p = p[n:]
		off += int64(n)
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func (d *Disk) loadGT(gdEntry uint32) ([]uint32, error) {
	if gt, ok := d.gtCache[gdEntry]; ok {
		return gt, nil
	}
	if len(d.gtCache) > gtCacheMax {
		d.gtCache = make(map[uint32][]uint32)
	}
	buf := make([]byte, d.numGTEs*4)
	if _, err := d.f.ReadAt(buf, int64(gdEntry)*sectorSize); err != nil && err != io.EOF {
		return nil, fmt.Errorf("read grain table: %w", err)
	}
	gt := make([]uint32, d.numGTEs)
	for i := range gt {
		gt[i] = binary.LittleEndian.Uint32(buf[i*4 : i*4+4])
	}
	d.gtCache[gdEntry] = gt
	return gt, nil
}

// ── stream-optimized ───────────────────────────────────────────────────────

// buildStreamIndex scans the file linearly from startOff and records the
// compressed location of every data grain.
func (d *Disk) buildStreamIndex(startOff int64) error {
	var hdr [13]byte // 8 (lba) + 4 (size) + 1 (type)
	pos := startOff
	for {
		n, err := d.f.ReadAt(hdr[:], pos)
		if n < 12 {
			break
		}
		lba := binary.LittleEndian.Uint64(hdr[0:8])
		size := binary.LittleEndian.Uint32(hdr[8:12])

		if size == 0 {
			typ := hdr[12]
			switch typ {
			case markerEOS, markerFooter:
				return nil
			}
			// lba field holds the number of following metadata sectors
			pos += sectorSize + int64(lba)*sectorSize
		} else {
			d.streamIndex[lba] = streamEntry{offset: pos + 12, size: size}
			total := int64(12 + size)
			pos += (total + sectorSize - 1) / sectorSize * sectorSize
		}
		if err != nil {
			break
		}
	}
	return nil
}

func (d *Disk) readStreamAt(p []byte, off int64) (int, error) {
	total := 0
	grainSectors := uint64(d.grainBytes / sectorSize)
	for len(p) > 0 {
		grainIdx := uint64(off) / uint64(d.grainBytes)
		inGrain := off % d.grainBytes
		grainLBA := grainIdx * grainSectors

		want := d.grainBytes - inGrain
		if want > int64(len(p)) {
			want = int64(len(p))
		}

		grain, err := d.readStreamGrain(grainLBA)
		if err != nil {
			return total, err
		}

		if grain == nil {
			clearSlice(p[:want])
		} else {
			end := inGrain + want
			if end > int64(len(grain)) {
				end = int64(len(grain))
			}
			n := copy(p[:want], grain[inGrain:end])
			clearSlice(p[n:want])
		}

		p, off, total = p[want:], off+want, total+int(want)
	}
	return total, nil
}

func (d *Disk) readStreamGrain(lba uint64) ([]byte, error) {
	if data, ok := d.grainCache[lba]; ok {
		return data, nil
	}
	entry, ok := d.streamIndex[lba]
	if !ok {
		return nil, nil
	}
	comp := make([]byte, entry.size)
	if _, err := d.f.ReadAt(comp, entry.offset); err != nil {
		return nil, fmt.Errorf("read compressed grain lba=%d: %w", lba, err)
	}
	zr, err := zlib.NewReader(bytes.NewReader(comp))
	if err != nil {
		return nil, fmt.Errorf("zlib open lba=%d: %w", lba, err)
	}
	data, err := io.ReadAll(zr)
	zr.Close()
	if err != nil {
		return nil, fmt.Errorf("zlib decompress lba=%d: %w", lba, err)
	}
	if len(d.grainCache) > 256 {
		d.grainCache = make(map[uint64][]byte)
	}
	d.grainCache[lba] = data
	return data, nil
}

func clearSlice(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
