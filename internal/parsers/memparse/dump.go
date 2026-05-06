package memparse

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

// Dump format signatures.
const (
	sigPAGE = 0x45474150 // "PAGE"
	sigDU64 = 0x34365544 // "DU64"
	sigDUMP = 0x504D5544 // "DUMP" (32-bit)
	hdrSize = 0x2000     // PAGEDUMP64 header size
	pageSize = 0x1000
	descOffset = 0x088  // Physical memory descriptor (PHYSICAL_MEMORY_DESCRIPTOR) embedded in DUMP_HEADER64 at +0x88
	maxRuns = 1024      // sanity cap
)

// physRun describes a contiguous range of physical pages packed into the dump file.
type physRun struct {
	BasePage  uint64 // physical page number where this run starts
	PageCount uint64 // number of pages in this run
	FileStart uint64 // file offset where this run's data starts
}

// Dump represents an opened Windows memory dump (or raw image) ready for physical reads.
type Dump struct {
	f *os.File
	size int64

	IsPageDump bool

	MajorVersion        uint32
	MinorVersion        uint32 // Windows build number
	SystemCR3           uint64 // DirectoryTableBase for kernel/System
	PfnDataBase         uint64
	PsLoadedModuleList  uint64 // virtual address
	PsActiveProcessHead uint64 // virtual address
	MachineImageType    uint32
	NumberProcessors    uint32
	KdDebuggerDataBlock uint64

	runs []physRun
}

// openDump opens a memory dump file and parses the header if present.
// If the file isn't a recognised dump format, it's treated as a raw physical image
// where physical address == file offset.
func openDump(path string) (*Dump, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open dump: %w", err)
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("stat dump: %w", err)
	}
	d := &Dump{f: f, size: st.Size()}

	// Read the first 0x2000 bytes to inspect for a PAGEDUMP64 header.
	hdr := make([]byte, hdrSize)
	n, _ := io.ReadFull(f, hdr)
	if n < 0x100 {
		f.Close()
		return nil, fmt.Errorf("dump too small: %d bytes", n)
	}

	sig := binary.LittleEndian.Uint32(hdr[0x00:0x04])
	val := binary.LittleEndian.Uint32(hdr[0x04:0x08])

	if sig == sigPAGE && val == sigDU64 {
		// PAGEDUMP64
		if err := d.parsePageDump64(hdr); err != nil {
			f.Close()
			return nil, fmt.Errorf("parse PAGEDUMP64: %w", err)
		}
		d.IsPageDump = true
		return d, nil
	}

	// Raw fallback: treat the entire file as a contiguous physical image.
	d.IsPageDump = false
	d.runs = []physRun{{BasePage: 0, PageCount: uint64(d.size) / pageSize, FileStart: 0}}
	return d, nil
}

func (d *Dump) parsePageDump64(hdr []byte) error {
	d.MajorVersion = binary.LittleEndian.Uint32(hdr[0x008:0x00C])
	d.MinorVersion = binary.LittleEndian.Uint32(hdr[0x00C:0x010])
	d.SystemCR3 = binary.LittleEndian.Uint64(hdr[0x010:0x018])
	d.PfnDataBase = binary.LittleEndian.Uint64(hdr[0x018:0x020])
	d.PsLoadedModuleList = binary.LittleEndian.Uint64(hdr[0x020:0x028])
	d.PsActiveProcessHead = binary.LittleEndian.Uint64(hdr[0x028:0x030])
	d.MachineImageType = binary.LittleEndian.Uint32(hdr[0x030:0x034])
	d.NumberProcessors = binary.LittleEndian.Uint32(hdr[0x034:0x038])
	if len(hdr) >= 0x88 {
		d.KdDebuggerDataBlock = binary.LittleEndian.Uint64(hdr[0x080:0x088])
	}

	if d.SystemCR3 == 0 {
		return fmt.Errorf("invalid SystemCR3 (0)")
	}
	if d.MachineImageType != 0 && d.MachineImageType != 0x8664 {
		return fmt.Errorf("unsupported machine 0x%x (only x64 supported)", d.MachineImageType)
	}

	// Physical memory descriptor at 0x1000
	if len(hdr) < descOffset+16 {
		return fmt.Errorf("header too short for descriptor")
	}
	desc := hdr[descOffset:]
	numRuns := binary.LittleEndian.Uint32(desc[0:4])
	// 4 bytes padding
	numPages := binary.LittleEndian.Uint64(desc[8:16])
	if numRuns == 0 || numRuns > maxRuns {
		return fmt.Errorf("bad run count: %d", numRuns)
	}

	runs := make([]physRun, 0, numRuns)
	off := uint64(16)
	fileCursor := uint64(hdrSize)
	totalPages := uint64(0)
	for i := uint32(0); i < numRuns; i++ {
		if off+16 > uint64(len(desc)) {
			return fmt.Errorf("descriptor truncated at run %d", i)
		}
		base := binary.LittleEndian.Uint64(desc[off : off+8])
		count := binary.LittleEndian.Uint64(desc[off+8 : off+16])
		off += 16
		if count == 0 {
			continue
		}
		runs = append(runs, physRun{
			BasePage:  base,
			PageCount: count,
			FileStart: fileCursor,
		})
		fileCursor += count * pageSize
		totalPages += count
	}
	if len(runs) == 0 {
		return fmt.Errorf("no valid runs in descriptor")
	}
	if totalPages != numPages {
		// Not fatal — just informational; some dumps have rounding.
		_ = numPages
	}
	d.runs = runs
	return nil
}

// Close releases the underlying file handle.
func (d *Dump) Close() error {
	if d == nil || d.f == nil {
		return nil
	}
	return d.f.Close()
}
