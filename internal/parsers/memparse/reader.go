package memparse

import (
	"io"
)

// physToFile maps a physical address to a file offset, or returns false if the
// address is not present in any of the dump's memory runs.
func (d *Dump) physToFile(pa uint64) (int64, bool) {
	page := pa / pageSize
	pageOff := pa % pageSize
	for _, r := range d.runs {
		if page >= r.BasePage && page < r.BasePage+r.PageCount {
			off := int64(r.FileStart) + int64(page-r.BasePage)*pageSize + int64(pageOff)
			return off, true
		}
	}
	return 0, false
}

// ReadPhys reads up to n bytes starting at physical address pa.
// On any failure (out-of-range address, short read, IO error) it returns nil
// — callers must always test the returned slice's length, never panic on it.
// Reads that span multiple memory runs are handled here by chunked copies.
func (d *Dump) ReadPhys(pa uint64, n int) []byte {
	if d == nil || d.f == nil || n <= 0 {
		return nil
	}
	if n > 1<<24 { // hard cap: 16 MB single read
		n = 1 << 24
	}
	out := make([]byte, 0, n)
	cur := pa
	remaining := n
	for remaining > 0 {
		off, ok := d.physToFile(cur)
		if !ok {
			break
		}
		// How many bytes are available contiguously starting at this address
		// within the current run?
		page := cur / pageSize
		var run *physRun
		for i := range d.runs {
			r := &d.runs[i]
			if page >= r.BasePage && page < r.BasePage+r.PageCount {
				run = r
				break
			}
		}
		if run == nil {
			break
		}
		runEnd := (run.BasePage + run.PageCount) * pageSize
		chunk := remaining
		if uint64(chunk) > runEnd-cur {
			chunk = int(runEnd - cur)
		}
		if chunk <= 0 {
			break
		}
		buf := make([]byte, chunk)
		read, err := d.f.ReadAt(buf, off)
		if read > 0 {
			out = append(out, buf[:read]...)
		}
		if err != nil && err != io.EOF {
			break
		}
		if read < chunk {
			break
		}
		cur += uint64(chunk)
		remaining -= chunk
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
