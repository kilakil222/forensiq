package memparse

import (
	"bytes"
	"encoding/binary"
	"time"
	"unicode/utf16"
)

// ProcessInfo is the in-memory snapshot of one EPROCESS instance.
type ProcessInfo struct {
	PID, PPID uint64
	Name      string
	CreateTS  time.Time
	ExitTS    time.Time
	CR3       uint64
	PEBAddr   uint64
	CmdLine   string
	ImagePath string
	EProcBase uint64
	StalePool bool // CR3 validation failed — freed EPROCESS block, not genuine DKOM
}

// vreadFn reads n bytes at virtual address va in the address space identified by cr3.
type vreadFn func(cr3, va uint64, n int) []byte

// filetimeToTime converts a Windows FILETIME (100ns ticks since 1601-01-01 UTC)
// to a Go time.Time. Returns the zero time on out-of-range values.
func filetimeToTime(ft uint64) time.Time {
	if ft == 0 {
		return time.Time{}
	}
	const epochDiff = 116444736000000000
	if ft < epochDiff {
		return time.Time{}
	}
	ns := (ft - epochDiff) * 100
	t := time.Unix(0, int64(ns)).UTC()
	if t.Year() < 1970 || t.Year() > 9999 {
		return time.Time{}
	}
	return t
}

// readEPROC parses one EPROCESS at virtual address eprocBase.
// Returns nil if minimum sanity checks fail.
func readEPROC(cr3sys, eprocBase uint64, p *WinProfile, vread vreadFn) *ProcessInfo {
	// Read up to ~0x600 bytes — enough to span PEB pointer + ImageFileName.
	const eprocSlab = 0x600
	buf := vread(cr3sys, eprocBase, eprocSlab)
	if len(buf) < 0x320 {
		return nil
	}
	get8 := func(off int) uint64 {
		if off+8 > len(buf) {
			return 0
		}
		return binary.LittleEndian.Uint64(buf[off : off+8])
	}
	getName := func(off int) string {
		if off+15 > len(buf) {
			return ""
		}
		raw := buf[off : off+15]
		// Trim at first NUL or non-printable.
		end := 0
		for end < len(raw) && raw[end] >= 0x20 && raw[end] < 0x7F {
			end++
		}
		return string(raw[:end])
	}
	pi := &ProcessInfo{EProcBase: eprocBase}
	pi.CR3 = get8(p.EProcDTB)
	pi.PID = get8(p.EProcPID)
	pi.PPID = get8(p.EProcPPID)
	pi.PEBAddr = get8(p.EProcPEB)
	pi.CreateTS = filetimeToTime(get8(p.EProcCreate))
	if p.EProcExitTime != 0 {
		pi.ExitTS = filetimeToTime(get8(p.EProcExitTime))
	}
	pi.Name = getName(p.EProcName)

	// Sanity gate: PID < 2^20, name printable.
	if pi.PID == 0 && pi.Name == "" {
		return nil
	}
	if pi.PID > 0xFFFFF {
		return nil
	}
	return pi
}

// walkProcesses follows the doubly-linked ActiveProcessLinks list starting from
// PsActiveProcessHead. Returns at most 1024 processes — the safety cap guards
// against corrupted lists looping into garbage.
func walkProcesses(cr3sys, psActiveHead uint64, p *WinProfile, vread vreadFn) []ProcessInfo {
	if !isKernelAddr(psActiveHead) {
		return nil
	}
	// Read Flink of the list head (LIST_ENTRY at psActiveHead, Flink at +0).
	buf := vread(cr3sys, psActiveHead+uint64(p.ListEntryFlink), 8)
	if len(buf) < 8 {
		return nil
	}
	nextLinks := binary.LittleEndian.Uint64(buf)
	if !isKernelAddr(nextLinks) {
		return nil
	}

	procs := make([]ProcessInfo, 0, 64)
	seen := map[uint64]bool{psActiveHead: true}

	for {
		if seen[nextLinks] {
			break
		}
		seen[nextLinks] = true
		if !isKernelAddr(nextLinks) {
			break
		}

		eprocBase := nextLinks - uint64(p.EProcLinks)
		if proc := readEPROC(cr3sys, eprocBase, p, vread); proc != nil {
			procs = append(procs, *proc)
		}

		buf := vread(cr3sys, nextLinks+uint64(p.ListEntryFlink), 8)
		if len(buf) < 8 {
			break
		}
		nextLinks = binary.LittleEndian.Uint64(buf)
		if nextLinks == 0 || nextLinks == psActiveHead {
			break
		}
		if len(procs) >= 1024 {
			break
		}
	}
	return procs
}

// readUnicodeString reads a UNICODE_STRING (Length:2 + MaxLen:2 + pad:4 + Buffer:8)
// at base in the supplied address space, then dereferences the buffer pointer.
func readUnicodeString(cr3, base uint64, vread vreadFn) string {
	b := vread(cr3, base, 16)
	if len(b) < 16 {
		return ""
	}
	length := binary.LittleEndian.Uint16(b[0:2])
	bufPtr := binary.LittleEndian.Uint64(b[8:16])
	if length == 0 || bufPtr == 0 {
		return ""
	}
	if length > 1024 {
		length = 1024
	}
	strBuf := vread(cr3, bufPtr, int(length))
	if len(strBuf) < int(length) {
		// Use whatever we got — partial reads still produce useful data.
		if len(strBuf) == 0 {
			return ""
		}
		length = uint16(len(strBuf) &^ 1)
	}
	count := int(length) / 2
	if count == 0 {
		return ""
	}
	u16 := make([]uint16, count)
	for i := 0; i < count; i++ {
		u16[i] = binary.LittleEndian.Uint16(strBuf[i*2:])
	}
	return string(utf16.Decode(u16))
}

// readPEB extracts ImagePathName and CommandLine from a process's PEB.
// All reads use the process's own CR3 because PEB lives in user space.
func readPEB(procCR3, pebAddr uint64, p *WinProfile, vread vreadFn) (imagePath, cmdLine string) {
	if procCR3 == 0 || !isUserAddr(pebAddr) {
		return "", ""
	}
	buf := vread(procCR3, pebAddr+uint64(p.PEBParams), 8)
	if len(buf) < 8 {
		return "", ""
	}
	paramsPtr := binary.LittleEndian.Uint64(buf)
	if !isUserAddr(paramsPtr) {
		return "", ""
	}
	imagePath = readUnicodeString(procCR3, paramsPtr+uint64(p.ParamsImagePath), vread)
	cmdLine = readUnicodeString(procCR3, paramsPtr+uint64(p.ParamsCmdLine), vread)
	return
}

// scanProcesses is the fallback path: scan every physical page for the EPROCESS
// pool tag "Proc" and validate candidate structures.
// Pool tag is 4 bytes immediately preceding the object; the EPROCESS body
// begins at tagOffset + 4 (legacy) or at a structure-specific offset on Win10+
// where the pool header sits before the object. We try a small set of common
// distances from the tag to the EPROCESS start.
func scanProcesses(d *Dump, p *WinProfile, vread vreadFn) []ProcessInfo {
	procs := make([]ProcessInfo, 0, 64)
	tag := []byte{0x50, 0x72, 0x6F, 0xE3} // 'P','r','o',0xE3 (legacy quoted tag)
	tag2 := []byte{0x50, 0x72, 0x6F, 0x63} // 'P','r','o','c'
	seen := map[uint64]bool{}

	// Walk physical runs page by page.
	const chunkSize = 0x10000 // 64 KB scan chunks
	for _, run := range d.runs {
		runStart := run.BasePage * pageSize
		runLen := run.PageCount * pageSize
		var off uint64
		for off < runLen {
			read := chunkSize
			if uint64(read) > runLen-off {
				read = int(runLen - off)
			}
			page := d.ReadPhys(runStart+off, read)
			if len(page) == 0 {
				off += uint64(read)
				continue
			}
			// Find every "Proc"/legacy-tag occurrence.
			for _, pat := range [][]byte{tag, tag2} {
				start := 0
				for {
					idx := bytes.Index(page[start:], pat)
					if idx < 0 {
						break
					}
					tagPA := runStart + off + uint64(start+idx)
					start += idx + 1
					// Try candidate offsets from pool tag to EPROCESS body.
					// On Win10 x64: tag at pool_header+4; EPROCESS body at chunk+0x70..0xC0
					// depending on optional object header components (quota, creator info).
					for _, delta := range []uint64{0x60, 0x68, 0x70, 0x74, 0x78, 0x7C, 0x80, 0x88, 0x90, 0x98, 0xA0, 0xC0} {
						eprocPA := tagPA + delta
						if seen[eprocPA] {
							continue
						}
						// Read raw via physical, then validate against profile fields.
						body := d.ReadPhys(eprocPA, 0x600)
						if len(body) < 0x320 {
							continue
						}
						pid := binary.LittleEndian.Uint64(body[p.EProcPID : p.EProcPID+8])
						if pid == 0 || pid > 0xFFFFF {
							continue
						}
						if p.EProcName+15 > len(body) {
							continue
						}
						nameRaw := body[p.EProcName : p.EProcName+15]
						printable := 0
						for _, c := range nameRaw {
							if c == 0 {
								break
							}
							if c < 0x20 || c >= 0x7F {
								printable = -1
								break
							}
							printable++
						}
						if printable < 3 {
							continue
						}
						// Strong validation: EProcLinks must be a kernel VA,
						// PPID must be sane, CR3 must be page-aligned.
						links := binary.LittleEndian.Uint64(body[p.EProcLinks : p.EProcLinks+8])
						if !isKernelAddr(links) {
							continue
						}
						ppid := binary.LittleEndian.Uint64(body[p.EProcPPID : p.EProcPPID+8])
						if ppid >= 0xFFFFF || ppid == pid {
							continue
						}
						cr3raw := binary.LittleEndian.Uint64(body[p.EProcDTB : p.EProcDTB+8])
						cr3 := cr3raw & 0xFFFFFFFFFFFFF000
						if cr3 < 0x1000 {
							continue
						}
						// Require at least one ASCII letter — eliminates space-only garbage matches.
						hasLetter := false
						for i := 0; i < printable; i++ {
							c := nameRaw[i]
							if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
								hasLetter = true
								break
							}
						}
						if !hasLetter {
							continue
						}
						// Real ImageFileName is a plain filename — no parens, brackets, path chars.
						hasBadChar := false
						for i := 0; i < printable; i++ {
							c := nameRaw[i]
							if c == '(' || c == ')' || c == '[' || c == ']' || c == '/' || c == ':' {
								hasBadChar = true
								break
							}
						}
						if hasBadChar {
							continue
						}
						// PPID=0 is only valid for System (PID 4) and early-boot kernel objects.
						if ppid == 0 && pid > 88 {
							continue
						}

						seen[eprocPA] = true
						pi := &ProcessInfo{EProcBase: eprocPA}
						pi.PID = pid
						pi.PPID = ppid
						pi.CR3 = cr3raw
						pi.PEBAddr = binary.LittleEndian.Uint64(body[p.EProcPEB : p.EProcPEB+8])
						pi.CreateTS = filetimeToTime(binary.LittleEndian.Uint64(body[p.EProcCreate : p.EProcCreate+8]))
						if p.EProcExitTime != 0 && p.EProcExitTime+8 <= len(body) {
							pi.ExitTS = filetimeToTime(binary.LittleEndian.Uint64(body[p.EProcExitTime : p.EProcExitTime+8]))
						}
						pi.Name = string(nameRaw[:printable])
						procs = append(procs, *pi)
						if len(procs) >= 2048 {
							return procs
						}
					}
				}
			}
			off += uint64(read)
		}
	}
	return procs
}
