package memparse

import (
	"encoding/binary"
	"fmt"
	"math"
	"strings"
)

// MalfindHit describes one suspicious VAD region. Modeled to match the
// `mem_malfind` table columns exactly so insertion is a one-liner.
type MalfindHit struct {
	PID     uint64
	Name    string
	Address uint64
	Size    uint64
	Reason  string
	VadTag  string
	Hexdump string
	Disasm  string
}

// VAD protection bit-field meanings (5 bits in u.VadFlags shifted from bit 24).
// Indices map to MMVAD protection codes:
//   0 NoAccess  1 R   2 X   3 RX
//   4 RW        5 WC  6 RWX 7 WX/Cow
var vadProtNames = [8]string{
	"NOACCESS",
	"READONLY",
	"EXECUTE",
	"EXECUTE_READ",
	"READWRITE",
	"WRITECOPY",
	"EXECUTE_READWRITE",
	"EXECUTE_WRITECOPY",
}

// VadType values for _MMVAD_FLAGS bits 4-6.
// Type 2 (VadImageMap) = section-backed (loaded DLL/EXE).
var vadTypeNames = [8]string{
	"None", "DevicePhysical", "ImageMap", "Awe",
	"WriteWatch", "LargePages", "RotatePhysical", "LargePageSection",
}

// scanMalfind walks every process's VAD tree and returns regions whose protection
// includes execute+write (codes 6 or 7) — the classic shellcode injection signature.
// kernCR3 must be the System/kernel CR3: EPROCESS and MMVAD nodes are kernel objects
// that require the kernel page tables. pr.CR3 (user DTB) cannot reach them on KPTI systems.
func scanMalfind(procs []ProcessInfo, kernCR3 uint64, p *WinProfile, vread vreadFn) []MalfindHit {
	hits := make([]MalfindHit, 0, 32)
	for _, pr := range procs {
		if pr.EProcBase == 0 {
			continue
		}
		root := readVadRoot(kernCR3, pr.EProcBase, p, vread)
		if root == 0 {
			continue
		}
		walkVAD(pr, kernCR3, root, p, vread, &hits, 0)
		if len(hits) >= 1024 {
			break
		}
	}
	return hits
}

func readVadRoot(kernCR3, eprocBase uint64, p *WinProfile, vread vreadFn) uint64 {
	if p.EProcVadRoot <= 0 {
		return 0
	}
	// EPROCESS is a kernel object — must use kernCR3, not the process user DTB.
	buf := vread(kernCR3, eprocBase+uint64(p.EProcVadRoot), 8)
	if len(buf) < 8 {
		return 0
	}
	root := binary.LittleEndian.Uint64(buf)
	if !isKernelAddr(root) {
		return 0
	}
	return root
}

// walkVAD recurses through a VAD balanced tree. Each node's Left/Right pointers
// are at VadLeftChild/VadRightChild. We check protection at VadFlags.
// kernCR3 is used for all kernel-object reads (MMVAD nodes); pr.CR3 is used only
// for reading user-space page content at the mapped VA range.
func walkVAD(pr ProcessInfo, kernCR3 uint64, node uint64, p *WinProfile, vread vreadFn, hits *[]MalfindHit, depth int) {
	if depth > 64 {
		return
	}
	if !isKernelAddr(node) {
		return
	}
	body := vread(kernCR3, node, 0x40)
	if len(body) < 0x28 {
		return
	}
	left := binary.LittleEndian.Uint64(body[p.VadLeftChild : p.VadLeftChild+8])
	right := binary.LittleEndian.Uint64(body[p.VadRightChild : p.VadRightChild+8])
	// Mask the low bit (color bit) often used by RTL_BALANCED_NODE.
	left &^= 0x3
	right &^= 0x3

	// Compute start/end VPN from low+high parts.
	startLow := binary.LittleEndian.Uint32(body[p.VadStartingVpn : p.VadStartingVpn+4])
	endLow := binary.LittleEndian.Uint32(body[p.VadEndingVpn : p.VadEndingVpn+4])
	var startHigh, endHigh uint8
	if p.VadStartingVpnHigh+1 <= len(body) {
		startHigh = body[p.VadStartingVpnHigh]
	}
	if p.VadEndingVpnHigh+1 <= len(body) {
		endHigh = body[p.VadEndingVpnHigh]
	}
	startVpn := uint64(startLow) | (uint64(startHigh) << 32)
	endVpn := uint64(endLow) | (uint64(endHigh) << 32)
	startVA := startVpn * pageSize
	endVA := (endVpn + 1) * pageSize
	// Sanitize size: shellcode/injection regions are always small (< 1 GB).
	// TB-scale sizes indicate a bogus EndingVpnHigh byte or a large reserved
	// address range (file mapping, JIT reservation) — not a real injection.
	// Store size=0 for oversized entries so the DB isn't polluted with fake TB values.
	var size uint64
	if endVA > startVA && (endVA-startVA) <= (1<<30) {
		size = endVA - startVA
	}
	// Still process the entry even if size is unknown (size==0).

	var flags uint32
	if p.VadFlags+4 <= len(body) {
		flags = binary.LittleEndian.Uint32(body[p.VadFlags : p.VadFlags+4])
	}
	// Protection field = bits 7..11 of u.VadFlags (_MMVAD_FLAGS.Protection at bit position 7).
	prot := (flags >> 7) & 0x1F
	// VadType = bits 4-6; PrivateMemory = bit 20.
	vadType := (flags >> 4) & 0x7
	isPrivate := (flags>>20)&0x1 != 0

	// Skip invalid VA ranges (kernel VA, or prot out of range).
	if startVA > 0 && startVA < 0x0000800000000000 && prot < uint32(len(vadProtNames)) {
		// Read 256 bytes for entropy (better sample); hexdump uses first 64.
		sample := vread(pr.CR3, startVA, 256)
		head := sample
		if len(head) > 64 {
			head = head[:64]
		}
		hasMZ := len(sample) >= 2 && sample[0] == 'M' && sample[1] == 'Z'

		var reason string
		switch {
		case prot == 6 || prot == 7:
			reason = "exec+write VAD"
			if hasMZ {
				reason += " (MZ header)"
			}
		case (prot == 2 || prot == 3) && hasMZ:
			// EXECUTE / EXECUTE_READ with PE header — injected DLL or shellcode loader.
			reason = "exec VAD (MZ header)"
		}

		if reason != "" {
			// Annotate memory type: private anonymous = shellcode candidate;
			// mapped = section-backed (DLL injection or hollowing).
			if isPrivate {
				reason += " [private]"
			} else if vadType == 2 {
				// VadImageMap: normal mapped DLL/EXE — lower suspicion unless also exec+write.
				reason += " [image-map]"
			} else {
				reason += " [mapped]"
			}
			if size == 0 {
				reason += " (large region)"
			}
			if len(sample) == 0 {
				reason += " (page not in dump)"
			} else {
				entropy := shannonEntropy(sample)
				if entropy > 0 {
					reason += fmt.Sprintf(" entropy=%.2f", entropy)
				}
			}
			peMeta := ""
			if hasMZ {
				peMeta = parsePEMeta(pr.CR3, startVA, vread)
			}
			// VadTag encodes "TYPE/PROTECTION" for easy filtering.
			vadTag := vadTypeNames[vadType] + "/" + vadProtNames[prot]
			*hits = append(*hits, MalfindHit{
				PID:     pr.PID,
				Name:    pr.Name,
				Address: startVA,
				Size:    size,
				Reason:  reason,
				VadTag:  vadTag,
				Hexdump: hexdump(head),
				Disasm:  peMeta,
			})
		}
	}

	walkVAD(pr, kernCR3, left, p, vread, hits, depth+1)
	walkVAD(pr, kernCR3, right, p, vread, hits, depth+1)
}

// parsePEMeta extracts a short summary from a PE header at the start of buf.
// Returns "" if buf doesn't contain a valid PE signature at a reasonable offset.
func parsePEMeta(cr3 uint64, va uint64, vread vreadFn) string {
	// Read enough to cover MZ header + PE header with imports
	fullBuf := vread(cr3, va, 0x400)
	if len(fullBuf) < 0x40 {
		return ""
	}
	if fullBuf[0] != 'M' || fullBuf[1] != 'Z' {
		return ""
	}
	peOff := binary.LittleEndian.Uint32(fullBuf[0x3C:0x40])
	if peOff == 0 || int(peOff)+0x60 > len(fullBuf) {
		return ""
	}
	if string(fullBuf[peOff:peOff+4]) != "PE\x00\x00" {
		return ""
	}
	// COFF header starts at peOff+4
	machine := binary.LittleEndian.Uint16(fullBuf[peOff+4 : peOff+6])
	numSections := binary.LittleEndian.Uint16(fullBuf[peOff+6 : peOff+8])
	chars := binary.LittleEndian.Uint16(fullBuf[peOff+22 : peOff+24])

	isDLL := chars&0x2000 != 0
	isExe := chars&0x0002 != 0
	kind := "EXE"
	if isDLL {
		kind = "DLL"
	} else if !isExe {
		kind = "OBJ"
	}
	machStr := "x64"
	if machine == 0x014C {
		machStr = "x86"
	}

	// Optional header size to locate data directory
	optHdrSize := binary.LittleEndian.Uint16(fullBuf[peOff+20 : peOff+22])
	parts := []string{fmt.Sprintf("PE %s/%s sects=%d", kind, machStr, numSections)}

	// Import directory (data dir entry 1) at optional header start + 0x78 for PE32+ or +0x68 for PE32
	optStart := int(peOff) + 24
	var importRVA uint32
	if optHdrSize >= 0x70 && machine == 0x8664 { // PE32+: data dirs at optStart+0x70, import dir at +0x78
		if optStart+0x7C <= len(fullBuf) {
			importRVA = binary.LittleEndian.Uint32(fullBuf[optStart+0x78 : optStart+0x7C])
		}
	} else if optHdrSize >= 0x60 { // PE32: data dirs at optStart+0x60, import dir at +0x68
		if optStart+0x6C <= len(fullBuf) {
			importRVA = binary.LittleEndian.Uint32(fullBuf[optStart+0x68 : optStart+0x6C])
		}
	}

	if importRVA > 0 && importRVA < 0x200000 {
		// Read up to 8 import descriptors (each 0x14 bytes)
		idBuf := vread(cr3, va+uint64(importRVA), 8*0x14)
		if len(idBuf) >= 0x14 {
			var dlls []string
			for i := 0; i+0x14 <= len(idBuf); i += 0x14 {
				nameRVA := binary.LittleEndian.Uint32(idBuf[i+12 : i+16])
				if nameRVA == 0 {
					break
				}
				nameBuf := vread(cr3, va+uint64(nameRVA), 64)
				if len(nameBuf) == 0 {
					continue
				}
				end := 0
				for end < len(nameBuf) && nameBuf[end] != 0 && nameBuf[end] >= 0x20 && nameBuf[end] < 0x7F {
					end++
				}
				if end > 0 {
					dlls = append(dlls, string(nameBuf[:end]))
				}
				if len(dlls) >= 4 {
					break
				}
			}
			if len(dlls) > 0 {
				parts = append(parts, "imports="+strings.Join(dlls, ","))
			}
		}
	}
	return strings.Join(parts, " ")
}

// shannonEntropy computes Shannon entropy (0.0–8.0 bits/byte) of b.
// Values above 7.0 typically indicate packed, encrypted, or compressed data.
func shannonEntropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var freq [256]int
	for _, by := range b {
		freq[by]++
	}
	n := float64(len(b))
	e := 0.0
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		e -= p * math.Log2(p)
	}
	return e
}

// hexdump produces a compact two-row "00 11 22 33  ..." representation.
func hexdump(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	const hexChars = "0123456789ABCDEF"
	out := make([]byte, 0, len(b)*3)
	for i, by := range b {
		if i > 0 {
			out = append(out, ' ')
		}
		out = append(out, hexChars[by>>4], hexChars[by&0xF])
	}
	return string(out)
}
