package memparse

import (
	"encoding/binary"
	"log"
)

// ModuleInfo is one row produced by walking PsLoadedModuleList.
type ModuleInfo struct {
	Base     uint64
	Size     uint32
	FullName string
	BaseName string
}

// walkModules follows the InLoadOrderLinks LIST_ENTRY rooted at psLoadedHead.
// All reads happen in the System CR3 since modules are kernel-mode.
func walkModules(cr3sys, psLoadedHead uint64, p *WinProfile, vread vreadFn) []ModuleInfo {
	if !isKernelAddr(psLoadedHead) {
		return nil
	}
	mods := make([]ModuleInfo, 0, 128)
	seen := map[uint64]bool{psLoadedHead: true}

	buf := vread(cr3sys, psLoadedHead+uint64(p.ListEntryFlink), 8)
	if len(buf) < 8 {
		log.Printf("[memparse] walkModules: vread failed for PsLoadedModuleList=0x%X cr3=0x%X", psLoadedHead, cr3sys)
		return nil
	}
	cur := binary.LittleEndian.Uint64(buf)
	if !isKernelAddr(cur) {
		log.Printf("[memparse] walkModules: Flink=0x%X not a kernel addr (PsLoadedModuleList=0x%X)", cur, psLoadedHead)
		return nil
	}

	for {
		if seen[cur] {
			break
		}
		seen[cur] = true
		// cur points at InLoadOrderLinks of a KLDR_DATA_TABLE_ENTRY.
		// The struct begins at cur - p.KldrInLoadOrder.
		base := cur - uint64(p.KldrInLoadOrder)

		body := vread(cr3sys, base, 0x80)
		if len(body) < 0x70 {
			log.Printf("[memparse] walkModules: short read at base=0x%X (%d bytes)", base, len(body))
			// Advance past this entry rather than aborting the whole walk.
			nxt2 := vread(cr3sys, cur, 8)
			if len(nxt2) < 8 {
				break
			}
			next2 := binary.LittleEndian.Uint64(nxt2)
			if next2 == 0 || next2 == psLoadedHead || seen[next2] {
				break
			}
			cur = next2
			continue
		}
		mod := ModuleInfo{}
		if p.KldrDllBase+8 <= len(body) {
			mod.Base = binary.LittleEndian.Uint64(body[p.KldrDllBase : p.KldrDllBase+8])
		}
		if p.KldrSizeOfImage+4 <= len(body) {
			mod.Size = binary.LittleEndian.Uint32(body[p.KldrSizeOfImage : p.KldrSizeOfImage+4])
		}
		if p.KldrFullDllName+16 <= len(body) {
			mod.FullName = readUnicodeString(cr3sys, base+uint64(p.KldrFullDllName), vread)
		}
		if p.KldrBaseDllName+16 <= len(body) {
			mod.BaseName = readUnicodeString(cr3sys, base+uint64(p.KldrBaseDllName), vread)
		}
		if mod.Base != 0 || mod.BaseName != "" {
			mods = append(mods, mod)
		}

		// Advance via Flink at the start of the entry (InLoadOrderLinks.Flink).
		nxt := vread(cr3sys, cur, 8)
		if len(nxt) < 8 {
			break
		}
		cur = binary.LittleEndian.Uint64(nxt)
		if cur == 0 || cur == psLoadedHead {
			break
		}
		if len(mods) >= 4096 {
			break
		}
	}
	return mods
}
