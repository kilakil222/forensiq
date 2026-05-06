package memparse

import (
	"encoding/binary"
	"fmt"
)

// virtToPhys translates a 64-bit virtual address using x86-64 4-level paging.
// readPhys is the dump's physical reader. Returns the physical address.
func virtToPhys(cr3, va uint64, readPhys func(pa uint64, n int) []byte) (uint64, error) {
	pml4Idx := (va >> 39) & 0x1FF
	pdptIdx := (va >> 30) & 0x1FF
	pdIdx := (va >> 21) & 0x1FF
	ptIdx := (va >> 12) & 0x1FF
	offset4k := va & 0xFFF

	readEntry := func(base, idx uint64) (uint64, error) {
		b := readPhys(base+idx*8, 8)
		if len(b) < 8 {
			return 0, fmt.Errorf("read failed at 0x%x", base+idx*8)
		}
		e := binary.LittleEndian.Uint64(b)
		if e&1 == 0 {
			return 0, fmt.Errorf("not present (entry 0x%x)", e)
		}
		return e, nil
	}

	cr3clean := cr3 & 0xFFFFFFFFFFFFF000

	pml4e, err := readEntry(cr3clean, pml4Idx)
	if err != nil {
		return 0, fmt.Errorf("pml4: %w", err)
	}

	pdpte, err := readEntry(pml4e&0xFFFFFFFFFF000, pdptIdx)
	if err != nil {
		return 0, fmt.Errorf("pdpt: %w", err)
	}
	// 1 GB page (PS bit 7)
	if pdpte&(1<<7) != 0 {
		return (pdpte & 0xFFFFFC0000000) | (va & 0x3FFFFFFF), nil
	}

	pde, err := readEntry(pdpte&0xFFFFFFFFFF000, pdIdx)
	if err != nil {
		return 0, fmt.Errorf("pd: %w", err)
	}
	// 2 MB page
	if pde&(1<<7) != 0 {
		return (pde & 0xFFFFFFFE00000) | (va & 0x1FFFFF), nil
	}

	pte, err := readEntry(pde&0xFFFFFFFFFF000, ptIdx)
	if err != nil {
		return 0, fmt.Errorf("pt: %w", err)
	}

	return (pte & 0xFFFFFFFFFF000) | offset4k, nil
}

// isKernelAddr returns true if the virtual address looks like a kernel-mode
// canonical x64 address. Used to gate scans/walks before attempting reads.
func isKernelAddr(va uint64) bool {
	return va >= 0xFFFF800000000000
}

// isUserAddr returns true if va looks like a user-mode canonical address.
func isUserAddr(va uint64) bool {
	return va != 0 && va < 0x0000800000000000
}
