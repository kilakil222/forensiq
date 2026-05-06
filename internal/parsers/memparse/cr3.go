package memparse

import "log"

// findKernelCR3 locates the kernel page directory table base (DTB/CR3) that can
// translate PsActiveProcessHead to a valid kernel pointer. On crash dumps where
// the header's DirectoryTableBase belongs to a user process (e.g., NMI dump),
// this scans the first 16 MB of physical RAM to find a CR3 that works.
func findKernelCR3(d *Dump, psActiveHead uint64) uint64 {
	if psActiveHead == 0 || !isKernelAddr(psActiveHead) {
		return 0
	}

	test := func(cr3 uint64) bool {
		cr3 = cr3 & 0xFFFFFFFFFFFFF000
		if cr3 == 0 {
			return false
		}
		pa, err := virtToPhys(cr3, psActiveHead, d.ReadPhys)
		if err != nil {
			return false
		}
		// The flink pointer at PsActiveProcessHead should be a kernel address.
		buf := d.ReadPhys(pa, 8)
		if len(buf) < 8 {
			return false
		}
		flink := uint64Of(buf)
		return isKernelAddr(flink)
	}

	// 1. Try the header CR3 first (fast path — works for most dumps).
	if test(d.SystemCR3) {
		return d.SystemCR3 & 0xFFFFFFFFFFFFF000
	}

	log.Printf("[memparse] header CR3 0x%x failed kernel-addr test — scanning for kernel DTB...", d.SystemCR3)

	// 2. Scan physical pages 1..4096 (first 16 MB) looking for a page whose
	//    entry at PML4[0x1ED] self-references (Windows self-mapping) OR that
	//    can directly translate PsActiveProcessHead.
	// Pages are 4 KB each; 4096 pages = 16 MB scan.
	const selfMapIdx = 0x1ED
	for page := uint64(1); page <= 4096; page++ {
		pa := page * pageSize
		// Check self-referencing PML4 heuristic: PML4[0x1ED].physAddr == this page.
		entry := d.ReadPhys(pa+selfMapIdx*8, 8)
		if len(entry) < 8 {
			continue
		}
		e := uint64Of(entry)
		if e&1 == 0 { // not present
			continue
		}
		if (e & 0xFFFFFFFFFF000) == pa {
			// Self-referencing PML4 found — validate it.
			if test(pa) {
				log.Printf("[memparse] found kernel CR3 at physical 0x%x (self-map)", pa)
				return pa
			}
		}
	}

	// 3. Brute-force: try every page-aligned physical address < 8 MB.
	for page := uint64(1); page <= 2048; page++ {
		pa := page * pageSize
		if test(pa) {
			log.Printf("[memparse] found kernel CR3 at physical 0x%x (brute-force)", pa)
			return pa
		}
	}

	log.Printf("[memparse] could not find kernel CR3 — falling back to header value")
	return d.SystemCR3 & 0xFFFFFFFFFFFFF000
}
