// Package memparse is a pure-Go Windows memory dump parser. It reads
// PAGEDUMP64 and raw memory images, walks EPROCESS / PsLoadedModuleList /
// VADs, and writes the same DuckDB tables that the Volatility3 wrapper used
// to populate. No subprocess, no Python — everything is embedded.
package memparse

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	"forensiq/internal/parsers"
)

// Parse is the single entry point: open the dump, run all phases, populate the
// DB. Errors here are fatal-for-this-dump; per-phase failures are logged and
// the next phase still runs (best-effort recovery).
func Parse(dumpPath string, db *sql.DB, ch chan<- parsers.Progress) error {
	start := time.Now()

	d, err := openDump(dumpPath)
	if err != nil {
		return err
	}
	defer d.Close()

	if !d.IsPageDump {
		log.Printf("[memparse] non-PAGEDUMP image (raw); structural fields unknown — limited extraction")
	} else {
		log.Printf("[memparse] PAGEDUMP64: build=%d procs=%d cr3=0x%x psHead=0x%x psMods=0x%x",
			d.MinorVersion, d.NumberProcessors, d.SystemCR3, d.PsActiveProcessHead, d.PsLoadedModuleList)
	}

	prof := selectProfile(d.MinorVersion)
	if prof == nil {
		return fmt.Errorf("no Windows profile available for build %d", d.MinorVersion)
	}
	log.Printf("[memparse] using profile: %s", prof.Name)

	// vread translates a virtual->physical address using cr3 and reads n bytes.
	// It handles cross-page reads by issuing a follow-up read for the remainder.
	vread := func(cr3, va uint64, n int) []byte {
		if cr3 == 0 || n <= 0 {
			return nil
		}
		// First page may not cover the whole request — read in page-sized chunks.
		out := make([]byte, 0, n)
		cur := va
		remaining := n
		for remaining > 0 {
			pa, err := virtToPhys(cr3, cur, d.ReadPhys)
			if err != nil {
				break
			}
			pageEnd := (cur | 0xFFF) + 1
			chunk := remaining
			if uint64(chunk) > pageEnd-cur {
				chunk = int(pageEnd - cur)
			}
			b := d.ReadPhys(pa, chunk)
			if len(b) == 0 {
				break
			}
			out = append(out, b...)
			if len(b) < chunk {
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

	// Find the actual kernel CR3. On NMI/live dumps the header's DirectoryTableBase
	// may belong to a user-space process. findKernelCR3 tests the header value first
	// (fast path) and falls back to a physical page scan if needed.
	kernCR3 := findKernelCR3(d, d.PsActiveProcessHead)
	if kernCR3 == 0 {
		kernCR3 = d.SystemCR3 & 0xFFFFFFFFFFFFF000
	}
	log.Printf("[memparse] using kernel CR3: 0x%x (header was 0x%x)", kernCR3, d.SystemCR3)

	// ------- Phase 0: profile validation against System (PID 4) -------
	if d.IsPageDump && d.PsActiveProcessHead != 0 {
		if !validateProfile(kernCR3, d.PsActiveProcessHead, prof, vread) {
			log.Printf("[memparse] primary profile failed validation, trying alternates...")
			for i := range Profiles {
				p := &Profiles[i]
				if p == prof {
					continue
				}
				if validateProfile(kernCR3, d.PsActiveProcessHead, p, vread) {
					prof = p
					log.Printf("[memparse] switched profile: %s", p.Name)
					break
				}
			}
		}
	}

	// ------- Phase 1a: process list (pslist) via ActiveProcessLinks walk -------
	procs := walkProcesses(kernCR3, d.PsActiveProcessHead, prof, vread)
	if len(procs) == 0 {
		log.Printf("[memparse] PsActiveProcessHead walk returned 0 — using pool scan as pslist source")
		procs = scanProcesses(d, prof, vread)
	}
	pslistPIDs := make(map[uint64]bool, len(procs))
	pidToName := make(map[uint64]string, len(procs))
	for i := range procs {
		p := &procs[i]
		if p.PEBAddr != 0 && p.CR3 != 0 {
			imgPath, cmd := readPEB(p.CR3, p.PEBAddr, prof, vread)
			p.ImagePath = imgPath
			p.CmdLine = cmd
		}
		insertProcess(db, p)
		insertCmdLine(db, p)
		pslistPIDs[p.PID] = true
		pidToName[p.PID] = p.Name
	}
	progress(ch, "memparse/processes", int64(len(procs)), time.Since(start))

	// ------- Phase 1b: independent pool tag scan → psscan (hidden process detection) -------
	// Always runs regardless of walk success. Processes that appear here but not in
	// pslist have been unlinked from ActiveProcessLinks (classic DKOM rootkit technique).
	scanned := scanProcesses(d, prof, vread)
	hiddenCount := 0
	// Precompute the physical address of a known kernel VA for CR3 validation.
	// All living processes share the same kernel page tables, so virtToPhys(p.CR3, kernVA)
	// must equal virtToPhys(kernCR3, kernVA). A freed EPROCESS has a recycled or
	// zeroed CR3 that fails or mismatches this check.
	kernValidateVA := d.PsLoadedModuleList
	if kernValidateVA == 0 {
		kernValidateVA = d.PsActiveProcessHead
	}
	var kernValidatePA uint64
	if kernValidateVA != 0 {
		kernValidatePA, _ = virtToPhys(kernCR3, kernValidateVA, d.ReadPhys)
	}

	for i := range scanned {
		p := &scanned[i]
		if p.PEBAddr != 0 && p.CR3 != 0 {
			imgPath, cmd := readPEB(p.CR3, p.PEBAddr, prof, vread)
			p.ImagePath = imgPath
			p.CmdLine = cmd
		}
		if !pslistPIDs[p.PID] && p.ExitTS.IsZero() {
			// Validate CR3: a living process must map kernel VAs identically to kernCR3.
			if kernValidatePA != 0 && p.CR3 != 0 {
				gotPA, err := virtToPhys(p.CR3, kernValidateVA, d.ReadPhys)
				if err != nil || gotPA != kernValidatePA {
					p.StalePool = true
				}
			} else if p.CR3 == 0 {
				p.StalePool = true
			}
		}
		insertPsScan(db, p)
		if !pslistPIDs[p.PID] {
			if p.ExitTS.IsZero() {
				if p.StalePool {
					log.Printf("[memparse] stale pool entry: PID=%d name=%q cr3=0x%x (freed EPROCESS — CR3 does not map kernel)", p.PID, p.Name, p.CR3)
				} else {
					hiddenCount++
					log.Printf("[memparse] HIDDEN PROCESS: PID=%d name=%q (still running, unlinked from ActiveProcessLinks — DKOM suspected)", p.PID, p.Name)
				}
			} else {
				log.Printf("[memparse] exited process in pool: PID=%d name=%q exit=%s (stale pool block, not DKOM)", p.PID, p.Name, p.ExitTS.Format("2006-01-02T15:04:05Z"))
			}
		}
	}
	if hiddenCount > 0 {
		log.Printf("[memparse] !!! %d hidden process(es) detected via pool scan", hiddenCount)
	}
	for i := range scanned {
		sp := &scanned[i]
		if _, ok := pidToName[sp.PID]; !ok {
			pidToName[sp.PID] = sp.Name
		}
	}
	progress(ch, "memparse/psscan", int64(len(scanned)), time.Since(start))

	// ------- Phase 2: network -------
	conns := scanNetwork(d, kernCR3, prof, vread)
	for i := range conns {
		c := &conns[i]
		// eprocNameFromPool may have already resolved the name from the pool block;
		// only fall back to pidToName / <pid:N> when that didn't succeed.
		if c.Owner == "" && c.PID != 0 {
			if name := pidToName[c.PID]; name != "" {
				c.Owner = name
			} else {
				c.Owner = fmt.Sprintf("<pid:%d>", c.PID)
			}
		}
		insertNetConn(db, c)
	}
	progress(ch, "memparse/network", int64(len(conns)), time.Since(start))

	// ------- Phase 3: kernel modules -------
	mods := walkModules(kernCR3, d.PsLoadedModuleList, prof, vread)
	for _, m := range mods {
		insertModule(db, &m)
	}
	progress(ch, "memparse/modules", int64(len(mods)), time.Since(start))

	// ------- Phase 4: malfind via VAD scan -------
	// Combine pslist procs with any hidden ones found only by pool scan.
	allProcs := procs
	for _, sp := range scanned {
		if !pslistPIDs[sp.PID] {
			allProcs = append(allProcs, sp)
		}
	}
	hits := scanMalfind(allProcs, kernCR3, prof, vread)
	for _, h := range hits {
		insertMalfind(db, &h)
	}
	progress(ch, "memparse/malfind", int64(len(hits)), time.Since(start))

	// ------- Phase 5: sysinfo summary -------
	insertSysInfo(db, "build", fmt.Sprintf("%d", d.MinorVersion))
	insertSysInfo(db, "profile", prof.Name)
	insertSysInfo(db, "processors", fmt.Sprintf("%d", d.NumberProcessors))
	insertSysInfo(db, "system_cr3", fmt.Sprintf("0x%X", d.SystemCR3))
	insertSysInfo(db, "kernel_cr3", fmt.Sprintf("0x%X", kernCR3))
	insertSysInfo(db, "ps_active_head", fmt.Sprintf("0x%X", d.PsActiveProcessHead))
	insertSysInfo(db, "ps_loaded_modules", fmt.Sprintf("0x%X", d.PsLoadedModuleList))
	insertSysInfo(db, "machine", fmt.Sprintf("0x%X", d.MachineImageType))
	progress(ch, "memparse/sysinfo", 8, time.Since(start))

	return nil
}

// validateProfile reads the System (PID 4) EPROCESS at the head of the active
// process list and checks PID==4 and Name starts with "System".
func validateProfile(cr3sys, psActiveHead uint64, p *WinProfile, vread vreadFn) bool {
	buf := vread(cr3sys, psActiveHead+uint64(p.ListEntryFlink), 8)
	if len(buf) < 8 {
		return false
	}
	flink := uint64Of(buf)
	if !isKernelAddr(flink) {
		return false
	}
	eprocBase := flink - uint64(p.EProcLinks)
	pi := readEPROC(cr3sys, eprocBase, p, vread)
	if pi == nil {
		return false
	}
	// First process out of PsActiveProcessHead is "System" (PID 4) on every
	// supported Windows build.
	return pi.PID == 4 && len(pi.Name) >= 6 && pi.Name[:6] == "System"
}

func uint64Of(b []byte) uint64 {
	var v uint64
	for i := 0; i < 8 && i < len(b); i++ {
		v |= uint64(b[i]) << (8 * i)
	}
	return v
}

func progress(ch chan<- parsers.Progress, name string, count int64, elapsed time.Duration) {
	if ch != nil {
		select {
		case ch <- parsers.Progress{Parser: name, Count: count, Done: true, Elapsed: elapsed}:
		default:
		}
	}
	log.Printf("[memparse] %s: %d items (%.1fs)", name, count, elapsed.Seconds())
}

// --- DuckDB inserters: mirror the Volatility3 column layout exactly. ---

func insertProcess(db *sql.DB, p *ProcessInfo) {
	if db == nil {
		return
	}
	var ct, et any
	if !p.CreateTS.IsZero() {
		ct = p.CreateTS
	}
	if !p.ExitTS.IsZero() {
		et = p.ExitTS
	}
	_, err := db.Exec(
		`INSERT INTO mem_pslist (pid, ppid, name, mem_offset, threads, handles, wow64, create_time, exit_time)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		int64(p.PID), int64(p.PPID), p.Name, fmt.Sprintf("0x%X", p.EProcBase),
		int64(0), int64(0), false, ct, et,
	)
	if err != nil {
		log.Printf("[memparse] insert pslist pid=%d: %v", p.PID, err)
	}
}

func insertPsScan(db *sql.DB, p *ProcessInfo) {
	if db == nil {
		return
	}
	var ct, et any
	if !p.CreateTS.IsZero() {
		ct = p.CreateTS
	}
	if !p.ExitTS.IsZero() {
		et = p.ExitTS
	}
	_, err := db.Exec(
		`INSERT INTO mem_psscan (pid, ppid, name, mem_offset, create_time, exit_time, stale_pool) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		int64(p.PID), int64(p.PPID), p.Name, fmt.Sprintf("0x%X", p.EProcBase), ct, et, p.StalePool,
	)
	if err != nil {
		log.Printf("[memparse] insert psscan pid=%d: %v", p.PID, err)
	}
}

func insertCmdLine(db *sql.DB, p *ProcessInfo) {
	if db == nil {
		return
	}
	if p.CmdLine == "" && p.ImagePath == "" {
		return
	}
	cmd := p.CmdLine
	if cmd == "" {
		cmd = p.ImagePath
	}
	_, err := db.Exec(
		`INSERT INTO mem_cmdline (pid, name, cmdline) VALUES (?, ?, ?)`,
		int64(p.PID), p.Name, cmd,
	)
	if err != nil {
		log.Printf("[memparse] insert cmdline pid=%d: %v", p.PID, err)
	}
}

func insertNetConn(db *sql.DB, c *NetConn) {
	if db == nil {
		return
	}
	var created any
	if !c.CreateTime.IsZero() {
		created = c.CreateTime
	}
	_, err := db.Exec(
		`INSERT INTO mem_netscan (mem_offset, proto, local_addr, local_port, remote_addr, remote_port, "state", pid, name, created)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		fmt.Sprintf("0x%X", c.Offset), c.Proto,
		c.LocalAddr, int64(c.LocalPort),
		c.RemoteAddr, int64(c.RemotePort),
		c.State, int64(c.PID), c.Owner, created,
	)
	if err != nil {
		log.Printf("[memparse] insert netscan: %v", err)
	}
}

func insertModule(db *sql.DB, m *ModuleInfo) {
	if db == nil {
		return
	}
	name := m.BaseName
	if name == "" {
		name = m.FullName
	}
	_, err := db.Exec(
		`INSERT INTO mem_modules (pid, name, base, size, path) VALUES (?, ?, ?, ?, ?)`,
		int64(0), name, fmt.Sprintf("0x%X", m.Base), int64(m.Size), m.FullName,
	)
	if err != nil {
		log.Printf("[memparse] insert module %q: %v", name, err)
	}
}

func insertMalfind(db *sql.DB, h *MalfindHit) {
	if db == nil {
		return
	}
	_, err := db.Exec(
		`INSERT INTO mem_malfind (pid, name, address, size, reason, vad_tag, hexdump, disasm)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		int64(h.PID), h.Name, fmt.Sprintf("0x%X", h.Address), int64(h.Size),
		h.Reason, h.VadTag, h.Hexdump, h.Disasm,
	)
	if err != nil {
		log.Printf("[memparse] insert malfind pid=%d: %v", h.PID, err)
	}
}

func insertSysInfo(db *sql.DB, key, value string) {
	if db == nil {
		return
	}
	// Table may not exist in case files created before this schema entry was added.
	db.Exec(`CREATE TABLE IF NOT EXISTS mem_sysinfo (key TEXT, value TEXT)`) //nolint:errcheck
	_, _ = db.Exec(`INSERT INTO mem_sysinfo (key, value) VALUES (?, ?)`, key, value)
}
