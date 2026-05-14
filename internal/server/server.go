package server

import (
	"database/sql"
	"embed"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	_ "github.com/marcboeker/go-duckdb"
	"forensiq/internal/detect"
	"forensiq/internal/parsers"
	"forensiq/internal/parsers/memparse"
	"forensiq/internal/sigma"
	"forensiq/internal/volatility"
)

//go:embed web2/index.html
var webFS embed.FS

var db *sql.DB
var currentRAMPath string
var currentCasePath string
var currentDB *sql.DB

func Start(casePath, ramPath string, port int) error {
	var err error
	db, err = sql.Open("duckdb", filepath.ToSlash(casePath))
	if err != nil {
		return fmt.Errorf("open case: %w", err)
	}
	currentDB = db
	currentCasePath = casePath
	defer db.Close()

	// Ensure case_notes table exists for analyst annotations
	initCaseNotes()

	if ramPath != "" {
		currentRAMPath = ramPath
		log.Printf("RAM path provided: %s — starting Volatility3 in background...", ramPath)
		go runRAMAnalysis(db, ramPath)
	}

	// Auto-run detectors if ioc_indicators has no detect: results yet
	row := db.QueryRow(`SELECT COUNT(*) FROM ioc_indicators WHERE source LIKE 'detect:%'`)
	var iocCount int64
	if row.Scan(&iocCount) == nil && iocCount == 0 {
		log.Print("ioc_indicators empty — running built-in detectors...")
		if _, err := detect.RunAll(db); err != nil {
			log.Printf("auto-detect: %v", err)
		}
		if dir := findSigmaRulesDir(); dir != "" {
			if rules, _ := sigma.LoadDir(dir); len(rules) > 0 {
				log.Printf("Running %d SIGMA rules from %s", len(rules), dir)
				sigma.RunAll(db, rules) //nolint:errcheck
			}
		}
	}

	// Pre-warm the timeline cache in background so the first UI load is fast.
	WarmTimelineCache()

	mux := http.NewServeMux()
	mux.HandleFunc("/", serveSPA)
	mux.HandleFunc("/api/run-detect", handleRunDetect)
	mux.HandleFunc("/api/summary", handleSummary)
	mux.HandleFunc("/api/detections", handleDetections)
	mux.HandleFunc("/api/detection-hits", handleDetectionHits)
	mux.HandleFunc("/api/processes", handleProcesses)
	mux.HandleFunc("/api/network", handleNetwork)
	mux.HandleFunc("/api/events", handleEvents)
	mux.HandleFunc("/api/timeline", handleTimeline)
	mux.HandleFunc("/api/search", handleSearch)
	mux.HandleFunc("/api/persistence", handlePersistence)
	mux.HandleFunc("/api/malfind", handleMalfind)
	mux.HandleFunc("/api/persistence-ioc", handlePersistenceIoc)
	mux.HandleFunc("/api/proc-creation", handleProcCreation)
	mux.HandleFunc("/api/sysmon-process", handleSysmonProcess)
	mux.HandleFunc("/api/sysmon-network", handleSysmonNetwork)
	mux.HandleFunc("/api/sysmon-dns", handleSysmonDns)
	mux.HandleFunc("/api/sysmon-imageload", handleSysmonImageLoad)
	mux.HandleFunc("/api/user-activity", handleUserActivity)
	mux.HandleFunc("/api/user-detail", handleUserDetail)
	mux.HandleFunc("/api/pivot", handlePivot)
	mux.HandleFunc("/api/event-context", handleEventContext)
	mux.HandleFunc("/api/event-lookup", handleEventLookup)
	mux.HandleFunc("/api/activity", handleActivity)
	mux.HandleFunc("/api/attack-summary", handleAttackSummary)
	mux.HandleFunc("/api/prefetch", handlePrefetch)
	mux.HandleFunc("/api/prefetch-detail", handlePrefetchDetail)
	mux.HandleFunc("/api/amcache", handleAmcache)
	mux.HandleFunc("/api/mem-modules", handleMemModules)
	mux.HandleFunc("/api/hidden-procs", handleHiddenProcs)
	mux.HandleFunc("/api/ps-scripts", handlePsScripts)
	mux.HandleFunc("/api/browser", handleBrowser)
	mux.HandleFunc("/api/lateral", handleLateral)
	mux.HandleFunc("/api/registry", handleRegistry)
	mux.HandleFunc("/api/execution", handleExecution)
	mux.HandleFunc("/api/ioc-all", handleIocAll)
	mux.HandleFunc("/api/defenders", handleDefenders)
	mux.HandleFunc("/api/hashes", handleHashes)
	mux.HandleFunc("/api/auth", handleAuth)
	mux.HandleFunc("/api/auth-stats", handleAuthStats)
	mux.HandleFunc("/api/events-stats", handleEventsStats)
	mux.HandleFunc("/api/files", handleFiles)
	mux.HandleFunc("/api/report", handleReport)
	mux.HandleFunc("/api/notes", handleNotes)
	mux.HandleFunc("/api/triage", handleTriage)
	mux.HandleFunc("/api/activity-histogram", handleActivityHistogram)
	mux.HandleFunc("/api/proc-deep", handleProcDeep)
	mux.HandleFunc("/api/ioc-import", handleIocImport)
	mux.HandleFunc("/api/ioc-extracted", handleIocExtracted)
	mux.HandleFunc("/api/ioc-extract-run", handleIocExtractedRun)
	mux.HandleFunc("/api/graph", handleGraph)
	mux.HandleFunc("/api/chain", handleChain)
	mux.HandleFunc("/api/hunt-query", handleHuntQuery)
	mux.HandleFunc("/api/lnk", handleLnk)
	mux.HandleFunc("/api/jumplists", handleJumplists)
	mux.HandleFunc("/api/recycle-bin", handleRecycleBin)
	mux.HandleFunc("/api/shellbags", handleShellbags)
	mux.HandleFunc("/api/usnjrnl", handleUsnjrnl)
	mux.HandleFunc("/api/rerun-ram", handleRerunRAM)
	mux.HandleFunc("/api/mem-summary", handleMemSummary)
	mux.HandleFunc("/api/emails", handleEmails)
	mux.HandleFunc("/api/email-detail", handleEmailDetail)
	mux.HandleFunc("/api/anydesk", handleAnyDesk)
	mux.HandleFunc("/api/wer-crashes", handleWerCrashes)
	mux.HandleFunc("/api/srum", handleSrum)
	mux.HandleFunc("/api/bam-dam", handleBamDam)
	mux.HandleFunc("/api/registry-mru", handleRegistryMRU)
	mux.HandleFunc("/api/ntds", handleNTDS)
	mux.HandleFunc("/api/bits", handleBits)
	mux.HandleFunc("/api/usb-history", handleUsbHistory)
	mux.HandleFunc("/api/network-adapters", handleNetworkAdapters)
	mux.HandleFunc("/api/installed-software", handleInstalledSoftware)
	mux.HandleFunc("/api/merge-artifact", handleMergeArtifact)

	addr := fmt.Sprintf(":%d", port)
	url := fmt.Sprintf("http://localhost:%d", port)
	log.Printf("forensiq serve  →  %s  (case: %s)", url, casePath)
	openBrowser(url)

	return http.ListenAndServe(addr, mux)
}

func serveSPA(w http.ResponseWriter, r *http.Request) {
	data, _ := webFS.ReadFile("web2/index.html")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(data)
}

func openBrowser(url string) {
	var cmd string
	var args []string
	switch runtime.GOOS {
	case "windows":
		cmd = "cmd"
		args = []string{"/c", "start", url}
	case "darwin":
		cmd = "open"
		args = []string{url}
	default:
		cmd = "xdg-open"
		args = []string{url}
	}
	go exec.Command(cmd, args...).Start() //nolint:errcheck
}

func jsonOK(w http.ResponseWriter, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		log.Printf("jsonOK marshal error: %v (type: %T)", err, v)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"marshal failed"}`)) //nolint:errcheck
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Write(append(b, '\n')) //nolint:errcheck
}

func jsonErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg}) //nolint:errcheck
}

func queryRows(query string, args ...any) ([]map[string]any, error) {
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}

	var result []map[string]any
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			continue
		}
		row := make(map[string]any, len(cols))
		for i, col := range cols {
			row[col] = safeVal(vals[i])
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

func safeQuery(query string, args ...any) []map[string]any {
	rows, err := queryRows(query, args...)
	if err != nil || rows == nil {
		return []map[string]any{}
	}
	return rows
}

func countFirst(rows []map[string]any) int64 {
	if len(rows) == 0 {
		return 0
	}
	for _, v := range rows[0] {
		return toInt64(v)
	}
	return 0
}

func toInt64(v any) int64 {
	switch x := v.(type) {
	case int64:
		return x
	case int32:
		return int64(x)
	case int:
		return int64(x)
	case float64:
		return int64(x)
	}
	return 0
}

// safeVal converts values that are not JSON-safe into safe equivalents.
// Specifically, time.Time with year outside [0,9999] cannot be marshaled by Go's json package.
func safeVal(v any) any {
	if t, ok := v.(time.Time); ok {
		y := t.Year()
		if y < 0 || y > 9999 {
			return nil
		}
	}
	return v
}

func findSigmaRulesDir() string {
	if exe, err := os.Executable(); err == nil {
		if c := filepath.Join(filepath.Dir(exe), "rules", "sigma"); isDirExist(c) {
			return c
		}
	}
	if wd, err := os.Getwd(); err == nil {
		if c := filepath.Join(wd, "rules", "sigma"); isDirExist(c) {
			return c
		}
	}
	return ""
}

func isDirExist(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.IsDir()
}

func handleRerunRAM(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonErr(w, 405, "POST required")
		return
	}
	ramPath := r.URL.Query().Get("path")
	if ramPath == "" {
		ramPath = currentRAMPath
	}
	if ramPath == "" {
		jsonErr(w, 400, "no RAM path — provide ?path= or start server with --ram")
		return
	}
	currentRAMPath = ramPath
	go runRAMAnalysis(db, ramPath)
	jsonOK(w, map[string]any{"status": "started", "path": ramPath})
}

func handleMemSummary(w http.ResponseWriter, r *http.Request) {
	counts := map[string]int64{
		"pslist":     countFirst(safeQuery("SELECT COUNT(*) AS c FROM mem_pslist")),
		"netscan":    countFirst(safeQuery("SELECT COUNT(*) AS c FROM mem_netscan")),
		"malfind":    countFirst(safeQuery("SELECT COUNT(*) AS c FROM mem_malfind")),
		"modules":    countFirst(safeQuery("SELECT COUNT(*) AS c FROM mem_modules")),
		"cmdline":    countFirst(safeQuery("SELECT COUNT(*) AS c FROM mem_cmdline")),
		"psscan":     countFirst(safeQuery("SELECT COUNT(*) AS c FROM mem_psscan")),
		"driverscan": countFirst(safeQuery("SELECT COUNT(*) AS c FROM mem_driverscan")),
	}
	hidden := countFirst(safeQuery(`
		SELECT COUNT(*) AS c FROM mem_psscan s
		LEFT JOIN mem_pslist p ON s.pid = p.pid
		WHERE p.pid IS NULL
		  AND CAST(s.pid AS BIGINT) BETWEEN 4 AND 131072
		  AND LENGTH(s.name) >= 3
	`))
	jsonOK(w, map[string]any{
		"counts":     counts,
		"hidden":     hidden,
		"ram_path":   currentRAMPath,
		"has_memory": counts["pslist"] > 0,
	})
}

func runRAMAnalysis(database *sql.DB, ramPath string) {
	log.Printf("[RAM] Starting native memory analysis: %s", ramPath)
	memTables := []string{
		"mem_pslist", "mem_psscan", "mem_cmdline", "mem_netscan", "mem_filescan",
		"mem_handles", "mem_modules", "mem_driverscan", "mem_malfind", "mem_hivelist", "mem_sysinfo",
	}
	for _, t := range memTables {
		database.Exec("DELETE FROM " + t) //nolint:errcheck
	}

	ch := make(chan parsers.Progress, 64)
	go func() {
		for p := range ch {
			if p.Err != nil {
				log.Printf("[RAM] %s err: %v", p.Parser, p.Err)
			} else if p.Done {
				log.Printf("[RAM] %s: %d items (%.1fs)", p.Parser, p.Count, p.Elapsed.Seconds())
			}
		}
	}()

	if err := memparse.Parse(ramPath, database, ch); err != nil {
		log.Printf("[RAM] native parser failed: %v — trying Volatility3", err)
		vol := volatility.New(ramPath)
		if !vol.IsAvailable() {
			log.Printf("[RAM] Volatility3 not found in PATH — skipping memory analysis")
			close(ch)
			return
		}
		var wg sync.WaitGroup
		for _, plugin := range vol.Plugins() {
			plugin := plugin
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := vol.RunPlugin(plugin, database, ch); err != nil {
					log.Printf("[RAM] vol/%s: %v", plugin, err)
				} else {
					log.Printf("[RAM] vol/%s: done", plugin)
				}
			}()
		}
		wg.Wait()
	}
	close(ch)
	log.Printf("[RAM] Memory analysis complete")

	// Re-run all detectors so RAM-based rules (hidden_process, suspicious_ppid,
	// masquerade_path, malfind_injection) fire against the freshly populated mem_* tables.
	log.Printf("[RAM] Re-running detectors with RAM data...")
	if _, err := detect.RunAll(database); err != nil {
		log.Printf("[RAM] detect.RunAll: %v", err)
	} else {
		log.Printf("[RAM] Detectors complete")
	}
}
