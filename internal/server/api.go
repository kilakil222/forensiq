package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"forensiq/internal/detect"
	iocext "forensiq/internal/ioc"
	"forensiq/internal/report"
	"forensiq/internal/sigma"
)

func handleSummary(w http.ResponseWriter, r *http.Request) {
	tables := []string{
		"prefetch", "shimcache", "amcache", "mft", "usnjrnl",
		"evtx_events", "auth_events", "persistence", "services",
		"scheduled_tasks", "mem_pslist", "mem_netscan", "ioc_indicators",
		"mem_malfind", "defender_events", "proc_creation", "ps_scriptblock",
		"lnk_files", "jumplists", "recycle_bin", "shellbags",
	}
	counts := make(map[string]int64)
	for _, t := range tables {
		rows := safeQuery(fmt.Sprintf("SELECT COUNT(*) AS c FROM %s", t))
		if len(rows) > 0 {
			counts[t] = toInt64(rows[0]["c"])
		}
	}

	high := countFirst(safeQuery("SELECT COUNT(*) AS c FROM ioc_indicators WHERE confidence = 'HIGH'"))
	med := countFirst(safeQuery("SELECT COUNT(*) AS c FROM ioc_indicators WHERE confidence = 'MED'"))

	topDets := safeQuery(`
		SELECT source, COUNT(*) AS hits, MAX(confidence) AS severity, MIN(first_seen) AS first_seen,
		       MAX(COALESCE(notes,'')) AS notes, MAX(COALESCE(related_campaign,'')) AS technique,
		       CASE
		         WHEN position('—' IN COALESCE(MAX(notes),'')) > 1
		         THEN LEFT(MAX(notes), position('—' IN MAX(notes)) - 2)
		         ELSE NULL
		       END AS title
		FROM ioc_indicators
		GROUP BY source
		ORDER BY CASE MAX(confidence) WHEN 'HIGH' THEN 0 ELSE 1 END, hits DESC
		LIMIT 15
	`)

	caseMeta := safeQuery("SELECT name, os_type, analyst, created_at FROM case_meta LIMIT 1")

	hints := map[string]int64{
		"hollow_process":    countFirst(safeQuery(`SELECT COUNT(*) AS c FROM ioc_indicators WHERE source LIKE '%hollow%'`)),
		"defender_disabled": countFirst(safeQuery(`SELECT COUNT(*) AS c FROM ioc_indicators WHERE source LIKE '%defender_tamper%'`)),
		"log_cleared":       countFirst(safeQuery(`SELECT COUNT(*) AS c FROM ioc_indicators WHERE source LIKE '%log_clear%'`)),
		"pass_the_hash":     countFirst(safeQuery(`SELECT COUNT(*) AS c FROM ioc_indicators WHERE source LIKE '%pass_the_hash%'`)),
		"new_service":       countFirst(safeQuery(`SELECT COUNT(*) AS c FROM ioc_indicators WHERE source LIKE '%new_service%'`)),
		"kerberoasting":     countFirst(safeQuery(`SELECT COUNT(*) AS c FROM ioc_indicators WHERE source LIKE '%kerberoasting%'`)),
		"dcsync":            countFirst(safeQuery(`SELECT COUNT(*) AS c FROM ioc_indicators WHERE source LIKE '%dcsync%'`)),
		"ext_connections": countFirst(safeQuery(`
			SELECT COUNT(*) AS c FROM mem_netscan
			WHERE state = 'ESTABLISHED'
			AND remote_addr NOT IN ('0.0.0.0','127.0.0.1','*','-','')
			AND remote_addr NOT LIKE '10.%' AND remote_addr NOT LIKE '192.168.%'
		`)),
		"auth_failures":  countFirst(safeQuery(`SELECT COUNT(*) AS c FROM auth_events WHERE event_id = 4625`)),
		"cleartext_pass": countFirst(safeQuery(`SELECT COUNT(*) AS c FROM auth_events WHERE logon_type = 8`)),
	}

	// Sanity-filter timestamps: corrupt EVTX records sometimes carry dates like
	// 1715-03-04 or 2105-... — clamp to a realistic Windows-era window.
	const tsBounds = `timestamp >= '1995-01-01' AND timestamp <= '2099-12-31'`
	const lrBounds = `last_run  >= '1995-01-01' AND last_run  <= '2099-12-31'`
	timeRange := safeQuery(`
		SELECT MIN(first_event) AS first_event, MAX(last_event) AS last_event FROM (
			SELECT MIN(timestamp) AS first_event, MAX(timestamp) AS last_event FROM evtx_events   WHERE timestamp IS NOT NULL AND ` + tsBounds + `
			UNION ALL SELECT MIN(timestamp), MAX(timestamp) FROM auth_events     WHERE timestamp IS NOT NULL AND ` + tsBounds + `
			UNION ALL SELECT MIN(timestamp), MAX(timestamp) FROM defender_events WHERE timestamp IS NOT NULL AND ` + tsBounds + `
			UNION ALL SELECT MIN(last_run),  MAX(last_run)  FROM prefetch        WHERE last_run  IS NOT NULL AND ` + lrBounds + `
		)
	`)

	var topProcs []map[string]any
	existing := getExistingTables()
	// Extract filename from path using reverse()+POSITION() — works on all DuckDB versions
	const filenameExpr = `reverse(CASE
		WHEN POSITION('/' IN reverse(lower(image))) > 0
		THEN LEFT(reverse(lower(image)), POSITION('/' IN reverse(lower(image)))-1)
		WHEN POSITION(chr(92) IN reverse(lower(image))) > 0
		THEN LEFT(reverse(lower(image)), POSITION(chr(92) IN reverse(lower(image)))-1)
		ELSE lower(image) END)`
	if existing["proc_creation"] {
		topProcs = safeQuery(`
			SELECT ` + filenameExpr + ` AS name,
			       COUNT(*) AS cnt, MAX(timestamp) AS last_seen
			FROM proc_creation
			WHERE image IS NOT NULL AND image != ''
			GROUP BY 1 ORDER BY cnt DESC LIMIT 10
		`)
	} else if existing["sysmon_process"] {
		topProcs = safeQuery(`
			SELECT ` + filenameExpr + ` AS name,
			       COUNT(*) AS cnt, MAX(utc_time) AS last_seen
			FROM sysmon_process
			WHERE image IS NOT NULL AND image != ''
			GROUP BY 1 ORDER BY cnt DESC LIMIT 10
		`)
	}

	topAuth := safeQuery(`
		SELECT "user", COUNT(*) AS cnt,
		       SUM(CASE WHEN event_id=4625 THEN 1 ELSE 0 END) AS failures,
		       SUM(CASE WHEN event_id=4624 THEN 1 ELSE 0 END) AS successes
		FROM auth_events
		WHERE "user" IS NOT NULL AND "user" != '' AND "user" NOT LIKE '%$'
		  AND "user" NOT ILIKE 'SYSTEM'
		  AND "user" NOT ILIKE 'LOCAL SERVICE'
		  AND "user" NOT ILIKE 'NETWORK SERVICE'
		  AND "user" NOT ILIKE 'ANONYMOUS LOGON'
		  AND "user" NOT ILIKE 'DWM-%'
		  AND "user" NOT ILIKE 'UMFD-%'
		  AND "user" NOT ILIKE 'Window Manager'
		GROUP BY 1
		ORDER BY cnt DESC
		LIMIT 10
	`)

	jsonOK(w, map[string]any{
		"meta":            caseMeta,
		"artifact_counts": counts,
		"detections": map[string]any{
			"high":  high,
			"med":   med,
			"total": high + med,
		},
		"top_detections": topDets,
		"hints":          hints,
		"time_range":     timeRange,
		"top_processes":  topProcs,
		"top_auth":       topAuth,
	})
}

func handleIocAll(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	t := r.URL.Query().Get("type")
	where := " WHERE 1=1"
	args := []any{}
	if q != "" {
		like := "%" + q + "%"
		where += " AND (value ILIKE ? OR source ILIKE ? OR notes ILIKE ?)"
		args = append(args, like, like, like)
	}
	if t != "" {
		where += " AND type = ?"
		args = append(args, t)
	}
	rows := safeQuery(`SELECT type, value, source, confidence, notes, first_seen, related_campaign
	                   FROM ioc_indicators`+where+`
	                   ORDER BY CASE confidence WHEN 'HIGH' THEN 0 ELSE 1 END, first_seen DESC
	                   LIMIT 2000`, args...)
	jsonOK(w, rows)
}

// builtinDetectTitles maps detect:* source IDs to human-readable names.
var builtinDetectTitles = map[string]string{
	"detect:defender_tamper":       "Defender Antivirus Tampered",
	"detect:defender_detection":    "Defender Malware Detection",
	"detect:log_cleared":           "Event Log Cleared (Anti-Forensics)",
	"detect:new_service":           "New Service Installed",
	"detect:privilege_group":       "Privileged Group Membership Change",
	"detect:user_created":          "Local User Account Created",
	"detect:pass_the_hash":         "Pass-the-Hash Attack",
	"detect:explicit_credentials":  "Explicit Credential Use (T1550.002)",
	"detect:exe_user_docs":         "Executable in User Documents/Desktop",
	"detect:pif_scr_user":          "PIF/SCR File in User Directory",
	"detect:hta_script_user":       "HTA/Script File in User Directory",
	"detect:process_masquerade":    "Process Name Masquerading",
	"detect:hollow_process":        "Process Hollowing Candidate",
	"detect:sticky_keys":           "Accessibility Feature Hijacked (Sticky Keys)",
	"detect:amcache_ghost":         "Ghost Executable (Amcache without MFT)",
	"detect:shimcache_suspicious":  "Suspicious Shimcache Path",
	"detect:prefetch_suspicious":   "Suspicious Prefetch Entry",
	"detect:ram_tools":             "Attack Tools in Memory",
	"detect:ram_net_suspicious":    "Suspicious Network Connection (RAM)",
	"detect:lateral_psexec":        "PsExec Lateral Movement",
	"detect:lateral_wmi":           "WMI Lateral Movement",
	"detect:sysmon_office_spawn":   "Office Application Spawned Shell",
	"detect:sysmon_encoded_ps":     "Encoded PowerShell Execution",
	"detect:sysmon_lolbin":         "LOLBin Execution (Sysmon)",
	"detect:sysmon_susp_path":      "Execution from Suspicious Path (Sysmon)",
	"detect:sysmon_network_external": "LOLBin/Shell External Connection",
	"detect:sysmon_dns_suspicious": "Suspicious DNS Query (Sysmon)",
	"detect:sysmon_unsigned_dll":   "Unsigned DLL Loaded from Writable Path",
	"detect:sysmon_masquerade_sysname": "Process Masquerading System Name (Sysmon)",
	"detect:proc_create_lolbin":    "LOLBin Process Created (4688)",
	"detect:proc_create_susp_parent": "Suspicious Parent-Child Process Relationship",
	"detect:proc_create_susp_path": "Process Created from Suspicious Path (4688)",
	"detect:dcsync":                "DCSync Attack (Credential Dump)",
	"detect:kerberoasting":         "Kerberoasting (RC4 Ticket Request)",
}

func handleDetections(w http.ResponseWriter, r *http.Request) {
	rows := safeQuery(`
		SELECT source, confidence AS severity, COUNT(*) AS hits,
		       MIN(first_seen) AS first_ts, MAX(first_seen) AS last_ts,
		       MAX(related_campaign) AS related_campaign,
		       CASE
		         WHEN position('—' IN COALESCE(MAX(notes),'')) > 1
		         THEN LEFT(MAX(notes), position('—' IN MAX(notes)) - 2)
		         ELSE NULL
		       END AS title
		FROM ioc_indicators
		GROUP BY source, confidence
		ORDER BY CASE confidence WHEN 'HIGH' THEN 0 ELSE 1 END, hits DESC
	`)
	// Fill in human-readable titles for builtin detect:* rules that lack them
	for _, row := range rows {
		if title, _ := row["title"].(string); title == "" {
			if src, _ := row["source"].(string); src != "" {
				if friendly, ok := builtinDetectTitles[src]; ok {
					row["title"] = friendly
				}
			}
		}
	}
	jsonOK(w, rows)
}

func handleDetectionHits(w http.ResponseWriter, r *http.Request) {
	source := r.URL.Query().Get("source")
	if source == "" {
		jsonErr(w, 400, "source required")
		return
	}
	rows := safeQuery(`
		SELECT type, value, confidence, related_campaign, first_seen, notes
		FROM ioc_indicators
		WHERE source = ?
		ORDER BY first_seen DESC
		LIMIT 500
	`, source)
	jsonOK(w, rows)
}

func handleRunDetect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonErr(w, 405, "POST required")
		return
	}
	results, err := detect.RunAll(db)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	detectHits := int64(0)
	for _, res := range results {
		detectHits += res.Hits
	}

	sigmaHits, sigmaRules := int64(0), 0
	if dir := findSigmaRulesDir(); dir != "" {
		rules, _ := sigma.LoadDir(dir)
		sigmaRules = len(rules)
		if len(rules) > 0 {
			if sRes, sErr := sigma.RunAll(db, rules); sErr == nil {
				for _, sr := range sRes {
					sigmaHits += sr.Hits
				}
			}
		}
	}

	jsonOK(w, map[string]any{
		"detect_hits": detectHits,
		"sigma_hits":  sigmaHits,
		"sigma_rules": sigmaRules,
	})
}

func handleProcesses(w http.ResponseWriter, r *http.Request) {
	rows := safeQuery(`
		SELECT p.pid, p.ppid, p.name, p.create_time, p.exit_time,
		       p.threads, p.handles, p.wow64,
		       c.cmdline,
		       pf.run_count, pf.last_run AS prefetch_last_run,
		       a.sha256 AS amcache_sha256, a.compile_time AS amcache_compile_time,
		       CASE WHEN pf.filename IS NOT NULL THEN 1 ELSE 0 END AS in_prefetch,
		       CASE WHEN a.path IS NOT NULL THEN 1 ELSE 0 END AS in_amcache,
		       pc.pc_count, pc.pc_user, pc.pc_integrity, pc.pc_cmdline, pc.pc_parent
		FROM mem_pslist p
		LEFT JOIN mem_cmdline c ON p.pid = c.pid
		LEFT JOIN prefetch pf ON lower(p.name) = lower(pf.filename)
		LEFT JOIN amcache a ON lower(p.name) = lower(split_part(a.path, '\', -1))
		LEFT JOIN (
			SELECT lower(split_part(image, '\', -1)) AS img_name,
			       COUNT(*) AS pc_count,
			       MAX(user_name) AS pc_user,
			       MAX(integrity_level) AS pc_integrity,
			       MAX(cmdline) AS pc_cmdline,
			       MAX(split_part(parent_image, '\', -1)) AS pc_parent
			FROM proc_creation
			WHERE image IS NOT NULL
			GROUP BY lower(split_part(image, '\', -1))
		) pc ON lower(p.name) = pc.img_name
		ORDER BY p.pid
	`)
	jsonOK(w, rows)
}

func handleNetwork(w http.ResponseWriter, r *http.Request) {
	rows := safeQuery(`
		SELECT n.pid, n.name, n.proto, n.local_addr, n.local_port,
		       n.remote_addr, n.remote_port, n."state", n.created,
		       i.type AS ioc_type, i.source AS ioc_source,
		       i.related_campaign, i.confidence AS ioc_confidence, i.notes AS ioc_notes
		FROM mem_netscan n
		LEFT JOIN ioc_indicators i ON n.remote_addr = i.value
		ORDER BY CASE WHEN i.confidence IS NOT NULL THEN 0 ELSE 1 END, n.pid
	`)
	jsonOK(w, rows)
}

func handleEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	eventID := q.Get("event_id")
	channel := q.Get("channel")
	search := q.Get("q")

	query := `SELECT event_id, channel, timestamp, computer, user_sid, provider, message
		FROM evtx_events WHERE 1=1`
	args := []any{}

	if eventID != "" {
		query += " AND CAST(event_id AS VARCHAR) = ?"
		args = append(args, eventID)
	}
	if eventIDs := q.Get("event_ids"); eventIDs != "" {
		var parts []string
		for _, id := range strings.Split(eventIDs, ",") {
			id = strings.TrimSpace(id)
			if _, err := strconv.Atoi(id); err == nil {
				parts = append(parts, id)
			}
		}
		if len(parts) > 0 {
			query += " AND event_id IN (" + strings.Join(parts, ",") + ")"
		}
	}
	if channel != "" {
		query += " AND channel ILIKE ?"
		args = append(args, "%"+channel+"%")
	}
	if search != "" {
		query += " AND (message ILIKE ? OR user_sid ILIKE ? OR computer ILIKE ?)"
		args = append(args, "%"+search+"%", "%"+search+"%", "%"+search+"%")
	}
	query += " ORDER BY timestamp DESC LIMIT 500"

	rows := safeQuery(query, args...)
	jsonOK(w, rows)
}

// timelineSources defines each timeline source: table name, timestamp col, and SELECT body.
var timelineSources = []struct {
	table string
	sel   string
}{
	{"evtx_events", `SELECT timestamp AS ts, 'evtx' AS source, CAST(event_id AS VARCHAR) AS category, COALESCE(message,'') AS detail, computer AS extra FROM evtx_events WHERE timestamp IS NOT NULL`},
	{"auth_events", `SELECT timestamp AS ts, 'auth' AS source, CAST(event_id AS VARCHAR) AS category, COALESCE("user",'') AS detail, COALESCE(src_ip,'') AS extra FROM auth_events WHERE timestamp IS NOT NULL`},
	{"defender_events", `SELECT timestamp AS ts, 'defender' AS source, severity AS category, COALESCE(threat_name,'') AS detail, COALESCE(path,'') AS extra FROM defender_events WHERE timestamp IS NOT NULL`},
	{"ioc_indicators", `SELECT first_seen AS ts, 'detect' AS source, confidence AS category, ioc_indicators.source AS detail, value AS extra FROM ioc_indicators WHERE first_seen IS NOT NULL`},
	{"prefetch", `SELECT last_run AS ts, 'prefetch' AS source, filename AS category, CAST(run_count AS VARCHAR)||' runs' AS detail, path AS extra FROM prefetch WHERE last_run IS NOT NULL`},
	{"amcache", `SELECT first_seen AS ts, 'amcache' AS source, 'exec' AS category, path AS detail, COALESCE(sha256,'') AS extra FROM amcache WHERE first_seen IS NOT NULL`},
	{"mft", `SELECT modified AS ts, 'mft' AS source, 'file' AS category, path AS detail, CAST(COALESCE(size,0) AS VARCHAR) AS extra FROM mft WHERE modified IS NOT NULL AND is_dir=false AND (path ILIKE '%\Temp\%.exe' OR path ILIKE '%\Temp\%.dll' OR path ILIKE '%\AppData\Roaming\%.exe' OR path ILIKE '%\Downloads\%.exe' OR path ILIKE '%\ProgramData\%.exe' OR path ILIKE '%\Temp\%.ps1')`},
	{"proc_creation", `SELECT timestamp AS ts, 'proc_4688' AS source, COALESCE(image,'') AS category, COALESCE(cmdline,'') AS detail, COALESCE(user_name,'') AS extra FROM proc_creation WHERE timestamp IS NOT NULL`},
	{"sysmon_process", `SELECT timestamp AS ts, 'sysmon' AS source, COALESCE(image,'') AS category, COALESCE(cmdline,'') AS detail, COALESCE(user_name,'') AS extra FROM sysmon_process WHERE timestamp IS NOT NULL`},
	{"sysmon_network",    `SELECT timestamp AS ts, 'sysmon_net' AS source, COALESCE(image,'') AS category, COALESCE(dst_ip,'')||':'||CAST(COALESCE(dst_port,0) AS VARCHAR) AS detail, COALESCE(dst_host,'') AS extra FROM sysmon_network WHERE timestamp IS NOT NULL`},
	{"sysmon_imageload",  `SELECT timestamp AS ts, 'dll_load' AS source, COALESCE(image,'') AS category, COALESCE(image_loaded,'') AS detail, COALESCE(CAST(signed AS VARCHAR)||' '||COALESCE(signature,''),'') AS extra FROM sysmon_imageload WHERE timestamp IS NOT NULL`},
	{"browser_history", `SELECT visit_time AS ts, 'browser' AS source, browser AS category, url AS detail, COALESCE(title,'') AS extra FROM browser_history WHERE visit_time IS NOT NULL`},
	{"lateral_movement", `SELECT timestamp AS ts, 'lateral' AS source, COALESCE(type,'') AS category, COALESCE("user",'') AS detail, COALESCE(src_host,'')||' → '||COALESCE(dst_host,'') AS extra FROM lateral_movement WHERE timestamp IS NOT NULL`},
	{"ps_scriptblock", `SELECT timestamp AS ts, 'powershell' AS source, 'script' AS category, SUBSTRING(COALESCE(script_text,''),1,120) AS detail, '' AS extra FROM ps_scriptblock WHERE timestamp IS NOT NULL`},
	{"rdp_events", `SELECT timestamp AS ts, 'rdp' AS source, 'rdp' AS category, COALESCE("user",'') AS detail, COALESCE(src_ip,'') AS extra FROM rdp_events WHERE timestamp IS NOT NULL`},
	{"smb_events", `SELECT timestamp AS ts, 'smb' AS source, COALESCE(operation,'') AS category, COALESCE("user",'') AS detail, COALESCE(src_ip,'')||':'||COALESCE(share,'') AS extra FROM smb_events WHERE timestamp IS NOT NULL`},
	{"persistence", `SELECT modified AS ts, 'persistence' AS source, COALESCE(type,'') AS category, COALESCE(name,'') AS detail, COALESCE(command,'') AS extra FROM persistence WHERE modified IS NOT NULL`},
	{"lnk_files", `SELECT modified AS ts, 'lnk' AS source, 'lnk' AS category, COALESCE(target_path,'') AS detail, path AS extra FROM lnk_files WHERE modified IS NOT NULL`},
	{"userassist", `SELECT last_run AS ts, 'userassist' AS source, 'exec' AS category, path AS detail, CAST(COALESCE(run_count,0) AS VARCHAR)||' runs' AS extra FROM userassist WHERE last_run IS NOT NULL`},
	{"bam_dam", `SELECT last_run AS ts, 'bam_dam' AS source, source AS category, path AS detail, sid AS extra FROM bam_dam WHERE last_run IS NOT NULL`},
}

var existingTables map[string]bool

func getExistingTables() map[string]bool {
	rows := safeQuery(`SELECT table_name FROM information_schema.tables WHERE table_schema = 'main'`)
	m := make(map[string]bool, len(rows))
	for _, r := range rows {
		if name, ok := r["table_name"].(string); ok {
			m[name] = true
		}
	}
	return m
}

func handleTimeline(w http.ResponseWriter, r *http.Request) {
	filter := r.URL.Query().Get("source")
	q      := r.URL.Query().Get("q")

	if existingTables == nil {
		existingTables = getExistingTables()
	}

	// Per-source row budgets: noisy tables are capped so sparse sources aren't squeezed out.
	srcBudget := func(table string) int {
		switch table {
		case "evtx_events":
			return 3000
		case "auth_events":
			return 1500
		default:
			return 500
		}
	}

	parts := []string{}
	for i, src := range timelineSources {
		if existingTables[src.table] {
			parts = append(parts, fmt.Sprintf(
				"(SELECT ts,source,category,detail,extra FROM (%s) _t%d ORDER BY ts DESC LIMIT %d)",
				src.sel, i, srcBudget(src.table),
			))
		}
	}
	if len(parts) == 0 {
		jsonOK(w, []map[string]any{})
		return
	}

	base := "SELECT ts,source,category,detail,extra FROM (" +
		strings.Join(parts, " UNION ALL ") + ") t WHERE ts IS NOT NULL"

	args := []any{}
	if filter != "" {
		base += " AND source = ?"
		args = append(args, filter)
	}
	if q != "" {
		base += " AND (detail ILIKE ? OR category ILIKE ? OR extra ILIKE ?)"
		like := "%" + q + "%"
		args = append(args, like, like, like)
	}
	base += " ORDER BY ts DESC LIMIT 10000"

	jsonOK(w, safeQuery(base, args...))
}

func handlePrefetch(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	query := `SELECT filename, path, run_count, last_run, volume_paths, sha256, file_refs
	          FROM prefetch`
	args := []any{}
	if q != "" {
		query += " WHERE filename ILIKE ? OR path ILIKE ?"
		args = append(args, "%"+q+"%", "%"+q+"%")
	}
	query += " ORDER BY last_run DESC NULLS LAST LIMIT 2000"
	jsonOK(w, safeQuery(query, args...))
}

func handlePrefetchDetail(w http.ResponseWriter, r *http.Request) {
	filename := strings.TrimSpace(r.URL.Query().Get("filename"))
	if filename == "" {
		jsonErr(w, 400, "filename required")
		return
	}
	like := "%" + filename + "%"
	tables := getExistingTables()
	children := []map[string]any{}
	sysmonChildren := []map[string]any{}
	if tables["proc_creation"] {
		children = safeQuery(
			`SELECT timestamp, image, cmdline, user_name, integrity_level, parent_image
			 FROM proc_creation WHERE parent_image ILIKE ? ORDER BY timestamp LIMIT 200`, like)
	}
	if tables["sysmon_process"] {
		sysmonChildren = safeQuery(
			`SELECT timestamp, image, cmdline, user_name, integrity_level, parent_image
			 FROM sysmon_process WHERE parent_image ILIKE ? ORDER BY timestamp LIMIT 200`, like)
	}
	amcacheInfo := []map[string]any{}
	bamInfo := []map[string]any{}
	if tables["amcache"] {
		amcacheInfo = safeQuery(
			`SELECT first_seen, path, sha256, publisher, compile_time FROM amcache WHERE path ILIKE ? LIMIT 5`, like)
	}
	if tables["bam_dam"] {
		bamInfo = safeQuery(
			`SELECT last_run, path, sid, source FROM bam_dam WHERE path ILIKE ? ORDER BY last_run DESC LIMIT 10`, like)
	}
	jsonOK(w, map[string]any{
		"children":        children,
		"sysmon_children": sysmonChildren,
		"amcache":         amcacheInfo,
		"bam_dam":         bamInfo,
	})
}

func handleSearch(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	if len(q) < 2 {
		jsonErr(w, 400, "query too short")
		return
	}
	like := "%" + q + "%"

	results := map[string][]map[string]any{
		"processes": safeQuery(`
			SELECT 'process' AS kind, p.name AS title,
			       COALESCE(c.cmdline, '') AS detail, CAST(p.pid AS VARCHAR) AS ref
			FROM mem_pslist p LEFT JOIN mem_cmdline c ON p.pid = c.pid
			WHERE p.name ILIKE ? OR c.cmdline ILIKE ?
			LIMIT 50
		`, like, like),
		"prefetch": safeQuery(`
			SELECT 'prefetch' AS kind, filename AS title, path AS detail,
			       CAST(run_count AS VARCHAR) AS ref
			FROM prefetch
			WHERE filename ILIKE ? OR path ILIKE ?
			LIMIT 50
		`, like, like),
		"events": safeQuery(`
			SELECT 'event' AS kind, CAST(event_id AS VARCHAR) AS title,
			       message AS detail, channel AS ref
			FROM evtx_events
			WHERE message ILIKE ? OR user_sid ILIKE ?
			LIMIT 50
		`, like, like),
		"ioc": safeQuery(`
			SELECT 'ioc' AS kind, value AS title, notes AS detail, source AS ref
			FROM ioc_indicators
			WHERE value ILIKE ? OR notes ILIKE ? OR source ILIKE ?
			LIMIT 50
		`, like, like, like),
		"mft": safeQuery(`
			SELECT 'file' AS kind, path AS title, '' AS detail,
			       CAST(size AS VARCHAR) AS ref
			FROM mft WHERE path ILIKE ?
			LIMIT 50
		`, like),
		"persistence": safeQuery(`
			SELECT 'persistence' AS kind, name AS title, command AS detail, type AS ref
			FROM persistence
			WHERE name ILIKE ? OR command ILIKE ? OR key_path ILIKE ?
			LIMIT 50
		`, like, like, like),
		"network": safeQuery(`
			SELECT 'network' AS kind,
			       remote_addr || ':' || CAST(remote_port AS VARCHAR) AS title,
			       name AS detail, proto AS ref
			FROM mem_netscan
			WHERE remote_addr ILIKE ? OR name ILIKE ?
			LIMIT 50
		`, like, like),
		"auth": safeQuery(`
			SELECT 'auth' AS kind, COALESCE(user,'?') AS title,
			       CAST(event_id AS VARCHAR) || COALESCE(' · ' || src_ip, '') AS detail,
			       CAST(timestamp AS VARCHAR) AS ref
			FROM auth_events
			WHERE user ILIKE ? OR src_ip ILIKE ? OR workstation ILIKE ?
			LIMIT 50
		`, like, like, like),
		"defender": safeQuery(`
			SELECT 'defender' AS kind, COALESCE(threat_name,'Unknown') AS title,
			       COALESCE(path,'') AS detail, CAST(timestamp AS VARCHAR) AS ref
			FROM defender_events
			WHERE threat_name ILIKE ? OR path ILIKE ? OR sha256 ILIKE ?
			LIMIT 50
		`, like, like, like),
		"proc_creation": safeQuery(`
			SELECT 'proc_creation' AS kind, image AS title,
			       COALESCE(cmdline,'') AS detail, COALESCE(user_name,'') AS ref
			FROM proc_creation
			WHERE image ILIKE ? OR cmdline ILIKE ? OR parent_image ILIKE ? OR user_name ILIKE ?
			LIMIT 50
		`, like, like, like, like),
		"sysmon": safeQuery(`
			SELECT 'sysmon' AS kind, COALESCE(image,'') AS title,
			       COALESCE(cmdline,'') AS detail, COALESCE(user_name,'') AS ref
			FROM sysmon_process
			WHERE image ILIKE ? OR cmdline ILIKE ? OR parent_image ILIKE ? OR sha256 ILIKE ?
			LIMIT 50
		`, like, like, like, like),
		"browser": safeQuery(`
			SELECT 'browser' AS kind, url AS title, COALESCE(title,'') AS detail,
			       browser AS ref
			FROM browser_history
			WHERE url ILIKE ? OR title ILIKE ?
			LIMIT 50
		`, like, like),
		"registry": safeQuery(`
			SELECT 'registry' AS kind, key_path AS title,
			       COALESCE(CAST(value_data AS VARCHAR),'') AS detail,
			       value_name AS ref
			FROM registry_raw
			WHERE key_path ILIKE ? OR CAST(value_data AS VARCHAR) ILIKE ? OR value_name ILIKE ?
			LIMIT 50
		`, like, like, like),
	}

	jsonOK(w, results)
}

func handlePersistence(w http.ResponseWriter, r *http.Request) {
	rows := safeQuery(`
		SELECT source, type, name, command, modified
		FROM v_persistence
		ORDER BY modified DESC NULLS LAST
		LIMIT 1000
	`)
	jsonOK(w, rows)
}

func handleDefenders(w http.ResponseWriter, r *http.Request) {
	rows := safeQuery(`
		SELECT event_id, timestamp, threat_name, severity, path,
		       action, detection_user, process_name, sha256
		FROM defender_events
		ORDER BY timestamp DESC
		LIMIT 500
	`)
	jsonOK(w, rows)
}

func handleAuth(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	eventID := q.Get("event_id")
	user    := q.Get("user")
	srcIP   := q.Get("src_ip")
	ltype   := q.Get("logon_type")

	query := `SELECT event_id, timestamp, "user", domain, logon_type,
	                 src_ip, workstation, logon_id, process_name
	          FROM auth_events WHERE 1=1`
	args := []any{}
	if eventID != "" {
		query += " AND CAST(event_id AS VARCHAR) = ?"
		args = append(args, eventID)
	}
	if user != "" {
		query += ` AND "user" ILIKE ?`
		args = append(args, "%"+user+"%")
	}
	if srcIP != "" {
		query += " AND src_ip ILIKE ?"
		args = append(args, "%"+srcIP+"%")
	}
	if ltype != "" {
		query += " AND CAST(logon_type AS VARCHAR) = ?"
		args = append(args, ltype)
	}
	query += " ORDER BY timestamp DESC LIMIT 1000"
	jsonOK(w, safeQuery(query, args...))
}

func handleAuthStats(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, map[string]any{
		"event_dist": safeQuery(`
			SELECT event_id, COUNT(*) AS cnt
			FROM auth_events GROUP BY event_id ORDER BY cnt DESC
		`),
		"top_users": safeQuery(`
			SELECT "user", COUNT(*) AS cnt
			FROM auth_events
			WHERE "user" IS NOT NULL AND "user" != '' AND "user" NOT LIKE 'S-1-%'
			GROUP BY "user" ORDER BY cnt DESC LIMIT 15
		`),
		"top_ips": safeQuery(`
			SELECT src_ip, COUNT(*) AS cnt
			FROM auth_events
			WHERE src_ip IS NOT NULL AND src_ip != '' AND src_ip != '-'
			GROUP BY src_ip ORDER BY cnt DESC LIMIT 15
		`),
		"failed":       countFirst(safeQuery(`SELECT COUNT(*) AS c FROM auth_events WHERE event_id = 4625`)),
		"total":        countFirst(safeQuery(`SELECT COUNT(*) AS c FROM auth_events`)),
		"unique_users": countFirst(safeQuery(`SELECT COUNT(DISTINCT "user") AS c FROM auth_events WHERE "user" IS NOT NULL AND "user" != '' AND "user" NOT LIKE 'S-1-%'`)),
		"unique_ips":   countFirst(safeQuery(`SELECT COUNT(DISTINCT src_ip) AS c FROM auth_events WHERE src_ip IS NOT NULL AND src_ip != '' AND src_ip != '-'`)),
		"failed_by_user": safeQuery(`
			SELECT "user", COUNT(*) AS cnt
			FROM auth_events
			WHERE event_id = 4625 AND "user" IS NOT NULL AND "user" != '' AND "user" NOT LIKE 'S-1-%'
			GROUP BY "user" ORDER BY cnt DESC LIMIT 10
		`),
		"failed_by_ip": safeQuery(`
			SELECT src_ip, COUNT(*) AS cnt
			FROM auth_events
			WHERE event_id = 4625 AND src_ip IS NOT NULL AND src_ip != '' AND src_ip != '-'
			GROUP BY src_ip ORDER BY cnt DESC LIMIT 10
		`),
		"kerb_total": countFirst(safeQuery(`SELECT COUNT(*) AS c FROM kerberos_events`)),
		"kerb_rc4":   countFirst(safeQuery(`SELECT COUNT(*) AS c FROM kerberos_events WHERE encryption_type ILIKE '%RC4%' OR encryption_type ILIKE '%0x17%' OR encryption_type = '23'`)),
		"kerb_top": safeQuery(`
			SELECT "user", service_name, encryption_type, src_ip, COUNT(*) AS cnt
			FROM kerberos_events
			GROUP BY "user", service_name, encryption_type, src_ip
			ORDER BY cnt DESC LIMIT 10
		`),
		"logon_type_breakdown": safeQuery(`
			SELECT
				CAST(logon_type AS VARCHAR) AS logon_type,
				COUNT(*) AS total,
				SUM(CASE WHEN event_id=4624 THEN 1 ELSE 0 END) AS successes,
				SUM(CASE WHEN event_id=4625 THEN 1 ELSE 0 END) AS failures,
				COUNT(DISTINCT "user") AS unique_users
			FROM auth_events
			WHERE logon_type IS NOT NULL AND logon_type != 0
			GROUP BY logon_type
			ORDER BY total DESC
		`),
		"pth_users": safeQuery(`
			SELECT "user", COUNT(*) AS cnt, MAX(timestamp) AS last_seen, src_ip
			FROM auth_events
			WHERE logon_type = 9 AND "user" IS NOT NULL AND "user" != '' AND "user" NOT LIKE 'S-1-%'
			GROUP BY "user", src_ip
			ORDER BY cnt DESC LIMIT 15
		`),
	})
}

func handleEventsStats(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, map[string]any{
		"top_ids": safeQuery(`
			SELECT event_id, COUNT(*) AS cnt, channel
			FROM evtx_events
			GROUP BY event_id, channel
			ORDER BY cnt DESC LIMIT 30
		`),
		"total": countFirst(safeQuery(`SELECT COUNT(*) AS c FROM evtx_events`)),
	})
}

func handleFiles(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	filter := q.Get("filter")
	search := q.Get("q")

	var query string
	args := []any{}

	switch filter {
	case "deleted":
		query = `SELECT path, size, modified, created, is_deleted
		         FROM mft WHERE is_deleted = true AND is_dir = false
		         ORDER BY modified DESC NULLS LAST LIMIT 500`
	case "exec":
		query = `SELECT path, size, modified, created, is_deleted
		         FROM mft WHERE is_dir = false AND (
		           path ILIKE '%.exe' OR path ILIKE '%.dll' OR
		           path ILIKE '%.bat' OR path ILIKE '%.ps1' OR
		           path ILIKE '%.vbs' OR path ILIKE '%.scr' OR
		           path ILIKE '%.com' OR path ILIKE '%.pif'
		         ) ORDER BY modified DESC NULLS LAST LIMIT 500`
	case "timestomped":
		query = `SELECT path, size, modified, created, is_deleted
		         FROM mft WHERE is_dir = false
		         AND created IS NOT NULL AND modified IS NOT NULL
		         AND created > modified
		         ORDER BY modified DESC NULLS LAST LIMIT 500`
	case "lnk":
		rows := safeQuery(`SELECT path, target_path, created, modified, args, machine_id
		                   FROM lnk_files ORDER BY modified DESC NULLS LAST LIMIT 500`)
		jsonOK(w, rows)
		return
	case "recycle":
		rows := safeQuery(`SELECT original_path AS path, deleted_at AS modified,
		                   size, sid
		                   FROM recycle_bin ORDER BY deleted_at DESC NULLS LAST LIMIT 500`)
		jsonOK(w, rows)
		return
	case "shellbags":
		rows := safeQuery(`SELECT path, last_modified, "user", source
		                   FROM shellbags ORDER BY last_modified DESC NULLS LAST LIMIT 500`)
		jsonOK(w, rows)
		return
	case "jumplists":
		rows := safeQuery(`SELECT target_path AS path, app_name, created, modified, accessed
		                   FROM jumplists ORDER BY modified DESC NULLS LAST LIMIT 500`)
		jsonOK(w, rows)
		return
	case "usnjrnl":
		rows := safeQuery(`SELECT path, reason, timestamp AS modified
		                   FROM usnjrnl
		                   WHERE reason IS NOT NULL
		                   ORDER BY timestamp DESC NULLS LAST LIMIT 500`)
		jsonOK(w, rows)
		return
	default:
		// suspicious paths — MFT stores paths with forward slashes, no drive letter
		query = `SELECT path, size, modified, created, is_deleted
		         FROM mft WHERE is_dir = false AND (
		           path ILIKE '%/Temp/%.exe' OR path ILIKE '%/Temp/%.dll' OR
		           path ILIKE '%/Temp/%.bat' OR path ILIKE '%/Temp/%.ps1' OR
		           path ILIKE '%/Temp/%.vbs' OR path ILIKE '%/Temp/%.hta' OR
		           path ILIKE '%/AppData/Roaming/%.exe' OR
		           path ILIKE '%/AppData/Local/Temp/%.exe' OR
		           path ILIKE '%/Downloads/%.exe' OR
		           path ILIKE '%/Downloads/%.dll' OR
		           path ILIKE '%/Public/%.exe' OR
		           path ILIKE '%/Windows/Tasks/%.exe' OR
		           path ILIKE '%/Windows/Tasks/%.ps1' OR
		           path ILIKE '%/Windows/Temp/%.exe' OR
		           path ILIKE '%/ProgramData/%.exe' OR
		           path ILIKE '%/Perflogs/%.exe' OR
		           path ILIKE '%/Windows/Fonts/%.exe' OR
		           path ILIKE '%/Windows/Help/%.exe' OR
		           path ILIKE '%/Recycle%/%.exe' OR
		           (path ILIKE '%/Users/%' AND path ILIKE '%/AppData/Roaming/%.exe')
		         ) ORDER BY modified DESC NULLS LAST LIMIT 500`
	}

	if search != "" {
		query = `SELECT path, size, modified, created, is_deleted
		         FROM mft WHERE is_dir = false AND path ILIKE ?
		         ORDER BY modified DESC NULLS LAST LIMIT 500`
		args = append(args, "%"+search+"%")
	}

	jsonOK(w, safeQuery(query, args...))
}

func handleLateral(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	src := r.URL.Query().Get("source")
	where := " WHERE 1=1"
	args := []any{}
	if q != "" {
		like := "%" + q + "%"
		where += ` AND ("user" ILIKE ? OR src ILIKE ? OR dst ILIKE ? OR method ILIKE ?)`
		args = append(args, like, like, like, like)
	}
	if src != "" {
		where += " AND source = ?"
		args = append(args, src)
	}
	rows := safeQuery(`SELECT source, timestamp, "user", src, dst, method
	                   FROM v_lateral_movement`+where+`
	                   ORDER BY timestamp DESC LIMIT 1000`, args...)

	// Also include direct lateral_movement table entries
	direct := safeQuery(`SELECT type AS source, timestamp, "user", src_host AS src,
	                     dst_host AS dst, method
	                     FROM lateral_movement ORDER BY timestamp DESC LIMIT 200`)

	jsonOK(w, map[string]any{"events": rows, "direct": direct})
}

func handleRegistry(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	susp := r.URL.Query().Get("susp")

	suspKeys := []string{
		`%\CurrentVersion\Run%`,
		`%\CurrentVersion\RunOnce%`,
		`%\Winlogon%`,
		`%Image File Execution Options%`,
		`%AppCertDlls%`,
		`%AppInitDLLs%`,
		`%\Policies\Explorer\Run%`,
		`%ShellServiceObjectDelayLoad%`,
		`%\Services\%ImagePath%`,
		`%BootExecute%`,
		`%SessionManager\SubSystems%`,
		`%LSA\%`,
		`%NetSH\%`,
		`%Print\Providers%`,
		`%SecurityProviders%`,
	}

	where := " WHERE 1=1"
	args := []any{}
	if q != "" {
		like := "%" + q + "%"
		where += " AND (key_path ILIKE ? OR value_name ILIKE ? OR value_data ILIKE ?)"
		args = append(args, like, like, like)
	}
	if susp == "1" || q == "" {
		suspParts := make([]string, len(suspKeys))
		for i, k := range suspKeys {
			suspParts[i] = "key_path ILIKE ?"
			args = append(args, k)
		}
		where += " AND (" + strings.Join(suspParts, " OR ") + ")"
	}
	rows := safeQuery(`SELECT hive, key_path, value_name, value_type, LEFT(value_data,500) AS value_data, modified
	                   FROM registry_raw`+where+`
	                   ORDER BY modified DESC NULLS LAST LIMIT 500`, args...)
	jsonOK(w, rows)
}

func handleBrowser(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	t := r.URL.Query().Get("type") // "history" or "downloads"
	susp := r.URL.Query().Get("susp")

	suspWhere := ""
	if susp == "1" {
		suspWhere = ` AND (url ILIKE '%pastebin%' OR url ILIKE '%hastebin%' OR url ILIKE '%paste.ee%' OR
			url ILIKE '%mega.nz%' OR url ILIKE '%gofile.io%' OR url ILIKE '%sendspace%' OR
			url ILIKE '%wetransfer%' OR url ILIKE '%anonfiles%' OR url ILIKE '%bayfiles%' OR
			url ILIKE '%raw.githubusercontent%' OR url ILIKE '%bit.ly%' OR url ILIKE '%tinyurl%' OR
			url ILIKE 'http://%')`
	}
	qWhere := ""
	qArgs := []any{}
	if q != "" {
		like := "%" + q + "%"
		qWhere = " AND (url ILIKE ? OR title ILIKE ?)"
		qArgs = append(qArgs, like, like)
	}

	var hist, dl []map[string]any
	if t == "" || t == "history" {
		hist = safeQuery(`SELECT browser, url, title, visit_time, visit_count, profile
		                  FROM browser_history WHERE 1=1`+suspWhere+qWhere+`
		                  ORDER BY visit_time DESC LIMIT 500`, qArgs...)
	}
	if t == "" || t == "downloads" {
		dlArgs := []any{}
		dlWhere := ""
		if q != "" {
			like := "%" + q + "%"
			dlWhere = " AND (url ILIKE ? OR local_path ILIKE ?)"
			dlArgs = append(dlArgs, like, like)
		}
		dl = safeQuery(`SELECT browser, url, local_path, start_time, end_time
		                FROM browser_downloads WHERE 1=1`+dlWhere+`
		                ORDER BY start_time DESC LIMIT 200`, dlArgs...)
	}
	jsonOK(w, map[string]any{"history": hist, "downloads": dl})
}

func handlePsScripts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	obf := r.URL.Query().Get("obf")
	where := " WHERE 1=1"
	args := []any{}
	if q != "" {
		like := "%" + q + "%"
		where += " AND (script_text ILIKE ? OR path ILIKE ?)"
		args = append(args, like, like)
	}
	if obf == "1" {
		where += ` AND (
			script_text ILIKE '%FromBase64%' OR script_text ILIKE '%EncodedCommand%' OR
			script_text ILIKE '%Invoke-Expression%' OR script_text ILIKE '%-enc %' OR
			script_text ILIKE '%[char]%' OR script_text ILIKE '%DownloadString%' OR
			script_text ILIKE '%New-Object%WebClient%' OR script_text ILIKE '%IEX%' OR
			script_text ILIKE '%bypass%' OR script_text ILIKE '%shellcode%' OR
			script_text ILIKE '%Reflection.Assembly%' OR script_text ILIKE '%Marshal%' OR
			script_text ILIKE '%-w hidden%' OR script_text ILIKE '%LSASS%'
		)`
	}
	blocks := safeQuery(`SELECT timestamp, script_id, path, level, computer,
	                   LEFT(script_text, 3000) AS preview, LENGTH(script_text) AS total_len
	                   FROM ps_scriptblock`+where+`
	                   ORDER BY timestamp DESC LIMIT 300`, args...)
	history := safeQuery(`SELECT command, timestamp, source, "user"
	                      FROM ps_history ORDER BY timestamp DESC LIMIT 500`)
	jsonOK(w, map[string]any{"blocks": blocks, "history": history})
}

func handleHiddenProcs(w http.ResponseWriter, r *http.Request) {
	hidden := safeQuery(`
		SELECT s.pid, s.ppid, s.name, s.create_time
		FROM mem_psscan s
		LEFT JOIN mem_pslist p ON s.pid = p.pid
		WHERE p.pid IS NULL
		  AND CAST(s.pid AS BIGINT) BETWEEN 4 AND 131072
		  AND LENGTH(s.name) >= 3
		ORDER BY s.create_time
	`)
	mutexes := safeQuery(`
		SELECT pid, name AS proc_name, object_name AS mutex_name
		FROM mem_handles
		WHERE handle_type = 'Mutant'
		AND object_name IS NOT NULL AND object_name != '' AND object_name != '\Sessions\1\BaseNamedObjects\'
		ORDER BY object_name
		LIMIT 300
	`)
	jsonOK(w, map[string]any{"hidden": hidden, "mutexes": mutexes})
}

func handleMemModules(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	susp := r.URL.Query().Get("susp")
	where := " WHERE 1=1"
	args := []any{}
	if q != "" {
		like := "%" + q + "%"
		where += " AND (path ILIKE ? OR name ILIKE ?)"
		args = append(args, like, like)
	}
	if susp == "1" {
		where += ` AND (
			path ILIKE '%\Temp\%' OR path ILIKE '%\AppData\%' OR
			path ILIKE '%\ProgramData\%' OR path ILIKE '%\Downloads\%' OR
			path ILIKE '%\Public\%' OR path ILIKE '%\Users\%\Desktop\%' OR
			(path NOT ILIKE '%\Windows\%' AND path NOT ILIKE '%\Program Files%' AND path != '')
		)`
	}
	modules := safeQuery(`SELECT pid, name, base, size, path
	                      FROM mem_modules`+where+`
	                      ORDER BY pid, name LIMIT 1000`, args...)
	drivers := safeQuery(`SELECT mem_offset, name, size, path
	                      FROM mem_driverscan
	                      ORDER BY name LIMIT 500`)
	jsonOK(w, map[string]any{"modules": modules, "drivers": drivers})
}

func handleAmcache(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	where := ""
	args := []any{}
	if q != "" {
		like := "%" + q + "%"
		where = " WHERE path ILIKE ? OR publisher ILIKE ? OR sha256 ILIKE ?"
		args = append(args, like, like, like)
	}
	rows := safeQuery(`SELECT path, sha256, compile_time, first_seen, publisher, version
	                   FROM amcache`+where+`
	                   ORDER BY first_seen DESC NULLS LAST
	                   LIMIT 1000`, args...)
	jsonOK(w, rows)
}

func handleMalfind(w http.ResponseWriter, r *http.Request) {
	rows := safeQuery(`
		SELECT pid, name, address, size, reason, vad_tag,
		       LEFT(hexdump, 160) AS hex_preview,
		       LEFT(disasm, 300) AS disasm_preview
		FROM mem_malfind
		ORDER BY pid, address
	`)
	// Group by process for easier consumption
	type hit struct {
		Address     string `json:"address"`
		Size        any    `json:"size"`
		Reason      string `json:"reason"`
		VadTag      string `json:"vad_tag"`
		HexPreview  string `json:"hex_preview"`
		DisasmPreview string `json:"disasm_preview"`
	}
	type proc struct {
		PID   any    `json:"pid"`
		Name  string `json:"name"`
		Hits  []hit  `json:"hits"`
	}
	order := []any{}
	byPID := map[any]*proc{}
	for _, r := range rows {
		pid := r["pid"]
		if _, ok := byPID[pid]; !ok {
			p := &proc{PID: pid, Name: fmt.Sprintf("%v", r["name"])}
			byPID[pid] = p
			order = append(order, pid)
		}
		byPID[pid].Hits = append(byPID[pid].Hits, hit{
			Address:      fmt.Sprintf("%v", r["address"]),
			Size:         r["size"],
			Reason:       fmt.Sprintf("%v", r["reason"]),
			VadTag:       fmt.Sprintf("%v", r["vad_tag"]),
			HexPreview:   fmt.Sprintf("%v", r["hex_preview"]),
			DisasmPreview: fmt.Sprintf("%v", r["disasm_preview"]),
		})
	}
	result := make([]proc, 0, len(order))
	for _, pid := range order {
		result = append(result, *byPID[pid])
	}
	jsonOK(w, result)
}

func handleAttackSummary(w http.ResponseWriter, r *http.Request) {
	rows := safeQuery(`
		SELECT source, confidence, related_campaign,
		       COUNT(*) AS hits,
		       MIN(first_seen) AS first_ts
		FROM ioc_indicators
		WHERE related_campaign IS NOT NULL AND related_campaign != ''
		GROUP BY source, confidence, related_campaign
		ORDER BY CASE confidence WHEN 'HIGH' THEN 0 ELSE 1 END, hits DESC
	`)
	jsonOK(w, rows)
}

func handleExecution(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	var ua, bd, sc []map[string]any
	if q != "" {
		like := "%" + q + "%"
		ua = safeQuery(`SELECT path, run_count, last_run FROM userassist WHERE path ILIKE ? ORDER BY last_run DESC NULLS LAST LIMIT 500`, like)
		bd = safeQuery(`SELECT path, last_run, sid, source FROM bam_dam WHERE path ILIKE ? ORDER BY last_run DESC NULLS LAST LIMIT 500`, like)
		sc = safeQuery(`SELECT path, last_modified AS last_run, executed, order_idx FROM shimcache WHERE path ILIKE ? ORDER BY order_idx ASC LIMIT 500`, like)
	} else {
		ua = safeQuery(`SELECT path, run_count, last_run FROM userassist ORDER BY last_run DESC NULLS LAST LIMIT 500`)
		bd = safeQuery(`SELECT path, last_run, sid, source FROM bam_dam ORDER BY last_run DESC NULLS LAST LIMIT 500`)
		sc = safeQuery(`SELECT path, last_modified AS last_run, executed, order_idx FROM shimcache ORDER BY order_idx ASC LIMIT 500`)
	}
	jsonOK(w, map[string]any{"userassist": ua, "bam_dam": bd, "shimcache": sc})
}

func handleHashes(w http.ResponseWriter, r *http.Request) {
	q       := r.URL.Query().Get("q")
	iocOnly := r.URL.Query().Get("ioc") == "1"

	where := " WHERE 1=1"
	args  := []any{}
	if q != "" {
		like := "%" + q + "%"
		where += " AND (g.hash ILIKE ? OR g.path ILIKE ? OR g.publisher ILIKE ? OR g.threat_name ILIKE ?)"
		args = append(args, like, like, like, like)
	}
	if iocOnly {
		where += " AND ib.confidence IS NOT NULL"
	}

	rows := safeQuery(`
		WITH hashes AS (
			SELECT sha256 AS hash, 'SHA1'   AS hash_type, 'amcache'  AS source,
			       path, first_seen,        publisher    AS extra
			FROM amcache
			WHERE sha256 IS NOT NULL AND sha256 != ''
			UNION ALL
			SELECT sha256 AS hash, 'SHA256' AS hash_type, 'prefetch' AS source,
			       path, last_run AS first_seen, CAST(NULL AS VARCHAR) AS extra
			FROM prefetch
			WHERE sha256 IS NOT NULL AND sha256 != ''
			UNION ALL
			SELECT sha256 AS hash, 'SHA256' AS hash_type, 'defender' AS source,
			       path, timestamp AS first_seen, threat_name AS extra
			FROM defender_events
			WHERE sha256 IS NOT NULL AND sha256 != ''
		),
		grouped AS (
			SELECT hash,
			       MAX(hash_type)                                                AS hash_type,
			       ARRAY_TO_STRING(list_sort(list_distinct(list(source))), ',') AS sources,
			       COUNT(DISTINCT source)                                        AS source_count,
			       MIN(path)                                                     AS path,
			       MIN(first_seen)                                               AS first_seen,
			       MAX(CASE WHEN source = 'amcache'  THEN extra END)            AS publisher,
			       MAX(CASE WHEN source = 'defender' THEN extra END)            AS threat_name
			FROM hashes
			GROUP BY hash
		),
		ioc_best AS (
			SELECT lower(value) AS hash_lower,
			       MIN(confidence) AS confidence,
			       MIN(source)     AS ioc_source,
			       MIN(notes)      AS ioc_notes
			FROM ioc_indicators
			WHERE type IN ('sha256','sha1','md5','hash')
			GROUP BY lower(value)
		)
		SELECT g.hash, g.hash_type, g.sources, g.source_count,
		       g.path, g.first_seen, g.publisher, g.threat_name,
		       ib.confidence AS ioc_confidence,
		       ib.ioc_source AS ioc_source,
		       ib.ioc_notes  AS ioc_notes
		FROM grouped g
		LEFT JOIN ioc_best ib ON lower(g.hash) = ib.hash_lower
	`+where+`
		ORDER BY CASE WHEN ib.confidence IS NOT NULL THEN 0 ELSE 1 END,
		         g.source_count DESC,
		         g.first_seen DESC NULLS LAST
		LIMIT 2000
	`, args...)

	var knownBad, multiSource int64
	for _, row := range rows {
		if row["ioc_confidence"] != nil {
			knownBad++
		}
		if toInt64(row["source_count"]) >= 2 {
			multiSource++
		}
	}
	jsonOK(w, map[string]any{
		"rows":         rows,
		"total":        int64(len(rows)),
		"known_bad":    knownBad,
		"multi_source": multiSource,
	})
}

func handlePersistenceIoc(w http.ResponseWriter, r *http.Request) {
	rows := safeQuery(`
		SELECT source, confidence, COUNT(*) AS hits,
		       MIN(first_seen) AS first_seen, MAX(first_seen) AS last_seen
		FROM ioc_indicators
		WHERE source LIKE '%persist%' OR source LIKE '%service%'
		   OR source LIKE '%task%'    OR source LIKE '%startup%'
		   OR source LIKE '%hijack%'  OR source LIKE '%registry%'
		   OR source LIKE '%sticky%'  OR source LIKE '%autorun%'
		   OR source LIKE '%bitsadmin%'
		GROUP BY source, confidence
		ORDER BY CASE confidence WHEN 'HIGH' THEN 0 ELSE 1 END, hits DESC
	`)
	jsonOK(w, rows)
}

func handleProcCreation(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	search     := q.Get("q")
	filterUser := q.Get("user")
	integrity  := q.Get("integrity")
	susp       := q.Get("suspicious")

	lolbinClause := `(image ILIKE '%certutil.exe' OR image ILIKE '%mshta.exe' OR
		image ILIKE '%regsvr32.exe' OR image ILIKE '%msiexec.exe' OR
		image ILIKE '%wscript.exe'  OR image ILIKE '%cscript.exe' OR
		image ILIKE '%rundll32.exe' OR image ILIKE '%bitsadmin.exe' OR
		image ILIKE '%wmic.exe'     OR image ILIKE '%odbcconf.exe' OR
		image ILIKE '%regasm.exe'   OR image ILIKE '%msbuild.exe' OR
		image ILIKE '%installutil.exe' OR image ILIKE '%cmstp.exe' OR
		image ILIKE '%forfiles.exe' OR image ILIKE '%pcalua.exe')`

	suspPathClause := `(image ILIKE '%\Temp\%' OR image ILIKE '%/Temp/%' OR
		image ILIKE '%\Downloads\%'  OR image ILIKE '%/Downloads/%' OR
		image ILIKE '%\AppData\%'    OR image ILIKE '%/AppData/%' OR
		image ILIKE '%\ProgramData\%' OR image ILIKE '%/ProgramData/%' OR
		image ILIKE '%\Public\%'     OR image ILIKE '%/Public/%')`

	stats := map[string]any{
		"total":          countFirst(safeQuery(`SELECT COUNT(*) AS c FROM proc_creation`)),
		"lolbins":        countFirst(safeQuery(fmt.Sprintf(`SELECT COUNT(*) AS c FROM proc_creation WHERE %s`, lolbinClause))),
		"susp_path":      countFirst(safeQuery(fmt.Sprintf(`SELECT COUNT(*) AS c FROM proc_creation WHERE %s`, suspPathClause))),
		"high_integrity": countFirst(safeQuery(`SELECT COUNT(*) AS c FROM proc_creation WHERE integrity_level IN ('High','System')`)),
		"unique_users":   countFirst(safeQuery(`SELECT COUNT(DISTINCT user_name) AS c FROM proc_creation WHERE user_name IS NOT NULL AND user_name != ''`)),
		"unique_images":  countFirst(safeQuery(`SELECT COUNT(DISTINCT image) AS c FROM proc_creation WHERE image IS NOT NULL`)),
	}

	where := " WHERE 1=1"
	args := []any{}

	if search != "" {
		like := "%" + search + "%"
		where += " AND (image ILIKE ? OR cmdline ILIKE ? OR parent_image ILIKE ? OR user_name ILIKE ?)"
		args = append(args, like, like, like, like)
	}
	if filterUser != "" {
		where += " AND user_name ILIKE ?"
		args = append(args, "%"+filterUser+"%")
	}
	if integrity != "" {
		where += " AND integrity_level = ?"
		args = append(args, integrity)
	}
	switch susp {
	case "lolbin":
		where += fmt.Sprintf(" AND %s", lolbinClause)
	case "path":
		where += fmt.Sprintf(" AND %s", suspPathClause)
	}

	rows := safeQuery(`SELECT timestamp, pid, ppid, image, cmdline, parent_image,
		user_name, integrity_level, token_elevation, logon_id, computer
		FROM proc_creation`+where+`
		ORDER BY timestamp DESC NULLS LAST
		LIMIT 2000`, args...)

	jsonOK(w, map[string]any{"stats": stats, "rows": rows})
}

func handleSysmonProcess(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	search := q.Get("q")
	susp   := q.Get("suspicious")

	lolbinClause := `(image ILIKE '%certutil.exe' OR image ILIKE '%mshta.exe' OR
		image ILIKE '%regsvr32.exe' OR image ILIKE '%wscript.exe' OR image ILIKE '%cscript.exe' OR
		image ILIKE '%rundll32.exe' OR image ILIKE '%msiexec.exe' OR image ILIKE '%bitsadmin.exe' OR
		image ILIKE '%wmic.exe' OR image ILIKE '%msbuild.exe' OR image ILIKE '%cmstp.exe')`

	suspPathClause := `(image ILIKE '%\Temp\%' OR image ILIKE '%/Temp/%' OR
		image ILIKE '%\Downloads\%' OR image ILIKE '%\AppData\%' OR
		image ILIKE '%\ProgramData\%' OR image ILIKE '%\Public\%')`

	stats := map[string]any{
		"total":          countFirst(safeQuery(`SELECT COUNT(*) AS c FROM sysmon_process`)),
		"with_sha256":    countFirst(safeQuery(`SELECT COUNT(*) AS c FROM sysmon_process WHERE sha256 IS NOT NULL AND sha256 != ''`)),
		"lolbins":        countFirst(safeQuery(fmt.Sprintf(`SELECT COUNT(*) AS c FROM sysmon_process WHERE %s`, lolbinClause))),
		"susp_path":      countFirst(safeQuery(fmt.Sprintf(`SELECT COUNT(*) AS c FROM sysmon_process WHERE %s`, suspPathClause))),
		"high_integrity": countFirst(safeQuery(`SELECT COUNT(*) AS c FROM sysmon_process WHERE integrity_level IN ('High','System')`)),
		"unique_images":  countFirst(safeQuery(`SELECT COUNT(DISTINCT image) AS c FROM sysmon_process WHERE image IS NOT NULL`)),
	}

	where := " WHERE 1=1"
	args := []any{}
	if search != "" {
		like := "%" + search + "%"
		where += " AND (image ILIKE ? OR cmdline ILIKE ? OR parent_image ILIKE ? OR user_name ILIKE ? OR sha256 ILIKE ?)"
		args = append(args, like, like, like, like, like)
	}
	switch susp {
	case "lolbin":
		where += fmt.Sprintf(" AND %s", lolbinClause)
	case "path":
		where += fmt.Sprintf(" AND %s", suspPathClause)
	case "high_integ":
		where += ` AND integrity_level IN ('High','System')`
	}

	rows := safeQuery(`SELECT timestamp, pid, ppid, image, cmdline, parent_image, parent_cmdline,
		sha256, integrity_level, user_name, logon_id, computer
		FROM sysmon_process`+where+`
		ORDER BY timestamp DESC NULLS LAST LIMIT 2000`, args...)

	jsonOK(w, map[string]any{"stats": stats, "rows": rows})
}

func handleSysmonNetwork(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	search := q.Get("q")
	dir    := q.Get("dir")

	stats := map[string]any{
		"total":    countFirst(safeQuery(`SELECT COUNT(*) AS c FROM sysmon_network`)),
		"outbound": countFirst(safeQuery(`SELECT COUNT(*) AS c FROM sysmon_network WHERE initiated = true`)),
		"external": countFirst(safeQuery(`SELECT COUNT(*) AS c FROM sysmon_network WHERE initiated = true
			AND dst_ip NOT IN ('0.0.0.0','-','') AND dst_ip IS NOT NULL
			AND NOT (dst_ip LIKE '10.%' OR dst_ip LIKE '192.168.%' OR dst_ip LIKE '172.1%'
			  OR dst_ip LIKE '172.2%' OR dst_ip LIKE '172.3%' OR dst_ip = '127.0.0.1')`)),
		"unique_dst": countFirst(safeQuery(`SELECT COUNT(DISTINCT dst_ip) AS c FROM sysmon_network WHERE dst_ip IS NOT NULL AND dst_ip != ''`)),
	}

	where := " WHERE 1=1"
	args := []any{}
	if search != "" {
		like := "%" + search + "%"
		where += " AND (image ILIKE ? OR dst_ip ILIKE ? OR dst_host ILIKE ? OR src_ip ILIKE ?)"
		args = append(args, like, like, like, like)
	}
	if dir == "out" {
		where += " AND initiated = true"
	} else if dir == "in" {
		where += " AND initiated = false"
	}

	rows := safeQuery(`SELECT timestamp, pid, image, proto, src_ip, src_port, src_host,
		dst_ip, dst_port, dst_host, initiated, user_name, computer
		FROM sysmon_network`+where+`
		ORDER BY timestamp DESC NULLS LAST LIMIT 2000`, args...)

	jsonOK(w, map[string]any{"stats": stats, "rows": rows})
}

func handleSysmonDns(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	search := q.Get("q")

	stats := map[string]any{
		"total":        countFirst(safeQuery(`SELECT COUNT(*) AS c FROM sysmon_dns`)),
		"unique_names": countFirst(safeQuery(`SELECT COUNT(DISTINCT query_name) AS c FROM sysmon_dns`)),
		"failed":       countFirst(safeQuery(`SELECT COUNT(*) AS c FROM sysmon_dns WHERE query_status != '0' AND query_status != ''`)),
	}

	where := " WHERE 1=1"
	args := []any{}
	if search != "" {
		like := "%" + search + "%"
		where += " AND (query_name ILIKE ? OR image ILIKE ? OR query_results ILIKE ?)"
		args = append(args, like, like, like)
	}

	rows := safeQuery(`SELECT timestamp, pid, image, query_name, query_status, query_results, user_name, computer
		FROM sysmon_dns`+where+`
		ORDER BY timestamp DESC NULLS LAST LIMIT 2000`, args...)

	jsonOK(w, map[string]any{"stats": stats, "rows": rows})
}

func handleSysmonImageLoad(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	search := q.Get("q")
	filter := q.Get("filter")

	stats := map[string]any{
		"total":       countFirst(safeQuery(`SELECT COUNT(*) AS c FROM sysmon_imageload`)),
		"unsigned":    countFirst(safeQuery(`SELECT COUNT(*) AS c FROM sysmon_imageload WHERE CAST(signed AS VARCHAR) = 'false' OR signed IS NULL`)),
		"susp_path":   countFirst(safeQuery(`SELECT COUNT(*) AS c FROM sysmon_imageload WHERE image_loaded ILIKE '%\Temp\%' OR image_loaded ILIKE '%\AppData\%' OR image_loaded ILIKE '%\ProgramData\%'`)),
		"unique_dlls": countFirst(safeQuery(`SELECT COUNT(DISTINCT image_loaded) AS c FROM sysmon_imageload`)),
	}

	where := " WHERE 1=1"
	args := []any{}
	if search != "" {
		like := "%" + search + "%"
		where += " AND (image ILIKE ? OR image_loaded ILIKE ? OR COALESCE(signature,'') ILIKE ?)"
		args = append(args, like, like, like)
	}
	switch filter {
	case "unsigned":
		where += " AND (CAST(signed AS VARCHAR) = 'false' OR signed IS NULL)"
	case "susp":
		where += " AND (image_loaded ILIKE '%\\Temp\\%' OR image_loaded ILIKE '%\\AppData\\%' OR image_loaded ILIKE '%\\ProgramData\\%' OR image_loaded ILIKE '%\\Users\\Public\\%')"
	}

	rows := safeQuery(`SELECT timestamp, pid, image, image_loaded,
		CAST(signed AS VARCHAR) AS signed, signature, sha256, user_name
		FROM sysmon_imageload`+where+`
		ORDER BY timestamp DESC NULLS LAST LIMIT 2000`, args...)

	jsonOK(w, map[string]any{"stats": stats, "rows": rows})
}

func handleUserActivity(w http.ResponseWriter, r *http.Request) {
	users := safeQuery(`
		SELECT u.user_name,
		       COALESCE(pc.proc_count,       0) AS proc_count,
		       COALESCE(pc.lolbin_count,     0) AS lolbin_count,
		       COALESCE(pc.susp_path_count,  0) AS susp_path_count,
		       COALESCE(pc.high_integ_count, 0) AS high_integ_count,
		       COALESCE(au.auth_total,       0) AS auth_total,
		       COALESCE(au.auth_failed,      0) AS auth_failed,
		       COALESCE(au.logon_types,      '') AS logon_types,
		       COALESCE(ioc.ioc_hits,        0) AS ioc_hits
		FROM (
			SELECT DISTINCT lower(user_name) AS user_name
			FROM proc_creation
			WHERE user_name IS NOT NULL AND user_name != '' AND user_name != '-'
			  AND user_name NOT LIKE 'S-1-%' AND user_name NOT LIKE '%$'
			UNION
			SELECT DISTINCT lower("user") AS user_name
			FROM auth_events
			WHERE "user" IS NOT NULL AND "user" != '' AND "user" != '-'
			  AND "user" NOT LIKE 'S-1-%' AND "user" NOT LIKE '%$'
		) u
		LEFT JOIN (
			SELECT lower(user_name) AS user_name,
			       COUNT(*) AS proc_count,
			       SUM(CASE WHEN image ILIKE '%certutil.exe' OR image ILIKE '%mshta.exe'
			                     OR image ILIKE '%regsvr32.exe' OR image ILIKE '%rundll32.exe'
			                     OR image ILIKE '%wscript.exe' OR image ILIKE '%cscript.exe'
			                     OR image ILIKE '%msiexec.exe' OR image ILIKE '%bitsadmin.exe'
			                     OR image ILIKE '%wmic.exe' OR image ILIKE '%odbcconf.exe'
			                THEN 1 ELSE 0 END) AS lolbin_count,
			       SUM(CASE WHEN image ILIKE '%\Temp\%' OR image ILIKE '%\AppData\%'
			                     OR image ILIKE '%\Downloads\%' OR image ILIKE '%\ProgramData\%'
			                THEN 1 ELSE 0 END) AS susp_path_count,
			       SUM(CASE WHEN integrity_level IN ('High','System') THEN 1 ELSE 0 END) AS high_integ_count
			FROM proc_creation
			WHERE user_name IS NOT NULL AND user_name != ''
			GROUP BY lower(user_name)
		) pc ON u.user_name = pc.user_name
		LEFT JOIN (
			SELECT lower("user") AS user_name,
			       COUNT(*) AS auth_total,
			       SUM(CASE WHEN event_id = 4625 THEN 1 ELSE 0 END) AS auth_failed,
			       STRING_AGG(DISTINCT CAST(logon_type AS VARCHAR), ',') AS logon_types
			FROM auth_events
			WHERE "user" IS NOT NULL AND "user" != ''
			GROUP BY lower("user")
		) au ON u.user_name = au.user_name
		LEFT JOIN (
			SELECT lower(value) AS user_name, COUNT(*) AS ioc_hits
			FROM ioc_indicators
			WHERE type = 'username'
			GROUP BY lower(value)
		) ioc ON u.user_name = ioc.user_name
		ORDER BY proc_count DESC, auth_total DESC
	`)

	jsonOK(w, users)
}

// pivotSources: {table, paramCount, SELECT template with ? placeholders}
var pivotSources = []struct {
	table  string
	nargs  int
	sel    string
}{
	{"prefetch",        2, `SELECT last_run AS ts, 'Prefetch' AS source, filename AS detail, path AS extra FROM prefetch WHERE filename ILIKE ? OR path ILIKE ?`},
	{"amcache",         1, `SELECT first_seen AS ts, 'Amcache' AS source, split_part(path,CHR(92),-1) AS detail, path AS extra FROM amcache WHERE path ILIKE ?`},
	{"shimcache",       1, `SELECT last_modified AS ts, 'Shimcache' AS source, split_part(path,CHR(92),-1) AS detail, path AS extra FROM shimcache WHERE path ILIKE ?`},
	{"bam_dam",         1, `SELECT last_run AS ts, 'BAM/DAM' AS source, split_part(path,CHR(92),-1) AS detail, path AS extra FROM bam_dam WHERE path ILIKE ?`},
	{"mft",             1, `SELECT modified AS ts, 'MFT' AS source, path AS detail, CAST(COALESCE(size,0) AS VARCHAR)||' B' AS extra FROM mft WHERE path ILIKE ? AND is_dir=false`},
	{"usnjrnl",         1, `SELECT timestamp AS ts, 'USNJrnl' AS source, path AS detail, reason AS extra FROM usnjrnl WHERE path ILIKE ?`},
	{"lnk_files",       2, `SELECT modified AS ts, 'LNK' AS source, COALESCE(target_path,'') AS detail, path AS extra FROM lnk_files WHERE target_path ILIKE ? OR path ILIKE ?`},
	{"proc_creation",   3, `SELECT timestamp AS ts, 'Proc 4688' AS source, COALESCE(image,'') AS detail, COALESCE(cmdline,'') AS extra FROM proc_creation WHERE image ILIKE ? OR cmdline ILIKE ? OR parent_image ILIKE ?`},
	{"sysmon_process",   2, `SELECT timestamp AS ts, 'Sysmon' AS source, COALESCE(image,'') AS detail, COALESCE(cmdline,'') AS extra FROM sysmon_process WHERE image ILIKE ? OR cmdline ILIKE ?`},
	{"sysmon_imageload", 2, `SELECT timestamp AS ts, 'DLL Load' AS source, COALESCE(image,'') AS detail, COALESCE(image_loaded,'') AS extra FROM sysmon_imageload WHERE image ILIKE ? OR image_loaded ILIKE ?`},
	{"auth_events",      2, `SELECT timestamp AS ts, 'Auth' AS source, COALESCE("user",'') AS detail, COALESCE(src_ip,'') AS extra FROM auth_events WHERE "user" ILIKE ? OR src_ip ILIKE ?`},
	{"browser_history", 2, `SELECT visit_time AS ts, 'Browser' AS source, url AS detail, COALESCE(title,'') AS extra FROM browser_history WHERE url ILIKE ? OR title ILIKE ?`},
	{"defender_events", 2, `SELECT timestamp AS ts, 'Defender' AS source, COALESCE(threat_name,'') AS detail, COALESCE(path,'') AS extra FROM defender_events WHERE threat_name ILIKE ? OR path ILIKE ?`},
	{"ps_scriptblock",  1, `SELECT timestamp AS ts, 'PowerShell' AS source, SUBSTRING(COALESCE(script_text,''),1,150) AS detail, '' AS extra FROM ps_scriptblock WHERE script_text ILIKE ?`},
	{"ioc_indicators",  2, `SELECT first_seen AS ts, 'IOC' AS source, value AS detail, COALESCE(notes,'') AS extra FROM ioc_indicators WHERE value ILIKE ? OR notes ILIKE ?`},
	{"registry_raw",    2, `SELECT modified AS ts, 'Registry' AS source, key_path AS detail, COALESCE(CAST(value_data AS VARCHAR),'') AS extra FROM registry_raw WHERE key_path ILIKE ? OR CAST(value_data AS VARCHAR) ILIKE ?`},
	{"persistence",     2, `SELECT modified AS ts, 'Persistence' AS source, name AS detail, COALESCE(command,'') AS extra FROM persistence WHERE name ILIKE ? OR command ILIKE ?`},
	{"services",        2, `SELECT modified AS ts, 'Service' AS source, name AS detail, COALESCE(binary_path,'') AS extra FROM services WHERE name ILIKE ? OR binary_path ILIKE ?`},
}

func handlePivot(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	if len(strings.TrimSpace(q)) < 2 {
		jsonErr(w, 400, "query too short")
		return
	}
	like := "%" + q + "%"

	if existingTables == nil {
		existingTables = getExistingTables()
	}

	parts := []string{}
	args  := []any{}
	for _, src := range pivotSources {
		if existingTables[src.table] {
			parts = append(parts, src.sel)
			for i := 0; i < src.nargs; i++ {
				args = append(args, like)
			}
		}
	}
	if len(parts) == 0 {
		jsonOK(w, []map[string]any{})
		return
	}
	pivotSQL := "SELECT ts, source, detail, extra FROM (" +
		strings.Join(parts, " UNION ALL ") +
		") t WHERE ts IS NOT NULL ORDER BY ts DESC LIMIT 500"

	jsonOK(w, safeQuery(pivotSQL, args...))
}

// handleEventContext returns all timeline events within ±window seconds of the given timestamp.
// Used by the "Context ±5m" button on detection hit cards to show correlated artifacts.
func handleEventContext(w http.ResponseWriter, r *http.Request) {
	tsStr := r.URL.Query().Get("ts")
	if tsStr == "" {
		jsonErr(w, 400, "ts required")
		return
	}
	window := 300
	if ws := r.URL.Query().Get("window"); ws != "" {
		if v, err := strconv.Atoi(ws); err == nil && v > 0 && v <= 3600 {
			window = v
		}
	}

	if existingTables == nil {
		existingTables = getExistingTables()
	}

	var parts []string
	for _, src := range timelineSources {
		if existingTables[src.table] {
			parts = append(parts, src.sel)
		}
	}
	if len(parts) == 0 {
		jsonOK(w, []map[string]any{})
		return
	}

	ctxSQL := "SELECT ts, source, category, detail, extra FROM (" +
		strings.Join(parts, " UNION ALL ") +
		") t WHERE ts IS NOT NULL AND ABS(epoch(CAST(ts AS TIMESTAMP)) - epoch(CAST(? AS TIMESTAMP))) <= ? ORDER BY ts LIMIT 300"

	jsonOK(w, safeQuery(ctxSQL, tsStr, window))
}

func handleActivity(w http.ResponseWriter, r *http.Request) {
	type bucket struct {
		Hour   string `json:"hour"`
		Evtx   int64  `json:"evtx"`
		Auth   int64  `json:"auth"`
		Proc   int64  `json:"proc"`
		Detect int64  `json:"detect"`
	}
	merged := map[string]*bucket{}

	hourQ := func(table, field string) {
		// Extract hour bucket in SQL: LEFT(CAST(ts AS VARCHAR), 13) gives 'YYYY-MM-DD HH' (13 chars)
		rows, err := queryRows(
			`SELECT LEFT(CAST(`+field+` AS VARCHAR), 13) AS h, COUNT(*) AS cnt FROM `+table+
				` WHERE `+field+` IS NOT NULL GROUP BY 1 ORDER BY 1 LIMIT 720`,
		)
		if err != nil {
			return
		}
		for _, row := range rows {
			ts := ""
			switch v := row["h"].(type) {
			case string:
				ts = v
			case time.Time:
				// DuckDB returned a timestamp — format as hour string
				ts = v.Format("2006-01-02 15")
			}
			if len(ts) < 13 {
				continue
			}
			// Normalize: DuckDB CAST gives 'YYYY-MM-DD HH', convert to 'YYYY-MM-DDTHH'
			hour := ts[:10] + "T" + ts[11:13]
			b := merged[hour]
			if b == nil {
				b = &bucket{Hour: hour}
				merged[hour] = b
			}
			cnt := toInt64(row["cnt"])
			switch table {
			case "evtx_events":
				b.Evtx += cnt
			case "auth_events":
				b.Auth += cnt
			case "proc_creation":
				b.Proc += cnt
			case "ioc_indicators":
				b.Detect += cnt
			}
		}
	}

	hourQ("evtx_events", "timestamp")
	hourQ("auth_events", "timestamp")
	hourQ("proc_creation", "timestamp")
	hourQ("ioc_indicators", "first_seen")

	out := make([]bucket, 0, len(merged))
	for _, b := range merged {
		out = append(out, *b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Hour < out[j].Hour })
	if len(out) > 720 {
		out = out[:720]
	}
	jsonOK(w, out)
}

func handleUserDetail(w http.ResponseWriter, r *http.Request) {
	user := r.URL.Query().Get("user")
	if user == "" {
		jsonErr(w, 400, "user required")
		return
	}
	like := "%" + user + "%"

	procs := safeQuery(`
		SELECT timestamp, pid, ppid, image, cmdline, parent_image, integrity_level, computer
		FROM proc_creation
		WHERE user_name ILIKE ?
		ORDER BY timestamp DESC LIMIT 500
	`, like)

	auths := safeQuery(`
		SELECT event_id, timestamp, logon_type, src_ip, workstation, process_name
		FROM auth_events
		WHERE "user" ILIKE ?
		ORDER BY timestamp DESC LIMIT 500
	`, like)

	iocs := safeQuery(`
		SELECT type, value, source, confidence, notes, first_seen
		FROM ioc_indicators
		WHERE value ILIKE ? OR notes ILIKE ?
		ORDER BY CASE confidence WHEN 'HIGH' THEN 0 ELSE 1 END, first_seen DESC
		LIMIT 100
	`, like, like)

	jsonOK(w, map[string]any{"procs": procs, "auths": auths, "iocs": iocs})
}

func handleReport(w http.ResponseWriter, r *http.Request) {
	var buf bytes.Buffer
	if err := report.Generate(db, &buf); err != nil {
		http.Error(w, "Report generation failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="forensiq-report.html"`)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", buf.Len()))
	w.Write(buf.Bytes()) //nolint:errcheck
}

// initCaseNotes creates the case_notes table on first use.
func initCaseNotes() {
	db.Exec(`CREATE SEQUENCE IF NOT EXISTS _case_notes_seq START 1`)
	db.Exec(`CREATE TABLE IF NOT EXISTS case_notes (
		id       BIGINT    DEFAULT nextval('_case_notes_seq') PRIMARY KEY,
		created_at TIMESTAMP DEFAULT now(),
		ref_type VARCHAR   DEFAULT '',
		ref_id   VARCHAR   DEFAULT '',
		text     VARCHAR   NOT NULL
	)`)
}

func handleNotes(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		rows := safeQuery(`SELECT id, created_at, ref_type, ref_id, text FROM case_notes ORDER BY created_at DESC LIMIT 500`)
		jsonOK(w, rows)
	case http.MethodPost:
		var body struct {
			RefType string `json:"ref_type"`
			RefID   string `json:"ref_id"`
			Text    string `json:"text"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Text) == "" {
			jsonErr(w, 400, "text required")
			return
		}
		if _, err := db.Exec(`INSERT INTO case_notes (ref_type, ref_id, text) VALUES (?, ?, ?)`,
			body.RefType, body.RefID, strings.TrimSpace(body.Text)); err != nil {
			jsonErr(w, 500, err.Error())
			return
		}
		jsonOK(w, map[string]any{"ok": true})
	case http.MethodDelete:
		id := r.URL.Query().Get("id")
		if id == "" {
			jsonErr(w, 400, "id required")
			return
		}
		db.Exec(`DELETE FROM case_notes WHERE CAST(id AS VARCHAR) = ?`, id)
		jsonOK(w, map[string]any{"ok": true})
	default:
		jsonErr(w, 405, "method not allowed")
	}
}

// handleTriage manages analyst triage decisions (TP/FP/Investigating) per detection rule.
// GET returns a map of {source -> {status, ts}}. POST upserts a triage decision.
func handleTriage(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		rows := safeQuery(`
			SELECT ref_id, text AS status, CAST(created_at AS VARCHAR) AS ts
			FROM case_notes
			WHERE ref_type = 'triage'
		`)
		result := map[string]any{}
		for _, row := range rows {
			if refID, ok := row["ref_id"].(string); ok && refID != "" {
				result[refID] = row
			}
		}
		jsonOK(w, result)
	case http.MethodPost:
		var body struct {
			Source string `json:"source"`
			Status string `json:"status"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Source == "" {
			jsonErr(w, 400, "source required")
			return
		}
		valid := map[string]bool{"TP": true, "FP": true, "Investigating": true, "": true}
		if !valid[body.Status] {
			jsonErr(w, 400, "invalid status")
			return
		}
		db.Exec(`DELETE FROM case_notes WHERE ref_type = 'triage' AND ref_id = ?`, body.Source)
		if body.Status != "" {
			if _, err := db.Exec(`INSERT INTO case_notes (ref_type, ref_id, text) VALUES ('triage', ?, ?)`,
				body.Source, body.Status); err != nil {
				jsonErr(w, 500, err.Error())
				return
			}
		}
		jsonOK(w, map[string]any{"ok": true, "source": body.Source, "status": body.Status})
	default:
		jsonErr(w, 405, "method not allowed")
	}
}

// handleActivityHistogram returns hourly event counts per source for the Dashboard sparkline.
func handleActivityHistogram(w http.ResponseWriter, r *http.Request) {
	existing := getExistingTables()

	parts := []string{
		`SELECT CAST(date_trunc('hour', "timestamp") AS VARCHAR) AS h, COUNT(*) AS cnt, 'evtx' AS src FROM evtx_events WHERE "timestamp" IS NOT NULL GROUP BY 1`,
		`SELECT CAST(date_trunc('hour', "timestamp") AS VARCHAR) AS h, COUNT(*) AS cnt, 'auth' AS src FROM auth_events WHERE "timestamp" IS NOT NULL GROUP BY 1`,
		`SELECT CAST(date_trunc('hour', first_seen) AS VARCHAR) AS h, COUNT(*) AS cnt, 'detect' AS src FROM ioc_indicators WHERE first_seen IS NOT NULL GROUP BY 1`,
	}
	if existing["proc_creation"] {
		parts = append(parts, `SELECT CAST(date_trunc('hour', "timestamp") AS VARCHAR) AS h, COUNT(*) AS cnt, 'proc' AS src FROM proc_creation WHERE "timestamp" IS NOT NULL GROUP BY 1`)
	}
	if existing["sysmon_process"] {
		parts = append(parts, `SELECT CAST(date_trunc('hour', utc_time) AS VARCHAR) AS h, COUNT(*) AS cnt, 'sysmon' AS src FROM sysmon_process WHERE utc_time IS NOT NULL GROUP BY 1`)
	}

	sql := `SELECT h, src, cnt FROM (` + strings.Join(parts, " UNION ALL ") + `) t ORDER BY h`
	raw := safeQuery(sql)

	// Merge rows into per-hour buckets
	type Bucket struct {
		Hour   string `json:"hour"`
		Evtx   int64  `json:"evtx"`
		Auth   int64  `json:"auth"`
		Detect int64  `json:"detect"`
		Proc   int64  `json:"proc"`
		Sysmon int64  `json:"sysmon"`
		Total  int64  `json:"total"`
	}
	buckets := map[string]*Bucket{}
	hourOrder := []string{}
	for _, row := range raw {
		h, _ := row["h"].(string)
		src, _ := row["src"].(string)
		cnt := toInt64(row["cnt"])
		if h == "" {
			continue
		}
		if buckets[h] == nil {
			buckets[h] = &Bucket{Hour: h}
			hourOrder = append(hourOrder, h)
		}
		b := buckets[h]
		switch src {
		case "evtx":
			b.Evtx += cnt
		case "auth":
			b.Auth += cnt
		case "detect":
			b.Detect += cnt
		case "proc":
			b.Proc += cnt
		case "sysmon":
			b.Sysmon += cnt
		}
	}
	sort.Strings(hourOrder)
	result := make([]Bucket, 0, len(hourOrder))
	for _, h := range hourOrder {
		b := buckets[h]
		b.Total = b.Evtx + b.Auth + b.Detect + b.Proc + b.Sysmon
		result = append(result, *b)
	}
	jsonOK(w, result)
}

// handleHuntQuery runs an analyst-supplied SELECT query against the case database.
// Only SELECT statements are accepted. Results are capped at 2000 rows.
func handleHuntQuery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonErr(w, 405, "method not allowed")
		return
	}
	var body struct {
		SQL string `json:"sql"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonErr(w, 400, "invalid JSON")
		return
	}
	sql := strings.TrimSpace(body.SQL)
	if sql == "" {
		jsonErr(w, 400, "sql required")
		return
	}
	// Only allow SELECT statements for safety
	upper := strings.ToUpper(sql)
	for _, kw := range []string{"INSERT", "UPDATE", "DELETE", "DROP", "CREATE", "ALTER", "TRUNCATE", "ATTACH", "DETACH", "COPY", "EXPORT"} {
		if strings.HasPrefix(upper, kw) {
			jsonErr(w, 400, "only SELECT queries are allowed")
			return
		}
	}
	if !strings.HasPrefix(upper, "SELECT") && !strings.HasPrefix(upper, "WITH") {
		jsonErr(w, 400, "query must start with SELECT or WITH")
		return
	}

	start := time.Now()
	// Wrap in LIMIT to prevent runaway results
	limited := sql
	if !strings.Contains(upper, "LIMIT") {
		limited = sql + " LIMIT 2000"
	}
	rows, err := queryRows(limited)
	elapsed := time.Since(start).Milliseconds()
	if err != nil {
		jsonOK(w, map[string]any{"error": err.Error(), "rows": []map[string]any{}, "count": 0, "elapsed_ms": elapsed})
		return
	}
	if rows == nil {
		rows = []map[string]any{}
	}
	jsonOK(w, map[string]any{"rows": rows, "count": len(rows), "elapsed_ms": elapsed})
}

// handleIocImport accepts a plain-text list of IOCs (one per line) and inserts them into ioc_indicators.
// Auto-detects type: MD5/SHA1/SHA256 (by hex length), IPv4, domain, URL, path.
func handleIocImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonErr(w, 405, "method not allowed")
		return
	}
	var body struct {
		Text       string `json:"text"`
		Source     string `json:"source"`
		Confidence string `json:"confidence"`
		Campaign   string `json:"campaign"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Text) == "" {
		jsonErr(w, 400, "text required")
		return
	}
	source := strings.TrimSpace(body.Source)
	if source == "" {
		source = "manual:import"
	} else {
		source = "manual:" + source
	}
	switch body.Confidence {
	case "HIGH", "MED", "LOW":
	default:
		body.Confidence = "HIGH"
	}
	campaign := strings.TrimSpace(body.Campaign)

	imported, dupes := 0, 0
	for _, line := range strings.Split(body.Text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		iocType, value := classifyIOC(line)
		if iocType == "" {
			continue
		}
		res, err := db.Exec(
			`INSERT INTO ioc_indicators (type, value, source, confidence, related_campaign, notes, first_seen)
			 SELECT ?, ?, ?, ?, ?, '', now()
			 WHERE NOT EXISTS (SELECT 1 FROM ioc_indicators WHERE lower(value) = lower(?) AND source = ?)`,
			iocType, value, source, body.Confidence, campaign, value, source)
		if err == nil {
			n, _ := res.RowsAffected()
			if n > 0 {
				imported++
			} else {
				dupes++
			}
		}
	}
	jsonOK(w, map[string]any{"imported": imported, "dupes": dupes, "source": source})
}

func classifyIOC(s string) (string, string) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", ""
	}
	if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
		return "url", s
	}
	if iocIsHex(s) {
		switch len(s) {
		case 32:
			return "md5", strings.ToLower(s)
		case 40:
			return "sha1", strings.ToLower(s)
		case 64:
			return "sha256", strings.ToLower(s)
		}
	}
	if iocIsIPv4(s) {
		return "ip", s
	}
	if strings.ContainsAny(s, `\/`) {
		return "path", s
	}
	if strings.Contains(s, ".") && iocIsDomain(s) {
		return "domain", strings.ToLower(s)
	}
	return "indicator", s
}

func iocIsHex(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func iocIsIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if len(p) == 0 || len(p) > 3 {
			return false
		}
		n := 0
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
			n = n*10 + int(c-'0')
		}
		if n > 255 {
			return false
		}
	}
	return true
}

func iocIsDomain(s string) bool {
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_') {
			return false
		}
	}
	parts := strings.Split(s, ".")
	return len(parts) >= 2 && len(parts[len(parts)-1]) >= 2
}

// handleProcDeep returns all correlated artifacts for a given process image path.
// Queries sysmon tables (children, network, dlls, files, dns), prefetch, amcache, ioc hits, proc_creation.
func handleProcDeep(w http.ResponseWriter, r *http.Request) {
	image := strings.TrimSpace(r.URL.Query().Get("image"))
	if image == "" {
		jsonErr(w, 400, "image required")
		return
	}
	like := "%" + image + "%"
	basename := image
	if i := strings.LastIndexAny(image, `\/`); i >= 0 {
		basename = image[i+1:]
	}
	baseLike := "%" + basename + "%"

	if existingTables == nil {
		existingTables = getExistingTables()
	}

	result := map[string]any{
		"image":    image,
		"basename": basename,
	}

	if existingTables["sysmon_process"] {
		result["self"] = safeQuery(`
			SELECT timestamp, pid, ppid, image, cmdline, parent_image, user_name, integrity_level, sha256
			FROM sysmon_process WHERE image ILIKE ? ORDER BY timestamp LIMIT 50`, like)
		result["children"] = safeQuery(`
			SELECT timestamp, pid, image, cmdline, user_name, integrity_level
			FROM sysmon_process WHERE parent_image ILIKE ? ORDER BY timestamp LIMIT 100`, like)
	}
	if existingTables["sysmon_network"] {
		result["network"] = safeQuery(`
			SELECT timestamp, dst_ip, dst_port, COALESCE(dst_host,'') AS dst_host, proto, initiated
			FROM sysmon_network WHERE image ILIKE ? ORDER BY timestamp LIMIT 100`, like)
	}
	if existingTables["sysmon_imageload"] {
		result["dlls"] = safeQuery(`
			SELECT image_loaded, signed, COALESCE(signature,'') AS signature, sha256,
			       MIN(timestamp) AS first_seen, COUNT(*) AS load_count
			FROM sysmon_imageload WHERE image ILIKE ?
			GROUP BY image_loaded, signed, signature, sha256
			ORDER BY signed, image_loaded LIMIT 200`, like)
	}
	if existingTables["sysmon_file"] {
		result["files"] = safeQuery(`
			SELECT timestamp, target_filename
			FROM sysmon_file WHERE image ILIKE ? ORDER BY timestamp LIMIT 100`, like)
	}
	if existingTables["sysmon_dns"] {
		result["dns"] = safeQuery(`
			SELECT timestamp, query_name, COALESCE(query_results,'') AS query_results
			FROM sysmon_dns WHERE image ILIKE ? ORDER BY timestamp LIMIT 100`, like)
	}
	if existingTables["prefetch"] {
		result["prefetch"] = safeQuery(`
			SELECT filename, run_count, last_run, path
			FROM prefetch WHERE filename ILIKE ? LIMIT 5`, baseLike)
	}
	if existingTables["amcache"] {
		result["amcache"] = safeQuery(`
			SELECT path, sha256, first_seen, COALESCE(publisher,'') AS publisher
			FROM amcache WHERE path ILIKE ? LIMIT 5`, like)
	}
	if existingTables["ioc_indicators"] {
		result["iocs"] = safeQuery(`
			SELECT type, value, source, confidence, COALESCE(notes,'') AS notes, first_seen
			FROM ioc_indicators WHERE value ILIKE ? OR notes ILIKE ?
			ORDER BY CASE confidence WHEN 'HIGH' THEN 0 ELSE 1 END LIMIT 50`, baseLike, like)
	}
	if existingTables["proc_creation"] {
		result["proc4688"] = safeQuery(`
			SELECT timestamp, pid, ppid, image, cmdline, parent_image, user_name, integrity_level
			FROM proc_creation WHERE image ILIKE ? ORDER BY timestamp LIMIT 50`, like)
	}

	jsonOK(w, result)
}

func handleIocExtracted(w http.ResponseWriter, r *http.Request) {
	iocType := r.URL.Query().Get("type")
	q := r.URL.Query().Get("q")
	where := " WHERE 1=1"
	args := []any{}
	if iocType != "" {
		where += " AND type = ?"
		args = append(args, iocType)
	}
	if q != "" {
		like := "%" + q + "%"
		where += " AND (value ILIKE ? OR source ILIKE ? OR context ILIKE ?)"
		args = append(args, like, like, like)
	}
	rows := safeQuery(`SELECT type, value, source, context, count, first_seen FROM ioc_extracted`+where+
		` ORDER BY count DESC, type, value LIMIT 5000`, args...)
	typeCounts := safeQuery(`SELECT type, COUNT(*) AS cnt, SUM(count) AS total FROM ioc_extracted GROUP BY type ORDER BY total DESC`)
	jsonOK(w, map[string]any{
		"rows":        rows,
		"type_counts": typeCounts,
		"total":       len(rows),
	})
}

func handleIocExtractedRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonErr(w, 405, "method not allowed")
		return
	}
	iocext.ExtractAll(db)
	jsonOK(w, map[string]any{"status": "done"})
}

// handleChain returns a chronologically-ordered chain of events related to a
// pivot value (process basename / file path / hash / IP / user). The chain
// pulls from multiple artifact tables and tags each event with its source
// category for timeline visualization.
//
//   GET /api/chain?q=<value>
//
// Returns: { "events": [...], "pivot": "...", "summary": {...} }
func handleChain(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if q == "" {
		jsonOK(w, map[string]any{"events": []any{}})
		return
	}
	// Detector hit values arrive as "svchost.exe (PID 884) @ 0xE917025000"
	// or "cmd.exe (PID 10396) parent=vmtoolsd.exe". Extract process name and PID
	// so disk-table queries (proc_creation, prefetch, amcache…) match correctly.
	processName := q
	var pidHint int64
	if idx := strings.Index(q, " (PID "); idx > 0 {
		processName = q[:idx]
		rest := q[idx+6:]
		if end := strings.IndexAny(rest, ") "); end > 0 {
			fmt.Sscanf(rest[:end], "%d", &pidHint)
		}
	}
	like := "%" + processName + "%"
	base := strings.ToLower(filepath.Base(strings.ReplaceAll(processName, "\\", "/")))
	likeBase := "%" + base + "%"
	// Windows paths that lost backslashes (e.g. "C:UsersIEUserDownloadsFirefox.exe"):
	// filepath.Base returns the whole string; extract filename from the last known dir segment.
	if strings.Contains(processName, ":") && !strings.Contains(processName, "\\") && !strings.Contains(processName, "/") {
		for _, seg := range []string{"Downloads", "Desktop", "Documents", "AppData", "Temp", "System32", "SysWOW64", "Users", "Roaming", "Local"} {
			if idx := strings.LastIndex(processName, seg); idx >= 0 {
				candidate := strings.TrimSpace(processName[idx+len(seg):])
				if candidate != "" && len(candidate) < len(base) {
					base = strings.ToLower(candidate)
					likeBase = "%" + base + "%"
				}
				break
			}
		}
	}

	type ev struct {
		TS       string `json:"ts"`
		Source   string `json:"source"`
		Severity string `json:"severity,omitempty"`
		Action   string `json:"action"`
		Detail   string `json:"detail,omitempty"`
		Extra    string `json:"extra,omitempty"`
		Related  string `json:"related,omitempty"`
		User     string `json:"user,omitempty"`
	}
	var events []ev
	addRows := func(rows []map[string]any, mk func(map[string]any) ev) {
		for _, row := range rows {
			e := mk(row)
			if e.TS != "" {
				events = append(events, e)
			}
		}
	}
	tsStr := func(v any) string {
		if v == nil {
			return ""
		}
		s := fmt.Sprintf("%v", v)
		if len(s) >= 19 {
			return strings.Replace(s[:19], "T", " ", 1)
		}
		return s
	}
	str := func(v any) string {
		if v == nil {
			return ""
		}
		return fmt.Sprintf("%v", v)
	}

	tables := getExistingTables()

	// proc_creation — central source
	if tables["proc_creation"] {
		addRows(safeQuery(`SELECT timestamp, image, parent_image, cmdline, user_name, integrity_level, pid, ppid
			FROM proc_creation
			WHERE timestamp IS NOT NULL AND timestamp >= '1995-01-01' AND timestamp <= '2099-12-31'
			AND (image ILIKE ? OR parent_image ILIKE ? OR cmdline ILIKE ?)
			ORDER BY timestamp LIMIT 500`, likeBase, likeBase, like),
			func(r map[string]any) ev {
				img := str(r["image"])
				p := str(r["parent_image"])
				bImg := filepath.Base(strings.ReplaceAll(img, "\\", "/"))
				bP := filepath.Base(strings.ReplaceAll(p, "\\", "/"))
				action := "Process spawn"
				if strings.EqualFold(bImg, base) {
					action = "Created (spawned by " + bP + ")"
				} else if strings.EqualFold(bP, base) {
					action = "Spawned " + bImg
				}
				return ev{
					TS:      tsStr(r["timestamp"]),
					Source:  "proc_creation",
					Action:  action,
					Detail:  img,
					Extra:   str(r["cmdline"]),
					Related: bP,
					User:    str(r["user_name"]),
				}
			})
	}

	// defender — high-priority events
	if tables["defender_events"] {
		addRows(safeQuery(`SELECT timestamp, threat_name, severity, path, action, detection_user, process_name, sha256, event_id
			FROM defender_events
			WHERE (path ILIKE ? OR threat_name ILIKE ? OR process_name ILIKE ? OR sha256 ILIKE ?)
			ORDER BY timestamp LIMIT 200`, like, like, like, like),
			func(r map[string]any) ev {
				return ev{
					TS:       tsStr(r["timestamp"]),
					Source:   "defender",
					Severity: "high",
					Action:   "Defender detection: " + str(r["threat_name"]),
					Detail:   str(r["path"]),
					Extra:    "Action: " + str(r["action"]) + " · " + str(r["severity"]),
					Related:  str(r["process_name"]),
					User:     str(r["detection_user"]),
				}
			})
	}

	// auth_events
	if tables["auth_events"] {
		addRows(safeQuery(`SELECT timestamp, event_id, "user", domain, src_ip, logon_type, process_name, workstation
			FROM auth_events
			WHERE (LOWER("user") = LOWER(?) OR src_ip = ? OR process_name ILIKE ?)
			ORDER BY timestamp LIMIT 200`, q, q, like),
			func(r map[string]any) ev {
				eid := str(r["event_id"])
				act := "Authentication " + eid
				if eid == "4624" {
					act = "Logon success"
				} else if eid == "4625" {
					act = "Logon failure"
				} else if eid == "4648" {
					act = "Explicit creds logon"
				}
				ip := str(r["src_ip"])
				detail := "User: " + str(r["user"])
				if ip != "" && ip != "-" {
					detail += " · IP: " + ip
				}
				return ev{
					TS:     tsStr(r["timestamp"]),
					Source: "auth",
					Action: act,
					Detail: detail,
					Extra:  "Type " + str(r["logon_type"]) + " · " + str(r["process_name"]),
					User:   str(r["user"]),
				}
			})
	}

	// prefetch
	if tables["prefetch"] {
		addRows(safeQuery(`SELECT last_run, filename, path, run_count
			FROM prefetch
			WHERE last_run IS NOT NULL AND last_run >= '1995-01-01' AND last_run <= '2099-12-31'
			AND (filename ILIKE ? OR path ILIKE ?)
			ORDER BY last_run LIMIT 100`, likeBase, like),
			func(r map[string]any) ev {
				return ev{
					TS:     tsStr(r["last_run"]),
					Source: "prefetch",
					Action: "Executed (prefetch)",
					Detail: str(r["filename"]),
					Extra:  "Runs: " + str(r["run_count"]) + " · " + str(r["path"]),
				}
			})
	}

	// amcache
	if tables["amcache"] {
		addRows(safeQuery(`SELECT first_seen, path, sha256, publisher, version
			FROM amcache
			WHERE path ILIKE ?
			ORDER BY first_seen LIMIT 100`, like),
			func(r map[string]any) ev {
				return ev{
					TS:     tsStr(r["first_seen"]),
					Source: "amcache",
					Action: "First seen on system",
					Detail: str(r["path"]),
					Extra:  str(r["publisher"]) + " · " + str(r["version"]) + " · " + str(r["sha256"]),
				}
			})
	}

	// persistence
	if tables["persistence"] {
		addRows(safeQuery(`SELECT modified, type, name, command, key_path
			FROM persistence
			WHERE command ILIKE ? OR name ILIKE ? OR key_path ILIKE ?
			ORDER BY modified NULLS LAST LIMIT 100`, like, likeBase, like),
			func(r map[string]any) ev {
				return ev{
					TS:       tsStr(r["modified"]),
					Source:   "persistence",
					Severity: "med",
					Action:   "Persistence: " + str(r["type"]) + " · " + str(r["name"]),
					Detail:   str(r["command"]),
					Extra:    "Key: " + str(r["key_path"]),
				}
			})
	}

	// bam_dam
	if tables["bam_dam"] {
		addRows(safeQuery(`SELECT last_run, path, sid, source
			FROM bam_dam
			WHERE path ILIKE ?
			ORDER BY last_run LIMIT 100`, like),
			func(r map[string]any) ev {
				return ev{
					TS:     tsStr(r["last_run"]),
					Source: "bam_dam",
					Action: "BAM/DAM execution record",
					Detail: str(r["path"]),
					Extra:  str(r["source"]) + " · SID: " + str(r["sid"]),
				}
			})
	}

	// userassist
	if tables["userassist"] {
		addRows(safeQuery(`SELECT last_run, path, run_count, focus_count, focus_duration
			FROM userassist
			WHERE path ILIKE ?
			ORDER BY last_run LIMIT 100`, like),
			func(r map[string]any) ev {
				return ev{
					TS:     tsStr(r["last_run"]),
					Source: "userassist",
					Action: "User-launched (UserAssist)",
					Detail: str(r["path"]),
					Extra:  "Runs: " + str(r["run_count"]) + " · Focus: " + str(r["focus_count"]),
				}
			})
	}

	// sysmon_process
	if tables["sysmon_process"] {
		addRows(safeQuery(`SELECT timestamp, image, parent_image, cmdline, sha256, user_name
			FROM sysmon_process
			WHERE image ILIKE ? OR parent_image ILIKE ? OR cmdline ILIKE ?
			ORDER BY timestamp LIMIT 200`, likeBase, likeBase, like),
			func(r map[string]any) ev {
				return ev{
					TS:     tsStr(r["timestamp"]),
					Source: "sysmon",
					Action: "Sysmon process",
					Detail: str(r["image"]),
					Extra:  str(r["cmdline"]),
					User:   str(r["user_name"]),
				}
			})
	}

	// sysmon_network
	if tables["sysmon_network"] {
		addRows(safeQuery(`SELECT timestamp, image, dst_ip, dst_port, dst_host, user_name
			FROM sysmon_network
			WHERE image ILIKE ? OR dst_ip = ? OR dst_host ILIKE ?
			ORDER BY timestamp LIMIT 200`, likeBase, q, like),
			func(r map[string]any) ev {
				return ev{
					TS:     tsStr(r["timestamp"]),
					Source: "sysmon_net",
					Action: "Network connection",
					Detail: str(r["image"]) + " → " + str(r["dst_ip"]) + ":" + str(r["dst_port"]),
					Extra:  str(r["dst_host"]),
					User:   str(r["user_name"]),
				}
			})
	}

	// evtx_events (general fallback for less-common matches)
	if tables["evtx_events"] {
		addRows(safeQuery(`SELECT timestamp, event_id, channel, computer, message
			FROM evtx_events
			WHERE timestamp IS NOT NULL AND timestamp >= '1995-01-01' AND timestamp <= '2099-12-31'
			AND message ILIKE ?
			ORDER BY timestamp LIMIT 100`, like),
			func(r map[string]any) ev {
				return ev{
					TS:     tsStr(r["timestamp"]),
					Source: "evtx",
					Action: "Event " + str(r["event_id"]) + " · " + str(r["channel"]),
					Detail: str(r["message"]),
				}
			})
	}

	// mem_pslist — processes found in RAM (use create_time if available).
	// When pidHint is set (from a detector hit like "svchost.exe (PID 884) @ 0x…")
	// also match by exact PID so we get the right svchost instance, not all of them.
	if tables["mem_pslist"] {
		pslistWhere := "LOWER(p.name) LIKE LOWER(?) OR c.cmdline ILIKE ?"
		pslistArgs := []any{likeBase, like}
		if pidHint > 0 {
			pslistWhere += " OR p.pid = ?"
			pslistArgs = append(pslistArgs, pidHint)
		}
		addRows(safeQuery(`
			SELECT p.pid, p.ppid, p.name, p.create_time, p.threads, p.handles,
			       c.cmdline
			FROM mem_pslist p
			LEFT JOIN mem_cmdline c ON p.pid = c.pid
			WHERE `+pslistWhere+`
			LIMIT 100`, pslistArgs...),
			func(r map[string]any) ev {
				ct := tsStr(r["create_time"])
				return ev{
					TS:     ct,
					Source: "mem_pslist",
					Action: "Process in RAM snapshot",
					Detail: str(r["name"]) + " (PID " + str(r["pid"]) + ")",
					Extra:  "Threads:" + str(r["threads"]) + " Handles:" + str(r["handles"]),
					User:   str(r["cmdline"]),
				}
			})
	}

	// mem_netscan — network connections captured from RAM
	if tables["mem_netscan"] {
		netscanWhere := "LOWER(name) LIKE LOWER(?) OR remote_addr ILIKE ? OR local_addr ILIKE ?"
		netscanArgs := []any{likeBase, like, like}
		if pidHint > 0 {
			netscanWhere += " OR pid = ?"
			netscanArgs = append(netscanArgs, pidHint)
		}
		addRows(safeQuery(`
			SELECT pid, name, proto, local_addr, local_port,
			       remote_addr, remote_port, "state", created
			FROM mem_netscan
			WHERE `+netscanWhere+`
			LIMIT 200`, netscanArgs...),
			func(r map[string]any) ev {
				remote := str(r["remote_addr"]) + ":" + str(r["remote_port"])
				return ev{
					TS:     tsStr(r["created"]),
					Source: "mem_netscan",
					Action: "RAM: Network (" + str(r["state"]) + ")",
					Detail: str(r["name"]) + " → " + remote,
					Extra:  str(r["proto"]) + " · PID " + str(r["pid"]),
				}
			})
	}

	// mem_malfind — injected code regions (no timestamp — use "~~~~" so they sort to end)
	if tables["mem_malfind"] {
		malfindWhere := "LOWER(name) LIKE LOWER(?)"
		malfindArgs := []any{likeBase}
		if pidHint > 0 {
			malfindWhere += " OR pid = ?"
			malfindArgs = append(malfindArgs, pidHint)
		}
		malfindRows := safeQuery(`
			SELECT pid, name, address, size, reason, LEFT(disasm, 200) AS disasm_short
			FROM mem_malfind
			WHERE `+malfindWhere+`
			LIMIT 50`, malfindArgs...)
		for _, row := range malfindRows {
			events = append(events, ev{
				TS:       "~~~~",
				Source:   "mem_malfind",
				Severity: "high",
				Action:   "RAM: Injected code region",
				Detail:   str(row["name"]) + " (PID " + str(row["pid"]) + ") @ " + str(row["address"]),
				Extra:    "Size: " + str(row["size"]) + " · " + str(row["reason"]),
				User:     str(row["disasm_short"]),
			})
		}
	}

	if tables["browser_downloads"] {
		addRows(safeQuery(`
			SELECT start_time, browser, url, local_path, end_time, state
			FROM browser_downloads
			WHERE local_path ILIKE ? OR local_path ILIKE ? OR url ILIKE ?
			ORDER BY start_time LIMIT 100`, like, likeBase, like),
			func(r map[string]any) ev {
				return ev{
					TS:     tsStr(r["start_time"]),
					Source: "browser_dl",
					Action: "Browser download",
					Detail: str(r["local_path"]),
					Extra:  str(r["browser"]) + " · " + str(r["url"]),
				}
			})
	}
	if tables["browser_history"] {
		addRows(safeQuery(`
			SELECT visit_time, browser, url, title
			FROM browser_history
			WHERE url ILIKE ? OR title ILIKE ?
			ORDER BY visit_time LIMIT 100`, like, like),
			func(r map[string]any) ev {
				return ev{
					TS:     tsStr(r["visit_time"]),
					Source: "browser",
					Action: "Browser visit",
					Detail: str(r["url"]),
					Extra:  str(r["title"]) + " · " + str(r["browser"]),
				}
			})
	}

	// Sort by ts then source
	sort.Slice(events, func(i, j int) bool {
		if events[i].TS != events[j].TS {
			return events[i].TS < events[j].TS
		}
		return events[i].Source < events[j].Source
	})

	// Cap total at 1500 events
	if len(events) > 1500 {
		events = events[:1500]
	}

	// Summary by source
	bySrc := map[string]int{}
	for _, e := range events {
		bySrc[e.Source]++
	}

	jsonOK(w, map[string]any{
		"pivot":   q,
		"events":  events,
		"summary": bySrc,
	})
}

// handleGraph returns a process-interaction graph derived from proc_creation
// (4688) plus correlations against amcache/defender/persistence/network.
// Optional ?pivot=<image_basename> filters to nodes within 2 hops of the pivot.
// Optional ?user=<user_name> filters by user. ?since=<ISO> filters by timestamp.
func handleGraph(w http.ResponseWriter, r *http.Request) {
	pivot := strings.ToLower(r.URL.Query().Get("pivot"))
	user := r.URL.Query().Get("user")

	// Aggregate proc_creation by (parent_image, image, user_name) — each tuple
	// becomes an edge.
	where := " WHERE image IS NOT NULL AND image != ''"
	args := []any{}
	if user != "" {
		where += " AND user_name = ?"
		args = append(args, user)
	}

	rows := safeQuery(`
		SELECT
			COALESCE(parent_image, '') AS parent,
			image AS child,
			COALESCE(user_name, '') AS u,
			COALESCE(integrity_level, '') AS integrity,
			COUNT(*) AS hits,
			MIN(timestamp) AS first_ts,
			MAX(timestamp) AS last_ts,
			MIN(cmdline) AS sample_cmd
		FROM proc_creation`+where+`
		GROUP BY parent, child, u, integrity
		ORDER BY hits DESC
		LIMIT 5000
	`, args...)

	// Build node map (key = lowercase basename) and edges.
	type nodeAgg struct {
		Name      string `json:"name"`
		Hits      int64  `json:"hits"`
		FirstTS   string `json:"first_ts,omitempty"`
		LastTS    string `json:"last_ts,omitempty"`
		Users     []string `json:"users,omitempty"`
		Integrity string `json:"integrity,omitempty"`
		Risk      string `json:"risk"` // "high" | "med" | ""
		Sample    string `json:"sample,omitempty"`
	}
	nodes := map[string]*nodeAgg{}
	type edgeRow struct {
		Src   string `json:"src"`
		Dst   string `json:"dst"`
		Hits  int64  `json:"hits"`
		User  string `json:"user,omitempty"`
	}
	edges := []edgeRow{}

	bumpNode := func(rawPath, user, integ, ts, cmd string, hits int64) {
		base := strings.ToLower(filepath.Base(strings.ReplaceAll(rawPath, "\\", "/")))
		if base == "" {
			return
		}
		n, ok := nodes[base]
		if !ok {
			n = &nodeAgg{Name: base}
			nodes[base] = n
		}
		n.Hits += hits
		if ts != "" && (n.FirstTS == "" || ts < n.FirstTS) {
			n.FirstTS = ts
		}
		if ts != "" && (n.LastTS == "" || ts > n.LastTS) {
			n.LastTS = ts
		}
		if user != "" {
			seen := false
			for _, u := range n.Users {
				if u == user {
					seen = true
					break
				}
			}
			if !seen && len(n.Users) < 5 {
				n.Users = append(n.Users, user)
			}
		}
		if integ != "" && (n.Integrity == "" || n.Integrity == "RAM") {
			n.Integrity = integ
		}
		if cmd != "" && len(n.Sample) < 5 {
			n.Sample = cmd
		}
		// Risk classification: malware-suspect paths
		low := strings.ToLower(rawPath)
		if strings.Contains(low, `\бухсофт\`) || strings.Contains(low, "/бухсофт/") ||
			strings.Contains(low, `\onedrivetemp\`) || strings.Contains(low, "/onedrivetemp/") ||
			strings.Contains(low, `\checkpfr\`) || strings.Contains(low, "/checkpfr/") ||
			strings.Contains(low, `\appdata\local\temp\`) || strings.Contains(low, "/appdata/local/temp/") ||
			strings.Contains(low, `\users\public\`) || strings.Contains(low, "/users/public/") {
			n.Risk = "high"
		} else if n.Risk == "" && (strings.Contains(low, `\appdata\`) || strings.Contains(low, "/appdata/")) {
			n.Risk = "med"
		}
	}
	for _, r := range rows {
		parent, _ := r["parent"].(string)
		child, _ := r["child"].(string)
		u, _ := r["u"].(string)
		integ, _ := r["integrity"].(string)
		ts := fmt.Sprintf("%v", r["last_ts"])
		first := fmt.Sprintf("%v", r["first_ts"])
		cmd, _ := r["sample_cmd"].(string)
		hits, _ := r["hits"].(int64)
		bumpNode(parent, u, integ, first, "", hits)
		bumpNode(child, u, integ, ts, cmd, hits)
		if parent == "" {
			continue
		}
		pBase := strings.ToLower(filepath.Base(strings.ReplaceAll(parent, "\\", "/")))
		cBase := strings.ToLower(filepath.Base(strings.ReplaceAll(child, "\\", "/")))
		if pBase == "" || cBase == "" || pBase == cBase {
			continue
		}
		edges = append(edges, edgeRow{Src: pBase, Dst: cBase, Hits: hits, User: u})
	}

	// Inject mem_pslist processes as graph nodes so RAM-only processes (no 4688
	// event on disk) appear in the graph and correlate with other artifacts.
	for _, r := range safeQuery(`
		SELECT p.name AS name,
		       COALESCE(pp.name, '') AS parent_name,
		       COALESCE(c.cmdline, '') AS cmd,
		       COALESCE(STRFTIME(p.create_time, '%Y-%m-%dT%H:%M:%SZ'), '') AS ts
		FROM mem_pslist p
		LEFT JOIN mem_pslist pp ON p.ppid = pp.pid
		LEFT JOIN mem_cmdline c ON p.pid = c.pid
		WHERE p.name IS NOT NULL AND p.name != ''
		LIMIT 500`) {
		child, _ := r["name"].(string)
		parent, _ := r["parent_name"].(string)
		ts, _ := r["ts"].(string)
		cmd, _ := r["cmd"].(string)
		bumpNode(child, "", "RAM", ts, cmd, 1)
		if parent != "" {
			bumpNode(parent, "", "RAM", "", "", 1)
			cBase := strings.ToLower(filepath.Base(strings.ReplaceAll(child, "\\", "/")))
			pBase := strings.ToLower(filepath.Base(strings.ReplaceAll(parent, "\\", "/")))
			if pBase != "" && cBase != "" && pBase != cBase {
				edges = append(edges, edgeRow{Src: pBase, Dst: cBase, Hits: 1, User: "RAM"})
			}
		}
	}
	// Elevate risk for processes with malfind injection hits.
	for _, r := range safeQuery(`SELECT DISTINCT LOWER(name) AS n FROM mem_malfind`) {
		if n, ok := r["n"].(string); ok {
			if node, exists := nodes[n]; exists {
				node.Risk = "high"
			}
		}
	}

	// Optionally restrict to ≤2 hops of the pivot node.
	if pivot != "" {
		keep := map[string]bool{pivot: true}
		// 1-hop: any edge touching pivot
		for _, e := range edges {
			if e.Src == pivot {
				keep[e.Dst] = true
			}
			if e.Dst == pivot {
				keep[e.Src] = true
			}
		}
		// 2-hop: any edge touching 1-hop nodes
		ext := map[string]bool{}
		for k := range keep {
			ext[k] = true
		}
		for _, e := range edges {
			if keep[e.Src] {
				ext[e.Dst] = true
			}
			if keep[e.Dst] {
				ext[e.Src] = true
			}
		}
		newNodes := map[string]*nodeAgg{}
		for k := range ext {
			if n, ok := nodes[k]; ok {
				newNodes[k] = n
			}
		}
		newEdges := edges[:0]
		for _, e := range edges {
			if ext[e.Src] && ext[e.Dst] {
				newEdges = append(newEdges, e)
			}
		}
		nodes, edges = newNodes, newEdges
	}

	// Convert nodes map to slice, sorted by hits desc.
	out := make([]*nodeAgg, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Hits > out[j].Hits })

	jsonOK(w, map[string]any{
		"nodes": out,
		"edges": edges,
		"total_processes": countFirst(safeQuery(`SELECT COUNT(*) AS c FROM proc_creation`)),
	})
}

func handleLnk(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	where := " WHERE 1=1"
	args := []any{}
	if q != "" {
		like := "%" + q + "%"
		where += " AND (path ILIKE ? OR target_path ILIKE ? OR machine_id ILIKE ? OR args ILIKE ?)"
		args = append(args, like, like, like, like)
	}
	rows := safeQuery(`SELECT path, target_path, created, modified, accessed, machine_id, drive_serial, volume_label, args, working_dir FROM lnk_files`+where+` ORDER BY modified DESC NULLS LAST LIMIT 5000`, args...)
	total := safeQuery(`SELECT COUNT(*) AS cnt FROM lnk_files` + where, args...)
	jsonOK(w, map[string]any{"rows": rows, "total": countFirst(total)})
}

func handleJumplists(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	where := " WHERE 1=1"
	args := []any{}
	if q != "" {
		like := "%" + q + "%"
		where += " AND (app_name ILIKE ? OR target_path ILIKE ? OR app_id ILIKE ?)"
		args = append(args, like, like, like)
	}
	rows := safeQuery(`SELECT app_id, app_name, entry_type, target_path, created, modified, accessed, access_count, pin_status, entry_id FROM jumplists`+where+` ORDER BY modified DESC NULLS LAST LIMIT 5000`, args...)
	total := safeQuery(`SELECT COUNT(*) AS cnt FROM jumplists` + where, args...)
	jsonOK(w, map[string]any{"rows": rows, "total": countFirst(total)})
}

func handleRecycleBin(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	where := " WHERE 1=1"
	args := []any{}
	if q != "" {
		like := "%" + q + "%"
		where += " AND (original_path ILIKE ? OR sid ILIKE ?)"
		args = append(args, like, like)
	}
	rows := safeQuery(`SELECT original_path, deleted_at, size, sid, i_file, r_file FROM recycle_bin`+where+` ORDER BY deleted_at DESC NULLS LAST LIMIT 5000`, args...)
	total := safeQuery(`SELECT COUNT(*) AS cnt FROM recycle_bin` + where, args...)
	jsonOK(w, map[string]any{"rows": rows, "total": countFirst(total)})
}

func handleShellbags(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	where := " WHERE 1=1"
	args := []any{}
	if q != "" {
		like := "%" + q + "%"
		where += ` AND (path ILIKE ? OR "user" ILIKE ? OR source ILIKE ? OR item_type ILIKE ?)`
		args = append(args, like, like, like, like)
	}
	rows := safeQuery(`SELECT path, last_modified, "user", source, item_type FROM shellbags`+where+` ORDER BY last_modified DESC NULLS LAST LIMIT 5000`, args...)
	total := safeQuery(`SELECT COUNT(*) AS cnt FROM shellbags` + where, args...)
	jsonOK(w, map[string]any{"rows": rows, "total": countFirst(total)})
}

func handleUsnjrnl(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	reason := r.URL.Query().Get("reason")
	where := " WHERE 1=1"
	args := []any{}
	if q != "" {
		like := "%" + q + "%"
		where += " AND (path ILIKE ? OR reason ILIKE ?)"
		args = append(args, like, like)
	}
	if reason != "" {
		where += " AND reason ILIKE ?"
		args = append(args, "%"+reason+"%")
	}
	rows := safeQuery(`SELECT usn, path, reason, timestamp, file_attributes, source_info FROM usnjrnl`+where+` ORDER BY timestamp DESC NULLS LAST LIMIT 10000`, args...)
	total := safeQuery(`SELECT COUNT(*) AS cnt FROM usnjrnl` + where, args...)
	reasons := safeQuery(`SELECT reason, COUNT(*) AS cnt FROM usnjrnl GROUP BY reason ORDER BY cnt DESC LIMIT 20`)
	jsonOK(w, map[string]any{"rows": rows, "total": countFirst(total), "reasons": reasons})
}
