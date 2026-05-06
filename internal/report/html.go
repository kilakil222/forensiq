package report

import (
	"database/sql"
	"fmt"
	"html/template"
	"io"
	"strings"
	"time"
)

// ExecFinding is one bullet point in the executive summary.
type ExecFinding struct {
	Title string
	Sev   string // HIGH | MED | LOW
}

// ExecSummary is auto-generated from the case data.
type ExecSummary struct {
	Verdict         string
	VerdictClass    string // verdict-critical | verdict-high | verdict-medium | verdict-low | verdict-clean
	TimeRange       string
	Duration        string
	HighCount       int
	MedCount        int
	TopFindings     []ExecFinding
	Tactics         []string
	AffectedUsers   []string
	Recommendations []string
}

type ReportData struct {
	CaseName       string
	CreatedAt      string
	GeneratedAt    string
	HighCount      int
	MedCount       int
	LowCount       int
	Exec           ExecSummary
	ThreatFindings []ThreatFinding
	Sections       []Section
}

// ThreatFinding is one row from ioc_indicators written by detect/hunt/yara.
type ThreatFinding struct {
	Source       string
	Type         string
	Value        string
	Confidence   string
	Notes        string
	Technique    string
	SevClass     string // css class: sev-high | sev-med | sev-low
	TriageStatus string // TP | FP | Investigating | ""
}

type Section struct {
	Title  string
	Tables []Table
}

type Table struct {
	Title   string
	Headers []string
	Rows    [][]string
}

func Generate(db *sql.DB, w io.Writer) error {
	data := ReportData{GeneratedAt: time.Now().UTC().Format(time.RFC3339)}

	db.QueryRow("SELECT name, created_at FROM case_meta WHERE id = 1").
		Scan(&data.CaseName, &data.CreatedAt)

	data.ThreatFindings = buildThreatFindings(db)
	for _, f := range data.ThreatFindings {
		switch f.Confidence {
		case "HIGH":
			data.HighCount++
		case "MED":
			data.MedCount++
		default:
			data.LowCount++
		}
	}
	data.Exec = buildExecSummary(db, data.HighCount, data.MedCount)

	data.Sections = append(data.Sections, buildSysmonSection(db))
	data.Sections = append(data.Sections, buildCorrelationSection(db))
	data.Sections = append(data.Sections, buildProcessCorrelationSection(db))
	data.Sections = append(data.Sections, buildNetworkCorrelationSection(db))
	data.Sections = append(data.Sections, buildSuspiciousScriptExecutionSection(db))
	data.Sections = append(data.Sections, buildSummarySection(db))
	data.Sections = append(data.Sections, buildDefenderSection(db))
	data.Sections = append(data.Sections, buildMalfindSection(db))
	data.Sections = append(data.Sections, buildExecutionSection(db))
	data.Sections = append(data.Sections, buildPersistenceSection(db))
	data.Sections = append(data.Sections, buildPSHistorySection(db))
	data.Sections = append(data.Sections, buildSuspiciousAuthSection(db))
	data.Sections = append(data.Sections, buildLinuxAuthSection(db))
	data.Sections = append(data.Sections, buildLinuxPersistenceSection(db))
	data.Sections = append(data.Sections, buildUsnJrnlSection(db))
	data.Sections = append(data.Sections, buildJumpListsSection(db))
	data.Sections = append(data.Sections, buildLNKSection(db))
	data.Sections = append(data.Sections, buildRecycleBinSection(db))
	data.Sections = append(data.Sections, buildShellbagsSection(db))
	data.Sections = append(data.Sections, buildUserAssistSection(db))
	data.Sections = append(data.Sections, buildBAMSection(db))
	data.Sections = append(data.Sections, buildKeyEventsSection(db))
	data.Sections = append(data.Sections, buildSuspiciousFilesSection(db))
	data.Sections = append(data.Sections, buildBrowserSection(db))
	data.Sections = append(data.Sections, buildTimelineSection(db))
	data.Sections = append(data.Sections, buildIOCSection(db))
	data.Sections = append(data.Sections, buildMITRESection(db))
	data.Sections = append(data.Sections, buildSkippedSection(db))

	return tmpl.Execute(w, data)
}

func buildThreatFindings(db *sql.DB) []ThreatFinding {
	rows, err := db.Query(`
		SELECT i.source, i."type", i.value, i.confidence,
		       COALESCE(i.notes, ''), COALESCE(i.related_campaign, ''),
		       COALESCE(cn.text, '') AS triage_status
		FROM ioc_indicators i
		LEFT JOIN case_notes cn ON cn.ref_type = 'triage' AND cn.ref_id = i.source
		WHERE i.source LIKE 'detect:%' OR i.source LIKE 'sigma:%' OR i.source LIKE 'yaralite:%'
		ORDER BY
		  CASE i.confidence WHEN 'HIGH' THEN 1 WHEN 'MED' THEN 2 ELSE 3 END,
		  i.source, i.value
	`)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var findings []ThreatFinding
	for rows.Next() {
		var f ThreatFinding
		rows.Scan(&f.Source, &f.Type, &f.Value, &f.Confidence, &f.Notes, &f.Technique, &f.TriageStatus)
		switch f.Confidence {
		case "HIGH":
			f.SevClass = "sev-high"
		case "MED":
			f.SevClass = "sev-med"
		default:
			f.SevClass = "sev-low"
		}
		findings = append(findings, f)
	}
	return findings
}

func buildSummarySection(db *sql.DB) Section {
	type stat struct{ label, query string }
	stats := []stat{
		{"MFT entries", "SELECT COUNT(*) FROM mft"},
		{"EVTX events", "SELECT COUNT(*) FROM evtx_events"},
		{"Auth events", "SELECT COUNT(*) FROM auth_events"},
		{"Prefetch entries", "SELECT COUNT(*) FROM prefetch"},
		{"Shimcache entries", "SELECT COUNT(*) FROM shimcache"},
		{"Amcache entries", "SELECT COUNT(*) FROM amcache"},
		{"Persistence entries", "SELECT COUNT(*) FROM persistence"},
		{"Scheduled tasks", "SELECT COUNT(*) FROM scheduled_tasks"},
		{"Services", "SELECT COUNT(*) FROM services"},
		{"LNK files", "SELECT COUNT(*) FROM lnk_files"},
		{"$UsnJrnl records", "SELECT COUNT(*) FROM usnjrnl"},
		{"Processes (memory)", "SELECT COUNT(*) FROM mem_pslist"},
		{"Malfind hits", "SELECT COUNT(*) FROM mem_malfind"},
		{"IOC indicators", "SELECT COUNT(*) FROM ioc_indicators"},
		{"Shellbag entries", "SELECT COUNT(*) FROM shellbags"},
	}
	var rows [][]string
	for _, s := range stats {
		var count int64
		db.QueryRow(s.query).Scan(&count)
		rows = append(rows, []string{s.label, fmt.Sprintf("%d", count)})
	}
	return Section{Title: "Summary", Tables: []Table{{
		Title: "Artifact Counts", Headers: []string{"Artifact", "Count"}, Rows: rows,
	}}}
}

func buildTimelineSection(db *sql.DB) Section {
	// Forensically relevant event_ids only — avoids flooding the report with
	// Windows Update / ContentDeliveryManager noise (event 325 etc).
	rows, err := db.Query(`
		SELECT ts, source, event, detail FROM (
			-- MFT: executables/scripts, exclude known-noisy installer paths
			SELECT modified AS ts, 'MFT' AS source, 'MODIFIED' AS event, path AS detail
				FROM mft
				WHERE NOT is_dir
				  AND modified IS NOT NULL
				  AND (lower(path) LIKE '%.exe' OR lower(path) LIKE '%.dll' OR lower(path) LIKE '%.bat' OR lower(path) LIKE '%.cmd' OR lower(path) LIKE '%.ps1' OR lower(path) LIKE '%.vbs' OR lower(path) LIKE '%.js' OR lower(path) LIKE '%.pif' OR lower(path) LIKE '%.scr' OR lower(path) LIKE '%.hta' OR lower(path) LIKE '%.lnk')
				  AND NOT (lower(path) LIKE '%microsoft office%' OR lower(path) LIKE '%windows installer%' OR lower(path) LIKE '%winsxs%' OR lower(path) LIKE '%servicing%')
			UNION ALL
			-- EVTX: security/forensic event IDs only (4103 excluded — too verbose)
			SELECT timestamp, 'EVTX', CAST(event_id AS VARCHAR), LEFT(COALESCE(message,''), 120)
				FROM evtx_events
				WHERE timestamp IS NOT NULL
				  AND event_id IN (
					4624,4625,4634,4647,4648,  -- logon/logoff
					4688,4689,                  -- process create/exit
					4698,4702,4699,             -- scheduled task
					7045,7036,                  -- service install/state
					4104,                       -- PowerShell scriptblock
					4663,4656,                  -- object access
					1102,1100,                  -- log cleared
					4720,4722,4723,4724,4725,4726, -- account mgmt
					4732,4756,                  -- group membership
					4776,4771,4768,4769         -- Kerberos / NTLM
				  )
			UNION ALL
			-- Prefetch: execution evidence
			SELECT last_run, 'Prefetch', 'EXECUTED', COALESCE(filename,'')
				FROM prefetch
				WHERE last_run IS NOT NULL
			UNION ALL
			-- Defender: always show, most critical
			SELECT timestamp, 'Defender', COALESCE(threat_name,'unknown'),
				COALESCE(severity,'') || ' | ' || COALESCE(path,'') || ' | ' || COALESCE(action,'')
				FROM defender_events
				WHERE timestamp IS NOT NULL AND COALESCE(threat_name,'') != ''
			UNION ALL
			-- Auth summary
			SELECT timestamp, 'Auth', 'LOGON_TYPE_' || CAST(logon_type AS VARCHAR),
				COALESCE("user",'') || ' @ ' || COALESCE(domain,'') ||
				CASE WHEN COALESCE(src_ip,'') NOT IN ('-','') THEN ' from ' || src_ip ELSE '' END
				FROM auth_events WHERE timestamp IS NOT NULL
		) t
		QUALIFY ROW_NUMBER() OVER (PARTITION BY source, event ORDER BY ts DESC) <= 10
		ORDER BY ts DESC
		LIMIT 500
	`)
	if err != nil {
		return Section{Title: "Timeline"}
	}
	defer rows.Close()

	var tableRows [][]string
	for rows.Next() {
		var ts time.Time
		var source, event, detail string
		rows.Scan(&ts, &source, &event, &detail)
		tableRows = append(tableRows, []string{
			ts.Format("2006-01-02 15:04:05"), source, event, detail,
		})
	}
	return Section{Title: "Timeline (500 most recent events)", Tables: []Table{{
		Headers: []string{"Timestamp", "Source", "Event", "Detail"},
		Rows:    tableRows,
	}}}
}

func buildDefenderSection(db *sql.DB) Section {
	rows, err := db.Query(`
		SELECT timestamp, event_id, threat_name, severity, path, action, process_name, sha256
		FROM defender_events
		WHERE threat_name != '' OR path != ''
		ORDER BY timestamp`)
	if err != nil {
		return Section{Title: "Defender Detections"}
	}
	defer rows.Close()
	var tableRows [][]string
	for rows.Next() {
		var ts time.Time
		var eventID int
		var threat, severity, path, action, process, sha256 string
		rows.Scan(&ts, &eventID, &threat, &severity, &path, &action, &process, &sha256)
		tableRows = append(tableRows, []string{
			ts.Format("2006-01-02 15:04:05"),
			fmt.Sprintf("%d", eventID),
			threat, severity,
			truncatePath(path, 60),
			action, process, sha256,
		})
	}
	return Section{Title: "Defender Detections", Tables: []Table{{
		Headers: []string{"Timestamp", "EventID", "Threat", "Severity", "Path", "Action", "Process", "SHA256"},
		Rows:    tableRows,
	}}}
}

func buildSuspiciousAuthSection(db *sql.DB) Section {
	rows, err := db.Query(`
		SELECT timestamp, event_id, "user", domain, logon_type, src_ip, workstation, process_name
		FROM auth_events
		WHERE event_id IN (4625, 4648)
		   OR (src_ip NOT IN ('-', '', '127.0.0.1') AND src_ip IS NOT NULL)
		   OR (domain NOT IN ('NT AUTHORITY', '') AND domain != computer_name())
		ORDER BY timestamp DESC
		LIMIT 100`)
	if err != nil {
		// Fallback without computer_name()
		rows, err = db.Query(`
			SELECT timestamp, event_id, "user", domain, logon_type, src_ip, workstation, process_name
			FROM auth_events
			WHERE event_id IN (4625, 4648)
			   OR (src_ip NOT IN ('-', '', '127.0.0.1') AND src_ip IS NOT NULL AND src_ip != '')
			ORDER BY timestamp DESC
			LIMIT 100`)
		if err != nil {
			return Section{Title: "Suspicious Auth Events"}
		}
	}
	defer rows.Close()
	var tableRows [][]string
	for rows.Next() {
		var ts time.Time
		var eventID, logonType int
		var user, domain, srcIP, workstation, process string
		rows.Scan(&ts, &eventID, &user, &domain, &logonType, &srcIP, &workstation, &process)
		tableRows = append(tableRows, []string{
			ts.Format("2006-01-02 15:04:05"),
			fmt.Sprintf("%d", eventID),
			user, domain,
			fmt.Sprintf("%d", logonType),
			srcIP, workstation, process,
		})
	}
	return Section{Title: "Suspicious Auth Events", Tables: []Table{{
		Headers: []string{"Timestamp", "EventID", "User", "Domain", "LogonType", "SrcIP", "Workstation", "Process"},
		Rows:    tableRows,
	}}}
}

func buildKeyEventsSection(db *sql.DB) Section {
	rows, err := db.Query(`
		SELECT timestamp, event_id, channel, computer, message
		FROM evtx_events
		WHERE event_id IN (
			1102, 1100,       -- log cleared
			7045,             -- new service installed
			4698, 4702, 4699, -- scheduled task created/modified/deleted
			4720, 4726,       -- user created/deleted
			4732, 4756        -- added to privileged group
		)
		AND timestamp >= TIMESTAMP '2000-01-01'
		ORDER BY timestamp DESC
		LIMIT 200`)
	if err != nil {
		return Section{Title: "Key Security Events"}
	}
	defer rows.Close()
	var tableRows [][]string
	for rows.Next() {
		var ts time.Time
		var eventID int
		var channel, computer, message string
		rows.Scan(&ts, &eventID, &channel, &computer, &message)
		tableRows = append(tableRows, []string{
			ts.Format("2006-01-02 15:04:05"),
			fmt.Sprintf("%d", eventID),
			channel, computer,
			truncate(message, 120),
		})
	}
	return Section{Title: "Key Security Events", Tables: []Table{{
		Headers: []string{"Timestamp", "EventID", "Channel", "Computer", "Message"},
		Rows:    tableRows,
	}}}
}

func buildSuspiciousFilesSection(db *sql.DB) Section {
	rows, err := db.Query(`
		SELECT MAX(modified) AS modified, path, MAX(size) AS size
		FROM mft
		WHERE NOT is_dir
		  AND modified >= TIMESTAMP '2000-01-01'
		  AND (
		    -- high-risk script extensions outside system dirs
		    ((lower(path) LIKE '%.pif' OR lower(path) LIKE '%.scr' OR lower(path) LIKE '%.hta' OR lower(path) LIKE '%.vbs' OR lower(path) LIKE '%.wsf' OR lower(path) LIKE '%.jse')
		     AND NOT (lower(path) LIKE '%/windows/%' OR lower(path) LIKE '%/program files%' OR lower(path) LIKE '%/windowsapps/%' OR lower(path) LIKE '%\windows\%' OR lower(path) LIKE '%\program files%'))
		    OR
		    -- ps1/bat/cmd only in user-writable paths
		    ((lower(path) LIKE '%.ps1' OR lower(path) LIKE '%.bat' OR lower(path) LIKE '%.cmd')
		     AND (lower(path) LIKE '%/users/%' OR lower(path) LIKE '%/temp/%' OR lower(path) LIKE '%/programdata/%' OR lower(path) LIKE '%/public/%' OR lower(path) LIKE '%\users\%' OR lower(path) LIKE '%\temp\%'))
		    OR
		    -- exe/dll dropped in user profile locations
		    ((lower(path) LIKE '%/users/%/documents/%' OR lower(path) LIKE '%/users/%/downloads/%' OR lower(path) LIKE '%/users/%/desktop/%' OR lower(path) LIKE '%/users/%/appdata/roaming/%' OR lower(path) LIKE '%\users\%\documents\%' OR lower(path) LIKE '%\users\%\downloads\%' OR lower(path) LIKE '%\users\%\desktop\%')
		     AND (lower(path) LIKE '%.exe' OR lower(path) LIKE '%.dll'))
		  )
		GROUP BY path
		ORDER BY modified DESC
		LIMIT 200`)
	if err != nil {
		return Section{Title: "Suspicious Files (MFT)"}
	}
	defer rows.Close()
	var tableRows [][]string
	for rows.Next() {
		var ts time.Time
		var path string
		var size int64
		rows.Scan(&ts, &path, &size)
		tableRows = append(tableRows, []string{
			ts.Format("2006-01-02 15:04:05"),
			path,
			fmt.Sprintf("%d", size),
		})
	}
	return Section{Title: "Suspicious Files (MFT)", Tables: []Table{{
		Headers: []string{"Modified", "Path", "Size"},
		Rows:    tableRows,
	}}}
}

func buildBrowserSection(db *sql.DB) Section {
	s := Section{Title: "Browser History"}

	rows, err := db.Query(`
		SELECT visit_time, browser, profile, url, title, visit_count
		FROM browser_history
		WHERE url IS NOT NULL AND url != ''
		ORDER BY visit_time DESC NULLS LAST
		LIMIT 200`)
	if err != nil {
		return s
	}
	defer rows.Close()

	var tableRows [][]string
	for rows.Next() {
		var ts time.Time
		var browser, profile, url, title string
		var visitCount int
		rows.Scan(&ts, &browser, &profile, &url, &title, &visitCount)
		tsStr := ""
		if !ts.IsZero() {
			tsStr = ts.Format("2006-01-02 15:04:05")
		}
		tableRows = append(tableRows, []string{
			tsStr, browser, profile,
			truncate(url, 100), truncate(title, 60),
			fmt.Sprintf("%d", visitCount),
		})
	}
	if len(tableRows) > 0 {
		s.Tables = append(s.Tables, Table{
			Title:   fmt.Sprintf("Top 200 Visited URLs (%d)", len(tableRows)),
			Headers: []string{"Visit Time", "Browser", "Profile", "URL", "Title", "Visit Count"},
			Rows:    tableRows,
		})
	}
	return s
}

func truncatePath(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "..." + s[len(s)-n+3:]
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

// buildCorrelationSection finds IOC values confirmed by 2+ independent detection sources.
// A value seen by both a SQL detector and a SIGMA rule has higher confidence than either alone.
func buildCorrelationSection(db *sql.DB) Section {
	rows, err := db.Query(`
		WITH dedup AS (
			SELECT DISTINCT "type", value, source, confidence, first_seen
			FROM ioc_indicators
		)
		SELECT "type", value,
		       COUNT(DISTINCT source)                              AS sc,
		       STRING_AGG(source, ' + ' ORDER BY source)          AS sources,
		       MAX(confidence)                                     AS confidence,
		       COALESCE(CAST(MIN(first_seen) AS VARCHAR), '')      AS earliest
		FROM dedup
		GROUP BY "type", value
		HAVING COUNT(DISTINCT source) > 1
		ORDER BY
		    CASE MAX(confidence) WHEN 'HIGH' THEN 1 WHEN 'MED' THEN 2 ELSE 3 END,
		    COUNT(DISTINCT source) DESC
		LIMIT 50
	`)
	if err != nil {
		return Section{Title: "Correlated Findings (Multi-Source)"}
	}
	defer rows.Close()

	var tableRows [][]string
	for rows.Next() {
		var typ, value, sources, confidence, earliest string
		var sc int
		rows.Scan(&typ, &value, &sc, &sources, &confidence, &earliest)
		tableRows = append(tableRows, []string{
			confidence,
			typ,
			truncate(value, 80),
			fmt.Sprintf("%d", sc),
			sources,
			earliest,
		})
	}
	return Section{Title: "Correlated Findings (Multi-Source)", Tables: []Table{{
		Headers: []string{"Confidence", "Type", "Value", "# Sources", "Sources", "First Seen"},
		Rows:    tableRows,
	}}}
}

func buildMalfindSection(db *sql.DB) Section {
	rows, err := db.Query(`
		SELECT pid, process_name, vad_start, vad_end, protection, hex_dump
		FROM mem_malfind ORDER BY pid LIMIT 100`)
	if err != nil {
		return Section{Title: "Memory: Malfind (Code Injection)"}
	}
	defer rows.Close()
	var tableRows [][]string
	for rows.Next() {
		var pid int
		var proc, start, end, prot, hex string
		rows.Scan(&pid, &proc, &start, &end, &prot, &hex)
		tableRows = append(tableRows, []string{
			fmt.Sprintf("%d", pid), proc, start, end, prot, truncate(hex, 60),
		})
	}
	if len(tableRows) == 0 {
		return Section{Title: "Memory: Malfind (Code Injection)"}
	}
	return Section{Title: "Memory: Malfind (Code Injection)", Tables: []Table{{
		Headers: []string{"PID", "Process", "Start", "End", "Protection", "Hex"},
		Rows:    tableRows,
	}}}
}

func buildExecutionSection(db *sql.DB) Section {
	s := Section{Title: "Execution Artifacts (Prefetch / Shimcache / Amcache)"}

	// Prefetch: executed binaries with path and volume info
	pfRows, err := db.Query(`
		SELECT last_run, filename, COALESCE(path,''), run_count, COALESCE(volume_paths,'')
		FROM prefetch
		ORDER BY last_run DESC NULLS LAST
		LIMIT 300`)
	if err == nil {
		defer pfRows.Close()
		var rows [][]string
		for pfRows.Next() {
			var ts time.Time
			var filename, path string
			var runCount int
			var volPaths string
			pfRows.Scan(&ts, &filename, &path, &runCount, &volPaths)
			rows = append(rows, []string{
				ts.Format("2006-01-02 15:04:05"),
				filename,
				truncatePath(path, 70),
				fmt.Sprintf("%d", runCount),
				truncate(volPaths, 80),
			})
		}
		if len(rows) > 0 {
			s.Tables = append(s.Tables, Table{
				Title:   "Prefetch (Executed Programs)",
				Headers: []string{"Last Run", "Filename", "Path", "Run Count", "Volumes"},
				Rows:    rows,
			})
		}
	}

	// Shimcache: all entries, flag suspicious paths
	scRows, err := db.Query(`
		SELECT last_modified, path, executed
		FROM shimcache
		ORDER BY last_modified DESC NULLS LAST
		LIMIT 300`)
	if err == nil {
		defer scRows.Close()
		var rows [][]string
		for scRows.Next() {
			var ts time.Time
			var path string
			var executed bool
			scRows.Scan(&ts, &path, &executed)
			exec := "?"
			if executed {
				exec = "YES"
			}
			rows = append(rows, []string{ts.Format("2006-01-02 15:04:05"), exec, path})
		}
		if len(rows) > 0 {
			s.Tables = append(s.Tables, Table{
				Title:   "Shimcache (AppCompatCache)",
				Headers: []string{"Last Modified", "Executed", "Path"},
				Rows:    rows,
			})
		}
	}

	// Amcache: recently executed/installed with SHA256
	acRows, err := db.Query(`
		SELECT first_seen, path, sha256, version, publisher
		FROM amcache
		ORDER BY first_seen DESC NULLS LAST
		LIMIT 300`)
	if err == nil {
		defer acRows.Close()
		var rows [][]string
		for acRows.Next() {
			var ts time.Time
			var path, sha256, ver, pub string
			acRows.Scan(&ts, &path, &sha256, &ver, &pub)
			rows = append(rows, []string{
				ts.Format("2006-01-02 15:04:05"),
				truncatePath(path, 60), sha256, ver, pub,
			})
		}
		if len(rows) > 0 {
			s.Tables = append(s.Tables, Table{
				Title:   "Amcache (Installed/Executed Programs)",
				Headers: []string{"First Seen", "Path", "SHA256", "Version", "Publisher"},
				Rows:    rows,
			})
		}
	}
	return s
}

func buildPersistenceSection(db *sql.DB) Section {
	s := Section{Title: "Windows Persistence"}

	// persistence table (Run keys etc)
	pRows, err := db.Query(`
		SELECT type, name, command, key_path, CAST(enabled AS VARCHAR)
		FROM persistence ORDER BY type, name LIMIT 200`)
	if err == nil {
		defer pRows.Close()
		var rows [][]string
		for pRows.Next() {
			var typ, name, cmd, keyPath, enabled string
			pRows.Scan(&typ, &name, &cmd, &keyPath, &enabled)
			rows = append(rows, []string{typ, name, truncate(cmd, 100), truncate(keyPath, 60), enabled})
		}
		if len(rows) > 0 {
			s.Tables = append(s.Tables, Table{
				Title:   "Run Keys / Startup",
				Headers: []string{"Type", "Name", "Command", "Key Path", "Enabled"},
				Rows:    rows,
			})
		}
	}

	// Scheduled tasks
	stRows, err := db.Query(`
		SELECT name, CAST(enabled AS VARCHAR), command, author, trigger
		FROM scheduled_tasks ORDER BY name LIMIT 200`)
	if err == nil {
		defer stRows.Close()
		var rows [][]string
		for stRows.Next() {
			var name, enabled, cmd, author, trigger string
			stRows.Scan(&name, &enabled, &cmd, &author, &trigger)
			rows = append(rows, []string{name, enabled, truncate(cmd, 100), author, truncate(trigger, 60)})
		}
		if len(rows) > 0 {
			s.Tables = append(s.Tables, Table{
				Title:   "Scheduled Tasks",
				Headers: []string{"Name", "Enabled", "Command", "Author", "Trigger"},
				Rows:    rows,
			})
		}
	}

	// Services
	svcRows, err := db.Query(`
		SELECT name, display_name, start_type, binary_path, object_name
		FROM services
		WHERE start_type IN ('Auto','Boot','System') OR binary_path NOT LIKE '%system32%'
		ORDER BY name LIMIT 200`)
	if err == nil {
		defer svcRows.Close()
		var rows [][]string
		for svcRows.Next() {
			var name, disp, start, bin, obj string
			svcRows.Scan(&name, &disp, &start, &bin, &obj)
			rows = append(rows, []string{name, disp, start, truncate(bin, 80), obj})
		}
		if len(rows) > 0 {
			s.Tables = append(s.Tables, Table{
				Title:   "Auto-Start Services",
				Headers: []string{"Name", "Display", "Start", "Binary", "Object"},
				Rows:    rows,
			})
		}
	}
	return s
}

func buildPSHistorySection(db *sql.DB) Section {
	s := Section{Title: "PowerShell Activity"}

	// PS history file (~/.config/...)
	histRows, err := db.Query(`
		SELECT command, timestamp
		FROM ps_history
		ORDER BY timestamp DESC NULLS LAST
		LIMIT 200`)
	if err == nil {
		defer histRows.Close()
		var rows [][]string
		for histRows.Next() {
			var cmd string
			var ts time.Time
			histRows.Scan(&cmd, &ts)
			rows = append(rows, []string{ts.Format("2006-01-02 15:04:05"), truncate(cmd, 150)})
		}
		if len(rows) > 0 {
			s.Tables = append(s.Tables, Table{
				Title:   "PowerShell Command History",
				Headers: []string{"Timestamp", "Command"},
				Rows:    rows,
			})
		}
	}

	// Scriptblock logging (EventID 4104) — only suspicious blocks
	sbRows, err := db.Query(`
		SELECT timestamp, script_id, LEFT(script_text, 300)
		FROM ps_scriptblock
		WHERE lower(script_text) LIKE '%invoke-expression%'
		   OR lower(script_text) LIKE '%iex%'
		   OR lower(script_text) LIKE '%downloadstring%'
		   OR lower(script_text) LIKE '%frombase64string%'
		   OR lower(script_text) LIKE '%bypass%'
		   OR lower(script_text) LIKE '%hidden%'
		ORDER BY timestamp DESC
		LIMIT 50`)
	if err == nil {
		defer sbRows.Close()
		var rows [][]string
		for sbRows.Next() {
			var ts time.Time
			var id, text string
			sbRows.Scan(&ts, &id, &text)
			rows = append(rows, []string{ts.Format("2006-01-02 15:04:05"), id, text})
		}
		if len(rows) > 0 {
			s.Tables = append(s.Tables, Table{
				Title:   "Suspicious Script Blocks (EventID 4104)",
				Headers: []string{"Timestamp", "BlockID", "Content"},
				Rows:    rows,
			})
		}
	}
	return s
}

func buildJumpListsSection(db *sql.DB) Section {
	s := Section{Title: "JumpLists (Recently Accessed Files)"}
	rows, err := db.Query(`
		SELECT COALESCE(NULLIF(app_name,''), app_id), entry_type,
		       target_path, accessed, access_count, pin_status
		FROM jumplists
		WHERE target_path != ''
		ORDER BY accessed DESC NULLS LAST
		LIMIT 200`)
	if err != nil {
		return s
	}
	defer rows.Close()
	var tableRows [][]string
	for rows.Next() {
		var app, etype, target, pin string
		var accessed time.Time
		var count int
		rows.Scan(&app, &etype, &target, &accessed, &count, &pin)
		ts := ""
		if !accessed.IsZero() {
			ts = accessed.Format("2006-01-02 15:04:05")
		}
		flag := ""
		if pin == "pinned" {
			flag = "📌"
		}
		tableRows = append(tableRows, []string{app, etype, target, ts, fmt.Sprintf("%d", count), flag})
	}
	if len(tableRows) > 0 {
		s.Tables = append(s.Tables, Table{
			Title:   fmt.Sprintf("Jump List Entries (%d)", len(tableRows)),
			Headers: []string{"Application", "Type", "Target Path", "Last Accessed", "Count", "Pin"},
			Rows:    tableRows,
		})
	}
	return s
}

func buildLNKSection(db *sql.DB) Section {
	rows, err := db.Query(`
		SELECT modified, path, target_path, args, machine_id
		FROM lnk_files
		WHERE target_path != ''
		ORDER BY modified DESC NULLS LAST
		LIMIT 200`)
	if err != nil {
		return Section{Title: "LNK Files (Recent)"}
	}
	defer rows.Close()
	var tableRows [][]string
	for rows.Next() {
		var ts time.Time
		var path, target, args, machine string
		rows.Scan(&ts, &path, &target, &args, &machine)
		tableRows = append(tableRows, []string{
			ts.Format("2006-01-02 15:04:05"),
			truncatePath(path, 50),
			truncatePath(target, 60),
			truncate(args, 40),
			machine,
		})
	}
	if len(tableRows) == 0 {
		return Section{Title: "LNK Files (Recent)"}
	}
	return Section{Title: "LNK Files (Recent)", Tables: []Table{{
		Headers: []string{"Modified", "LNK Path", "Target", "Args", "Machine ID"},
		Rows:    tableRows,
	}}}
}

func buildLinuxAuthSection(db *sql.DB) Section {
	rows, err := db.Query(`
		SELECT timestamp, event_type, COALESCE("user",''), COALESCE(src_ip,''), message
		FROM linux_auth
		WHERE event_type IN ('ssh_login_success','ssh_login_failed','ssh_invalid_user','sudo','useradd','su_success')
		ORDER BY timestamp DESC
		LIMIT 200`)
	if err != nil {
		return Section{Title: "Linux Auth Events"}
	}
	defer rows.Close()
	var tableRows [][]string
	for rows.Next() {
		var ts time.Time
		var evType, user, srcIP, msg string
		rows.Scan(&ts, &evType, &user, &srcIP, &msg)
		tableRows = append(tableRows, []string{
			ts.Format("2006-01-02 15:04:05"), evType, user, srcIP, truncate(msg, 100),
		})
	}
	if len(tableRows) == 0 {
		return Section{Title: "Linux Auth Events"}
	}
	return Section{Title: "Linux Auth Events", Tables: []Table{{
		Headers: []string{"Timestamp", "Event", "User", "Source IP", "Message"},
		Rows:    tableRows,
	}}}
}

func buildLinuxPersistenceSection(db *sql.DB) Section {
	rows, err := db.Query(`
		SELECT type, COALESCE("user",''), path, COALESCE(command,''), COALESCE(details,'')
		FROM linux_persistence
		ORDER BY type, "user"
		LIMIT 200`)
	if err != nil {
		return Section{Title: "Linux Persistence"}
	}
	defer rows.Close()
	var tableRows [][]string
	for rows.Next() {
		var typ, user, path, cmd, details string
		rows.Scan(&typ, &user, &path, &cmd, &details)
		tableRows = append(tableRows, []string{typ, user, truncatePath(path, 50), truncate(cmd, 80), truncate(details, 60)})
	}
	if len(tableRows) == 0 {
		return Section{Title: "Linux Persistence"}
	}
	return Section{Title: "Linux Persistence", Tables: []Table{{
		Headers: []string{"Type", "User", "Path", "Command", "Details"},
		Rows:    tableRows,
	}}}
}

func buildUsnJrnlSection(db *sql.DB) Section {
	rows, err := db.Query(`
		SELECT timestamp, reason, path
		FROM usnjrnl
		WHERE reason LIKE '%FILE_CREATE%' OR reason LIKE '%FILE_DELETE%' OR reason LIKE '%RENAME%'
		ORDER BY timestamp DESC
		LIMIT 300`)
	if err != nil {
		return Section{Title: "$UsnJrnl File Activity"}
	}
	defer rows.Close()
	var tableRows [][]string
	for rows.Next() {
		var ts time.Time
		var reason, path string
		rows.Scan(&ts, &reason, &path)
		tableRows = append(tableRows, []string{ts.Format("2006-01-02 15:04:05"), reason, path})
	}
	if len(tableRows) == 0 {
		return Section{Title: "$UsnJrnl File Activity"}
	}
	return Section{Title: "$UsnJrnl File Activity", Tables: []Table{{
		Headers: []string{"Timestamp", "Reason", "Path"},
		Rows:    tableRows,
	}}}
}

// buildIOCSection shows only manually added / external IOCs, not automated detections.
func buildIOCSection(db *sql.DB) Section {
	rows, err := db.Query(`
		SELECT "type", value, source, confidence, related_campaign
		FROM ioc_indicators
		WHERE source NOT LIKE 'detect:%'
		  AND source NOT LIKE 'sigma:%'
		  AND source NOT LIKE 'yaralite:%'
		ORDER BY confidence DESC`)
	if err != nil {
		return Section{Title: "IOC Indicators (External)"}
	}
	defer rows.Close()
	var tableRows [][]string
	for rows.Next() {
		var t, v, s, c, camp string
		rows.Scan(&t, &v, &s, &c, &camp)
		tableRows = append(tableRows, []string{t, v, s, c, camp})
	}
	return Section{Title: "IOC Indicators (External)", Tables: []Table{{
		Headers: []string{"Type", "Value", "Source", "Confidence", "Campaign"},
		Rows:    tableRows,
	}}}
}

func buildMITRESection(db *sql.DB) Section {
	rows, err := db.Query("SELECT technique_id, name, tactic, evidence FROM attack_techniques")
	if err != nil {
		return Section{Title: "MITRE ATT&CK"}
	}
	defer rows.Close()
	var tableRows [][]string
	for rows.Next() {
		var id, name, tactic, evidence string
		rows.Scan(&id, &name, &tactic, &evidence)
		tableRows = append(tableRows, []string{id, name, tactic, evidence})
	}
	return Section{Title: "MITRE ATT&CK", Tables: []Table{{
		Headers: []string{"Technique ID", "Name", "Tactic", "Evidence"},
		Rows:    tableRows,
	}}}
}

func buildSkippedSection(db *sql.DB) Section {
	rows, err := db.Query(`SELECT path, "type", error FROM source_files WHERE error IS NOT NULL AND error != ''`)
	if err != nil {
		return Section{}
	}
	defer rows.Close()
	var tableRows [][]string
	for rows.Next() {
		var path, typ, errMsg string
		rows.Scan(&path, &typ, &errMsg)
		tableRows = append(tableRows, []string{path, typ, errMsg})
	}
	if len(tableRows) == 0 {
		return Section{}
	}
	return Section{Title: "Skipped Sources", Tables: []Table{{
		Headers: []string{"Path", "Type", "Error"},
		Rows:    tableRows,
	}}}
}

func buildRecycleBinSection(db *sql.DB) Section {
	rows, err := db.Query(`
		SELECT COALESCE(deleted_at::TEXT,''), original_path, size, COALESCE(sid,''), i_file
		FROM recycle_bin
		ORDER BY deleted_at DESC NULLS LAST
		LIMIT 300`)
	if err != nil {
		return Section{Title: "Recycle Bin (Deleted Files)"}
	}
	defer rows.Close()
	var tableRows [][]string
	for rows.Next() {
		var ts, path, sid, iFile string
		var size int64
		rows.Scan(&ts, &path, &size, &sid, &iFile)
		sizeStr := fmt.Sprintf("%d", size)
		if size > 1<<20 {
			sizeStr = fmt.Sprintf("%.1f MB", float64(size)/(1<<20))
		} else if size > 1<<10 {
			sizeStr = fmt.Sprintf("%.1f KB", float64(size)/(1<<10))
		}
		tableRows = append(tableRows, []string{ts, truncatePath(path, 80), sizeStr, sid, iFile})
	}
	if len(tableRows) == 0 {
		return Section{Title: "Recycle Bin (Deleted Files)"}
	}
	return Section{Title: "Recycle Bin (Deleted Files)", Tables: []Table{{
		Headers: []string{"Deleted At", "Original Path", "Size", "SID", "$I File"},
		Rows:    tableRows,
	}}}
}

func buildShellbagsSection(db *sql.DB) Section {
	rows, err := db.Query(`
		SELECT COALESCE(CAST(last_modified AS VARCHAR), '-'), path,
		       COALESCE("user", '-'), COALESCE(source, '-'), COALESCE(item_type, '-')
		FROM shellbags
		ORDER BY last_modified DESC NULLS LAST
		LIMIT 300`)
	if err != nil {
		return Section{Title: "Shellbags (Folder History)"}
	}
	defer rows.Close()
	var tableRows [][]string
	for rows.Next() {
		var ts, path, user, source, itemType string
		rows.Scan(&ts, &path, &user, &source, &itemType)
		tableRows = append(tableRows, []string{ts, truncatePath(path, 80), user, source, itemType})
	}
	if len(tableRows) == 0 {
		return Section{Title: "Shellbags (Folder History)"}
	}
	return Section{Title: "Shellbags (Folder History)", Tables: []Table{{
		Headers: []string{"Last Modified", "Path", "User", "Source", "Type"},
		Rows:    tableRows,
	}}}
}

func buildUserAssistSection(db *sql.DB) Section {
	rows, err := db.Query(`
		SELECT COALESCE(last_run::TEXT,''), path, run_count, focus_count
		FROM userassist
		ORDER BY last_run DESC NULLS LAST
		LIMIT 200`)
	if err != nil {
		return Section{Title: "UserAssist (Program Execution)"}
	}
	defer rows.Close()
	var tableRows [][]string
	for rows.Next() {
		var ts, program string
		var runCount, focusCount int
		rows.Scan(&ts, &program, &runCount, &focusCount)
		tableRows = append(tableRows, []string{
			ts, truncatePath(program, 80),
			fmt.Sprintf("%d", runCount),
			fmt.Sprintf("%d", focusCount),
		})
	}
	if len(tableRows) == 0 {
		return Section{Title: "UserAssist (Program Execution)"}
	}
	return Section{Title: "UserAssist (Program Execution)", Tables: []Table{{
		Headers: []string{"Last Run", "Program", "Run Count", "Focus Count"},
		Rows:    tableRows,
	}}}
}

func buildBAMSection(db *sql.DB) Section {
	rows, err := db.Query(`
		SELECT COALESCE(last_run::TEXT,''), path, COALESCE(sid,'')
		FROM bam_dam
		ORDER BY last_run DESC NULLS LAST
		LIMIT 200`)
	if err != nil {
		return Section{Title: "BAM/DAM (Background Activity Monitor)"}
	}
	defer rows.Close()
	var tableRows [][]string
	for rows.Next() {
		var ts, exe, sid string
		rows.Scan(&ts, &exe, &sid)
		tableRows = append(tableRows, []string{ts, truncatePath(exe, 80), sid})
	}
	if len(tableRows) == 0 {
		return Section{Title: "BAM/DAM (Background Activity Monitor)"}
	}
	return Section{Title: "BAM/DAM (Background Activity Monitor)", Tables: []Table{{
		Headers: []string{"Last Run", "Executable", "SID"},
		Rows:    tableRows,
	}}}
}

func buildProcessCorrelationSection(db *sql.DB) Section {
	s := Section{Title: "Process Investigation (Disk + RAM)"}
	rows, err := db.Query(`
		SELECT
			CAST(p.pid AS VARCHAR),
			CAST(COALESCE(p.ppid, 0) AS VARCHAR),
			p.name,
			LEFT(COALESCE(c.cmdline, '-'), 120),
			COALESCE(CAST(p.create_time AS VARCHAR), '-'),
			CASE WHEN pf.filename IS NOT NULL
				THEN CAST(pf.run_count AS VARCHAR) || 'x | ' || COALESCE(CAST(pf.last_run AS VARCHAR), '?')
				ELSE 'NOT IN PREFETCH'
			END,
			CASE WHEN sc.path IS NOT NULL
				THEN COALESCE(CAST(sc.last_modified AS VARCHAR), '?') || CASE WHEN sc.executed THEN ' | executed' ELSE '' END
				ELSE 'NOT IN SHIMCACHE'
			END,
			COALESCE(LEFT(ac.sha256, 16), '-')
		FROM mem_pslist p
		LEFT JOIN mem_cmdline c ON p.pid = c.pid
		LEFT JOIN prefetch pf ON lower(p.name) = lower(pf.filename)
		LEFT JOIN shimcache sc ON lower(sc.path) LIKE '%' || lower(p.name)
		LEFT JOIN amcache ac ON lower(ac.path) LIKE '%' || lower(p.name)
		ORDER BY p.create_time DESC NULLS LAST
		LIMIT 300`)
	if err != nil {
		return s
	}
	defer rows.Close()
	var tableRows [][]string
	for rows.Next() {
		var pid, ppid, name, cmdline, created, prefetch, shimcache, hash string
		rows.Scan(&pid, &ppid, &name, &cmdline, &created, &prefetch, &shimcache, &hash)
		tableRows = append(tableRows, []string{pid, ppid, name, cmdline, created, prefetch, shimcache, hash})
	}
	if len(tableRows) == 0 {
		return s
	}
	s.Tables = []Table{{
		Title:   fmt.Sprintf("Processes in memory cross-referenced with disk artifacts (%d)", len(tableRows)),
		Headers: []string{"PID", "PPID", "Name", "Command Line", "Started", "Prefetch", "Shimcache", "Hash"},
		Rows:    tableRows,
	}}
	return s
}

func buildNetworkCorrelationSection(db *sql.DB) Section {
	s := Section{Title: "Network Investigation (RAM + IOC + Auth)"}
	rows, err := db.Query(`
		SELECT
			CAST(n.pid AS VARCHAR),
			n.name,
			n.proto,
			n.remote_addr,
			CAST(n.remote_port AS VARCHAR),
			n.state,
			COALESCE(i.confidence || ' | ' || COALESCE(i.related_campaign, i.type), '-') AS ioc_hit,
			CAST(COUNT(DISTINCT a.timestamp) AS VARCHAR) AS auth_events
		FROM mem_netscan n
		LEFT JOIN ioc_indicators i ON n.remote_addr = i.value
		LEFT JOIN auth_events a ON a.src_ip = n.remote_addr
		WHERE n.remote_addr NOT IN ('-', '0.0.0.0', '::')
		  AND n.remote_addr NOT LIKE '127.%'
		  AND n.remote_addr != '::1'
		GROUP BY n.pid, n.name, n.proto, n.remote_addr, n.remote_port, n.state, i.confidence, i.related_campaign, i.type
		ORDER BY i.confidence NULLS LAST, n.remote_addr
		LIMIT 200`)
	if err != nil {
		return s
	}
	defer rows.Close()
	var tableRows [][]string
	for rows.Next() {
		var pid, name, proto, addr, port, state, ioc, authCount string
		rows.Scan(&pid, &name, &proto, &addr, &port, &state, &ioc, &authCount)
		tableRows = append(tableRows, []string{pid, name, proto, addr, port, state, ioc, authCount})
	}
	if len(tableRows) == 0 {
		return s
	}
	s.Tables = []Table{{
		Title:   fmt.Sprintf("Network connections cross-referenced with IOC indicators and auth events (%d)", len(tableRows)),
		Headers: []string{"PID", "Process", "Proto", "Remote IP", "Port", "State", "IOC Hit", "Auth Events"},
		Rows:    tableRows,
	}}
	return s
}

func buildSuspiciousScriptExecutionSection(db *sql.DB) Section {
	s := Section{Title: "Suspicious Script Execution Evidence"}

	type entry struct {
		modified string
		path     string
		size     int64
		base     string
	}

	mftRows, err := db.Query(`
		SELECT COALESCE(CAST(MAX(modified) AS VARCHAR), ''), path, MAX(size)
		FROM mft
		WHERE NOT is_dir
		  AND modified >= TIMESTAMP '2000-01-01'
		  AND (lower(path) LIKE '%.ps1' OR lower(path) LIKE '%.bat' OR lower(path) LIKE '%.cmd'
		       OR lower(path) LIKE '%.vbs' OR lower(path) LIKE '%.hta' OR lower(path) LIKE '%.js'
		       OR lower(path) LIKE '%.jse' OR lower(path) LIKE '%.wsf')
		  AND (lower(path) LIKE '%/users/%' OR lower(path) LIKE '%/temp/%'
		       OR lower(path) LIKE '%/programdata/%' OR lower(path) LIKE '%/public/%'
		       OR lower(path) LIKE '%\users\%' OR lower(path) LIKE '%\temp\%')
		GROUP BY path
		ORDER BY MAX(modified) DESC
		LIMIT 60`)
	if err != nil {
		return s
	}
	defer mftRows.Close()

	var entries []entry
	for mftRows.Next() {
		var ts, path string
		var size int64
		mftRows.Scan(&ts, &path, &size)
		if len(ts) > 19 {
			ts = ts[:19]
		}
		entries = append(entries, entry{ts, path, size, strings.ToLower(baseName(path))})
	}
	if len(entries) == 0 {
		return s
	}

	// Load all proc_creation cmdlines into memory for in-process matching
	type pcEntry struct{ ts, cmd, user string }
	var pcList []pcEntry
	pcRows, _ := db.Query(`SELECT COALESCE(CAST(timestamp AS VARCHAR),''), lower(COALESCE(cmdline,'')), COALESCE(user_name,'') FROM proc_creation LIMIT 20000`)
	if pcRows != nil {
		defer pcRows.Close()
		for pcRows.Next() {
			var ts, cmd, user string
			pcRows.Scan(&ts, &cmd, &user)
			if len(ts) > 19 {
				ts = ts[:19]
			}
			pcList = append(pcList, pcEntry{ts, cmd, user})
		}
	}

	// Load prefetch filename → run summary
	pfMap := map[string]string{}
	pfRows, _ := db.Query(`SELECT lower(COALESCE(filename,'')), run_count, COALESCE(CAST(last_run AS VARCHAR),'') FROM prefetch`)
	if pfRows != nil {
		defer pfRows.Close()
		for pfRows.Next() {
			var fname, lastRun string
			var rc int
			pfRows.Scan(&fname, &rc, &lastRun)
			if len(lastRun) > 19 {
				lastRun = lastRun[:19]
			}
			pfMap[fname] = fmt.Sprintf("%dx last:%s", rc, lastRun)
		}
	}

	var tableRows [][]string
	for _, e := range entries {
		evidence := ""
		detail := ""

		if v, ok := pfMap[e.base]; ok {
			evidence = "PREFETCH"
			detail = v
		}
		for _, pc := range pcList {
			if strings.Contains(pc.cmd, e.base) {
				if evidence == "" {
					evidence = "PROC 4688"
				} else {
					evidence += "+PROC"
				}
				detail += " | " + truncate(pc.user+": "+pc.cmd, 100)
				break
			}
		}
		if evidence == "" {
			evidence = "FILE ONLY"
		}

		tableRows = append(tableRows, []string{
			e.modified, e.path, fmt.Sprintf("%d", e.size), evidence, truncate(detail, 120),
		})
	}
	if len(tableRows) == 0 {
		return s
	}
	s.Tables = []Table{{
		Title:   fmt.Sprintf("Suspicious scripts in user-writable paths (%d)", len(tableRows)),
		Headers: []string{"Modified", "Path", "Size", "Evidence", "Detail"},
		Rows:    tableRows,
	}}
	return s
}

// baseName extracts the filename from a path using either / or \ separator.
func baseName(path string) string {
	if i := strings.LastIndexAny(path, "/\\"); i >= 0 {
		return path[i+1:]
	}
	return path
}

// tacticFromCode converts a MITRE T-code prefix to a tactic name.
var tacticFromCode = map[string]string{
	"T1059": "Execution", "T1047": "Execution", "T1053": "Persistence/Execution",
	"T1078": "Persistence", "T1543": "Persistence", "T1547": "Persistence",
	"T1055": "Defense Evasion", "T1562": "Defense Evasion", "T1027": "Defense Evasion",
	"T1036": "Defense Evasion", "T1218": "Defense Evasion",
	"T1003": "Credential Access", "T1558": "Credential Access", "T1110": "Credential Access",
	"T1550": "Lateral Movement", "T1021": "Lateral Movement",
	"T1087": "Discovery", "T1069": "Discovery", "T1082": "Discovery", "T1018": "Discovery",
	"T1566": "Initial Access",
	"T1048": "Exfiltration", "T1041": "Exfiltration",
	"T1105": "Command and Control", "T1071": "Command and Control",
}

func buildExecSummary(db *sql.DB, highCount, medCount int) ExecSummary {
	es := ExecSummary{HighCount: highCount, MedCount: medCount}

	// Time range from actual event timestamps (evtx + auth only — mft has unreliable old dates)
	var minTs, maxTs string
	db.QueryRow(`
		SELECT CAST(MIN(mn) AS VARCHAR), CAST(MAX(mx) AS VARCHAR) FROM (
			SELECT MIN("timestamp") AS mn, MAX("timestamp") AS mx FROM evtx_events WHERE "timestamp" IS NOT NULL
			UNION ALL SELECT MIN("timestamp"), MAX("timestamp") FROM auth_events WHERE "timestamp" IS NOT NULL
		) x WHERE mn IS NOT NULL
	`).Scan(&minTs, &maxTs)
	if minTs == "" {
		db.QueryRow(`SELECT MIN(CAST(first_seen AS VARCHAR)), MAX(CAST(first_seen AS VARCHAR)) FROM ioc_indicators WHERE first_seen IS NOT NULL`).Scan(&minTs, &maxTs)
	}
	if minTs != "" {
		if len(minTs) > 16 {
			minTs = minTs[:16]
		}
		if len(maxTs) > 16 {
			maxTs = maxTs[:16]
		}
		es.TimeRange = minTs + " → " + maxTs
	}

	// Verdict
	switch {
	case highCount >= 50:
		es.Verdict, es.VerdictClass = "CRITICAL — Active Compromise Indicators Detected", "verdict-critical"
	case highCount >= 10:
		es.Verdict, es.VerdictClass = "HIGH — Multiple Threat Indicators Present", "verdict-high"
	case highCount >= 1:
		es.Verdict, es.VerdictClass = "ELEVATED — Threat Indicators Present", "verdict-medium"
	case medCount >= 1:
		es.Verdict, es.VerdictClass = "LOW — Minor Indicators Only", "verdict-low"
	default:
		es.Verdict, es.VerdictClass = "CLEAN — No Automated Detections", "verdict-clean"
	}

	// Top findings: top 6 detectors by hit count, HIGH first
	rows, err := db.Query(`
		SELECT source, confidence, COUNT(*) AS c,
		       CASE WHEN position('—' IN COALESCE(MAX(notes),'')) > 1
		            THEN LEFT(MAX(notes), position('—' IN MAX(notes)) - 2)
		            ELSE NULL END AS title
		FROM ioc_indicators
		WHERE source LIKE 'detect:%' OR source LIKE 'sigma:%'
		GROUP BY source, confidence
		ORDER BY CASE confidence WHEN 'HIGH' THEN 1 WHEN 'MED' THEN 2 ELSE 3 END, c DESC
		LIMIT 6`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var src, conf string
			var cnt int
			var title sql.NullString
			rows.Scan(&src, &conf, &cnt, &title)
			name := title.String
			if name == "" {
				name = strings.ReplaceAll(strings.TrimPrefix(strings.TrimPrefix(src, "detect:"), "sigma:"), "_", " ")
			}
			es.TopFindings = append(es.TopFindings, ExecFinding{
				Title: fmt.Sprintf("%s (%d hits)", name, cnt),
				Sev:   conf,
			})
		}
	}

	// Tactics from MITRE codes in related_campaign
	seen := map[string]bool{}
	tRows, err2 := db.Query(`SELECT DISTINCT related_campaign FROM ioc_indicators WHERE related_campaign IS NOT NULL AND related_campaign != ''`)
	if err2 == nil {
		defer tRows.Close()
		for tRows.Next() {
			var rc string
			tRows.Scan(&rc)
			for _, code := range strings.Split(rc, ",") {
				code = strings.TrimSpace(code)
				if len(code) >= 5 {
					prefix := strings.ToUpper(code[:5])
					if tac, ok := tacticFromCode[prefix]; ok && !seen[tac] {
						seen[tac] = true
						es.Tactics = append(es.Tactics, tac)
					}
				}
			}
		}
	}

	// Affected users — proc_creation first, fall back to auth_events
	uRows, err3 := db.Query(`
		SELECT DISTINCT user_name FROM proc_creation
		WHERE user_name IS NOT NULL AND user_name != '' AND user_name NOT LIKE '%SYSTEM%'
		  AND (image ILIKE '%certutil%' OR image ILIKE '%powershell%' OR image ILIKE '%mshta%'
		    OR image ILIKE '%wscript%' OR image ILIKE '%cscript%' OR integrity_level IN ('High','System'))
		LIMIT 5`)
	if err3 == nil {
		defer uRows.Close()
		for uRows.Next() {
			var u string
			uRows.Scan(&u)
			es.AffectedUsers = append(es.AffectedUsers, u)
		}
	}
	if len(es.AffectedUsers) == 0 {
		aRows, err4 := db.Query(`
			SELECT "user" FROM (
				SELECT "user", COUNT(*) AS c FROM auth_events
				WHERE "user" IS NOT NULL AND "user" != '' AND "user" NOT LIKE '%$'
				  AND "user" NOT ILIKE '%system%' AND "user" NOT ILIKE 'DWM-%'
				  AND "user" NOT ILIKE 'UMFD-%' AND "user" NOT ILIKE 'LOCAL SERVICE'
				  AND "user" NOT ILIKE 'NETWORK SERVICE' AND "user" NOT ILIKE 'ANONYMOUS%'
				GROUP BY "user" ORDER BY c DESC LIMIT 5
			) t`)
		if err4 == nil {
			defer aRows.Close()
			for aRows.Next() {
				var u string
				aRows.Scan(&u)
				es.AffectedUsers = append(es.AffectedUsers, u)
			}
		}
	}

	// Rule-based recommendations
	type recRule struct {
		query string
		rec   string
	}
	rules := []recRule{
		{`SELECT COUNT(*) FROM ioc_indicators WHERE source LIKE '%dcsync%' OR source LIKE '%pass_the_hash%'`,
			"Reset ALL domain admin and service account credentials immediately"},
		{`SELECT COUNT(*) FROM ioc_indicators WHERE source LIKE '%log_clear%' OR source LIKE '%defender_disabled%' OR source LIKE '%defender_tamper%'`,
			"Audit SIEM/EVTX gaps — logs were tampered; reconstruct timeline from alternate sources"},
		{`SELECT COUNT(*) FROM ioc_indicators WHERE source LIKE '%new_service%' OR source LIKE '%wmi_subscription%' OR source LIKE '%schtask%'`,
			"Enumerate and remove all unauthorized persistence mechanisms (services, tasks, WMI)"},
		{`SELECT COUNT(*) FROM ioc_indicators WHERE source LIKE '%lateral%' OR source LIKE '%impacket%' OR source LIKE '%psexec%'`,
			"Isolate affected segment — lateral movement detected; audit all SMB/WMI/RDP access"},
		{`SELECT COUNT(*) FROM ioc_indicators WHERE source LIKE '%kerberoast%'`,
			"Audit all service accounts with SPNs; rotate Kerberos service tickets (KRBTGT twice)"},
		{`SELECT COUNT(*) FROM ioc_indicators WHERE source LIKE '%exfil%' OR source LIKE '%rclone%' OR source LIKE '%dns_tunnel%'`,
			"Review outbound traffic logs for data exfiltration; check cloud storage access"},
		{`SELECT COUNT(*) FROM ioc_indicators WHERE confidence = 'HIGH'`,
			"Preserve forensic evidence (disk image + memory dump) before any remediation"},
	}
	for _, r := range rules {
		var n int
		db.QueryRow(r.query).Scan(&n)
		if n > 0 {
			es.Recommendations = append(es.Recommendations, r.rec)
		}
	}
	if len(es.Recommendations) == 0 {
		es.Recommendations = []string{"No critical actions required — continue routine monitoring"}
	}

	return es
}

func buildSysmonSection(db *sql.DB) Section {
	s := Section{Title: "Sysmon Events"}

	// Suspicious process creation (LOLBins, susp paths, encoded PS)
	lolbins := `'certutil','mshta','regsvr32','msiexec','wscript','cscript','rundll32','bitsadmin','installutil','cmstp','odbcconf'`
	procRows, err := db.Query(fmt.Sprintf(`
		SELECT COALESCE(CAST(timestamp AS VARCHAR),''), CAST(COALESCE(pid,0) AS VARCHAR),
		       COALESCE(image,''), COALESCE(cmdline,''), COALESCE(parent_image,''),
		       COALESCE(integrity_level,''), COALESCE(sha256,''), COALESCE(user_name,'')
		FROM sysmon_process
		WHERE (LOWER(SPLIT_PART(image,'\',-1)) IN (%s))
		   OR image ILIKE '%%\AppData\Roaming\%%'
		   OR image ILIKE '%%\Temp\%%'
		   OR cmdline ILIKE '%%-EncodedCommand%%'
		   OR cmdline ILIKE '%%IEX%%'
		   OR cmdline ILIKE '%%downloadstring%%'
		ORDER BY timestamp DESC NULLS LAST
		LIMIT 100`, lolbins))
	if err == nil {
		defer procRows.Close()
		var tableRows [][]string
		for procRows.Next() {
			var ts, pid, img, cmd, par, integ, sha, usr string
			procRows.Scan(&ts, &pid, &img, &cmd, &par, &integ, &sha, &usr)
			if len(ts) > 19 {
				ts = ts[:19]
			}
			if len(cmd) > 80 {
				cmd = cmd[:80] + "…"
			}
			if len(sha) > 12 {
				sha = sha[:12] + "…"
			}
			tableRows = append(tableRows, []string{ts, pid, img, cmd, par, integ, usr, sha})
		}
		if len(tableRows) > 0 {
			s.Tables = append(s.Tables, Table{
				Title:   fmt.Sprintf("Suspicious Process Creation — Sysmon Event 1 (%d rows)", len(tableRows)),
				Headers: []string{"Time", "PID", "Image", "CommandLine", "Parent", "Integrity", "User", "SHA256"},
				Rows:    tableRows,
			})
		}
	}

	// External network connections
	netRows, err2 := db.Query(`
		SELECT COALESCE(CAST(timestamp AS VARCHAR),''), COALESCE(image,''),
		       COALESCE(dst_ip,''), CAST(COALESCE(dst_port,0) AS VARCHAR),
		       COALESCE(dst_host,''), COALESCE(proto,''),
		       CAST(COALESCE(initiated,false) AS VARCHAR), COALESCE(user_name,'')
		FROM sysmon_network
		WHERE initiated = true
		  AND dst_ip IS NOT NULL AND dst_ip NOT IN ('0.0.0.0','-','','127.0.0.1')
		  AND NOT (dst_ip LIKE '10.%' OR dst_ip LIKE '192.168.%'
		        OR dst_ip LIKE '172.16.%' OR dst_ip LIKE '172.17.%' OR dst_ip LIKE '172.18.%'
		        OR dst_ip LIKE '172.19.%' OR dst_ip LIKE '172.2%.%' OR dst_ip LIKE '172.3%.%')
		ORDER BY timestamp DESC NULLS LAST LIMIT 100`)
	if err2 == nil {
		defer netRows.Close()
		var tableRows [][]string
		for netRows.Next() {
			var ts, img, dip, dport, dhost, proto, init, usr string
			netRows.Scan(&ts, &img, &dip, &dport, &dhost, &proto, &init, &usr)
			if len(ts) > 19 {
				ts = ts[:19]
			}
			tableRows = append(tableRows, []string{ts, img, dip + ":" + dport, dhost, proto, usr})
		}
		if len(tableRows) > 0 {
			s.Tables = append(s.Tables, Table{
				Title:   fmt.Sprintf("External Network Connections — Sysmon Event 3 (%d rows)", len(tableRows)),
				Headers: []string{"Time", "Process", "Destination", "Hostname", "Protocol", "User"},
				Rows:    tableRows,
			})
		}
	}

	// Suspicious DNS
	dnsRows, err3 := db.Query(`
		SELECT COALESCE(CAST(timestamp AS VARCHAR),''), COALESCE(image,''),
		       COALESCE(query_name,''), COALESCE(query_status,''),
		       COALESCE(query_results,''), COALESCE(user_name,'')
		FROM sysmon_dns
		WHERE query_name ILIKE '%.onion%' OR query_name ILIKE '%.bit%'
		   OR query_name ILIKE '%.xyz%' OR query_name ILIKE '%.top%'
		   OR query_name ILIKE '%.tk%' OR query_name ILIKE '%.ru%'
		   OR (LENGTH(SPLIT_PART(query_name,'.',1)) > 20)
		ORDER BY timestamp DESC NULLS LAST LIMIT 50`)
	if err3 == nil {
		defer dnsRows.Close()
		var tableRows [][]string
		for dnsRows.Next() {
			var ts, img, name, status, results, usr string
			dnsRows.Scan(&ts, &img, &name, &status, &results, &usr)
			if len(ts) > 19 {
				ts = ts[:19]
			}
			if len(results) > 60 {
				results = results[:60] + "…"
			}
			tableRows = append(tableRows, []string{ts, img, name, status, results, usr})
		}
		if len(tableRows) > 0 {
			s.Tables = append(s.Tables, Table{
				Title:   fmt.Sprintf("Suspicious DNS Queries — Sysmon Event 22 (%d rows)", len(tableRows)),
				Headers: []string{"Time", "Process", "Query", "Status", "Results", "User"},
				Rows:    tableRows,
			})
		}
	}

	if len(s.Tables) == 0 {
		s.Tables = []Table{{Title: "No Sysmon events found (sysmon_process/network/dns tables empty)", Headers: []string{"Info"}, Rows: nil}}
	}
	return s
}

var tmpl = template.Must(template.New("report").Funcs(template.FuncMap{
	"join":  strings.Join,
	"lower": strings.ToLower,
}).Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>forensiq &#8212; {{.CaseName}}</title>
<style>
  *{box-sizing:border-box}
  body{font-family:monospace;background:#0d1117;color:#c9d1d9;margin:0;padding:0}
  #layout{display:flex;min-height:100vh}
  #sidebar{width:240px;min-width:240px;background:#010409;border-right:1px solid #21262d;padding:1rem 0;position:sticky;top:0;height:100vh;overflow-y:auto;flex-shrink:0}
  #sidebar h3{color:#58a6ff;padding:0 1rem;margin:0 0 0.5rem;font-size:0.85em;text-transform:uppercase;letter-spacing:0.05em}
  #sidebar a{display:block;padding:3px 1rem;color:#8b949e;text-decoration:none;font-size:0.8em;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  #sidebar a:hover{color:#c9d1d9;background:#161b22}
  #sidebar .toc-count{float:right;font-size:0.75em;color:#58a6ff}
  #main{flex:1;padding:1.5rem 2rem;overflow:auto;min-width:0}
  #topbar{position:sticky;top:0;background:#0d1117;border-bottom:1px solid #21262d;padding:0.5rem 1rem;z-index:100;display:flex;align-items:center;gap:1rem}
  #search{background:#161b22;border:1px solid #30363d;color:#c9d1d9;padding:5px 12px;border-radius:6px;font-family:monospace;font-size:0.9em;width:320px;outline:none}
  #search:focus{border-color:#58a6ff}
  #search-count{color:#8b949e;font-size:0.8em}
  h1{color:#58a6ff;margin-top:0}
  h2{color:#79c0ff;border-bottom:1px solid #30363d;padding:0.4rem 0;margin-top:1.5rem;cursor:pointer;user-select:none}
  h2:hover{color:#a0c4ff}
  h2.collapsed::before{content:"+ "}
  h2:not(.collapsed)::before{content:"- "}
  h3{color:#8b949e;font-size:0.9em;margin:0.5rem 0}
  table{border-collapse:collapse;width:100%;margin:0.8rem 0;font-size:0.85em}
  th{background:#161b22;color:#58a6ff;padding:5px 10px;text-align:left;cursor:pointer;white-space:nowrap;user-select:none}
  th:hover{background:#1c2128;color:#a0c4ff}
  th.sort-asc::after{content:" \25b2"}
  th.sort-desc::after{content:" \25bc"}
  td{padding:3px 10px;border-bottom:1px solid #21262d;max-width:400px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  tr:hover td{background:#161b22}
  .meta{color:#8b949e;font-size:0.85em}
  .sev-high td{background:rgba(248,81,73,.12)}
  .sev-high:hover td{background:rgba(248,81,73,.22)}
  .sev-med td{background:rgba(210,153,34,.10)}
  .sev-med:hover td{background:rgba(210,153,34,.20)}
  .badge{display:inline-block;padding:1px 8px;border-radius:10px;font-size:0.78em;font-weight:bold;margin-left:6px;vertical-align:middle}
  .badge-high{background:rgba(248,81,73,.25);color:#f85149;border:1px solid rgba(248,81,73,.4)}
  .badge-med{background:rgba(210,153,34,.20);color:#d29922;border:1px solid rgba(210,153,34,.4)}
  .badge-low{background:rgba(100,200,100,.15);color:#56d364;border:1px solid rgba(100,200,100,.3)}
  .no-findings{color:#8b949e;font-style:italic;padding:0.5rem 0}
  code{background:#161b22;padding:1px 5px;border-radius:3px;font-size:0.9em}
  .warn-cell{color:#f85149;font-weight:bold}
  .sec-body.hidden{display:none}
  .hidden-row{display:none}
  .exec-summary{border:1px solid #30363d;border-radius:8px;padding:1rem 1.5rem;margin:1rem 0 1.5rem;background:#0d1117}
  .exec-verdict{font-size:1.1em;font-weight:bold;padding:6px 14px;border-radius:6px;display:inline-block;margin-bottom:0.8rem}
  .verdict-critical .exec-verdict{background:rgba(248,81,73,.2);color:#f85149;border:1px solid rgba(248,81,73,.5)}
  .verdict-high .exec-verdict{background:rgba(210,153,34,.2);color:#d29922;border:1px solid rgba(210,153,34,.5)}
  .verdict-medium .exec-verdict{background:rgba(88,166,255,.15);color:#58a6ff;border:1px solid rgba(88,166,255,.4)}
  .verdict-low .exec-verdict{background:rgba(63,185,80,.15);color:#56d364;border:1px solid rgba(63,185,80,.4)}
  .verdict-clean .exec-verdict{background:rgba(63,185,80,.15);color:#56d364;border:1px solid rgba(63,185,80,.4)}
  .exec-grid{display:grid;grid-template-columns:1fr 1fr 1fr;gap:1rem;margin-top:0.8rem}
  .exec-col h4{color:#58a6ff;margin:0 0 0.4rem;font-size:0.8em;text-transform:uppercase;letter-spacing:0.05em}
  .exec-col ul{margin:0;padding-left:1.2rem;font-size:0.82em;color:#c9d1d9}
  .exec-col li{margin:2px 0}
  .exec-col .ef-high{color:#f85149}
  .exec-col .ef-med{color:#d29922}
  .exec-meta{font-size:0.82em;color:#8b949e;margin:0.3rem 0}
</style>
</head>
<body>
<div id="topbar">
  <input id="search" type="text" placeholder="Search all tables..." autocomplete="off">
  <span id="search-count"></span>
</div>
<div id="layout">
<nav id="sidebar">
  <h3>Sections</h3>
  <div id="toc"></div>
</nav>
<div id="main">
<h1>forensiq &#8212; {{.CaseName}}</h1>
<p class="meta">Created: {{.CreatedAt}} | Generated: {{.GeneratedAt}}</p>

<div class="exec-summary {{.Exec.VerdictClass}}">
  <div class="exec-verdict">{{.Exec.Verdict}}</div>
  {{if .Exec.TimeRange}}<p class="exec-meta">Detection time range: {{.Exec.TimeRange}}</p>{{end}}
  <div class="exec-grid">
    <div class="exec-col">
      <h4>Top Findings</h4>
      {{if .Exec.TopFindings}}<ul>{{range .Exec.TopFindings}}<li class="ef-{{.Sev | lower}}">{{.Title}}</li>{{end}}</ul>
      {{else}}<p style="color:#8b949e;font-size:0.82em">No detections</p>{{end}}
    </div>
    <div class="exec-col">
      <h4>Attack Tactics (ATT&CK)</h4>
      {{if .Exec.Tactics}}<ul>{{range .Exec.Tactics}}<li>{{.}}</li>{{end}}</ul>
      {{else}}<p style="color:#8b949e;font-size:0.82em">None identified</p>{{end}}
      {{if .Exec.AffectedUsers}}<h4 style="margin-top:0.6rem">Affected Accounts</h4>
      <ul>{{range .Exec.AffectedUsers}}<li>{{.}}</li>{{end}}</ul>{{end}}
    </div>
    <div class="exec-col">
      <h4>Recommended Actions</h4>
      <ul>{{range .Exec.Recommendations}}<li>{{.}}</li>{{end}}</ul>
    </div>
  </div>
</div>

<h2 id="sec-threats">Threat Findings
  {{if .HighCount}}<span class="badge badge-high">{{.HighCount}} HIGH</span>{{end}}
  {{if .MedCount}}<span class="badge badge-med">{{.MedCount}} MED</span>{{end}}
  {{if .LowCount}}<span class="badge badge-low">{{.LowCount}} LOW</span>{{end}}
</h2>
<div class="sec-body">
{{if .ThreatFindings}}
<table>
<thead><tr><th>Source</th><th>Type</th><th>Value</th><th>Confidence</th><th>Technique</th><th>Notes</th><th>Triage</th></tr></thead>
<tbody>
{{range .ThreatFindings}}<tr class="{{.SevClass}}"><td>{{.Source}}</td><td>{{.Type}}</td><td>{{.Value}}</td><td>{{.Confidence}}</td><td>{{.Technique}}</td><td>{{.Notes}}</td><td>{{if .TriageStatus}}<b>{{.TriageStatus}}</b>{{end}}</td></tr>
{{end}}
</tbody>
</table>
{{else}}
<p class="no-findings">No automated detections found. Run <code>forensiq detect &lt;case&gt;</code> and <code>forensiq hunt &lt;case&gt;</code> first.</p>
{{end}}
</div>

{{range .Sections}}
{{if .Title}}
<h2>{{.Title}}</h2>
<div class="sec-body">
{{range .Tables}}
{{if .Rows}}
{{if .Title}}<h3>{{.Title}}</h3>{{end}}
<table>
<thead><tr>{{range .Headers}}<th>{{.}}</th>{{end}}</tr></thead>
<tbody>
{{range .Rows}}<tr>{{range .}}<td>{{.}}</td>{{end}}</tr>
{{end}}
</tbody>
</table>
{{end}}
{{end}}
</div>
{{end}}
{{end}}
</div>
</div>
<script>
(function(){
  // Build TOC from h2 elements
  var toc = document.getElementById("toc");
  var h2s = document.querySelectorAll("#main h2");
  h2s.forEach(function(h, i){
    var id = "sec-" + i;
    if (!h.id) h.id = id;
    var text = h.textContent.trim().replace(/^[-+]\s*/,"");
    var a = document.createElement("a");
    a.href = "#" + h.id;
    a.textContent = text.substring(0, 28);
    toc.appendChild(a);
    // Collapse on click
    var body = h.nextElementSibling;
    h.addEventListener("click", function(){
      var hidden = body.classList.toggle("hidden");
      h.classList.toggle("collapsed", hidden);
    });
  });

  // Warn cells containing "NOT IN"
  document.querySelectorAll("td").forEach(function(td){
    if (td.textContent.indexOf("NOT IN") !== -1) td.classList.add("warn-cell");
  });

  // Sort on th click
  document.querySelectorAll("th").forEach(function(th){
    th.addEventListener("click", function(){
      var tbl = th.closest("table");
      var idx = Array.prototype.indexOf.call(th.parentNode.children, th);
      var asc = th.dataset.sort !== "asc";
      tbl.querySelectorAll("th").forEach(function(t){ t.removeAttribute("data-sort"); t.classList.remove("sort-asc","sort-desc"); });
      th.dataset.sort = asc ? "asc" : "desc";
      th.classList.add(asc ? "sort-asc" : "sort-desc");
      var tbody = tbl.querySelector("tbody");
      var rows = Array.prototype.slice.call(tbody.querySelectorAll("tr"));
      rows.sort(function(a, b){
        var va = a.cells[idx] ? a.cells[idx].textContent : "";
        var vb = b.cells[idx] ? b.cells[idx].textContent : "";
        var na = parseFloat(va), nb = parseFloat(vb);
        if (!isNaN(na) && !isNaN(nb)) return asc ? na - nb : nb - na;
        return asc ? va.localeCompare(vb) : vb.localeCompare(va);
      });
      rows.forEach(function(r){ tbody.appendChild(r); });
    });
  });

  // Search
  var searchEl = document.getElementById("search");
  var countEl = document.getElementById("search-count");
  searchEl.addEventListener("input", function(){
    var q = this.value.toLowerCase().trim();
    var total = 0, visible = 0;
    document.querySelectorAll("tbody tr").forEach(function(tr){
      total++;
      var show = !q || tr.textContent.toLowerCase().indexOf(q) !== -1;
      tr.classList.toggle("hidden-row", !show);
      if (show) visible++;
    });
    countEl.textContent = q ? (visible + " / " + total + " rows") : "";
  });
})();
</script>
</body>
</html>
`))
