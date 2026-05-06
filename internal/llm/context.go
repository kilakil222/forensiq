package llm

import (
	"database/sql"
	"fmt"
	"strings"
	"time"
)

const systemPrompt = `You are an expert DFIR (Digital Forensics and Incident Response) analyst.
You are analyzing a forensic case using the forensiq tool. The user will provide you with artifact
data extracted from a Windows or Linux system and ask you a specific question.

Rules:
- Be concise and direct. Focus on actionable findings.
- Reference specific artifacts (file paths, process names, timestamps, event IDs) when possible.
- Highlight the most suspicious/critical findings first.
- If data is insufficient to answer confidently, say so clearly.
- Use MITRE ATT&CK technique IDs where applicable.
- Do not make up data not present in the context.`

// BuildContext queries the DuckDB case database and returns a formatted forensic summary
// suitable for use as LLM context.
func BuildContext(db *sql.DB) string {
	var sb strings.Builder

	sb.WriteString("=== FORENSIC CASE CONTEXT ===\n\n")

	// Case metadata
	var caseName, createdAt string
	db.QueryRow("SELECT name, created_at FROM case_meta WHERE id = 1").Scan(&caseName, &createdAt)
	if caseName != "" {
		sb.WriteString(fmt.Sprintf("Case: %s  Created: %s\n\n", caseName, createdAt))
	}

	// Artifact counts
	sb.WriteString("--- ARTIFACT COUNTS ---\n")
	counts := []struct{ label, q string }{
		{"MFT entries", "SELECT COUNT(*) FROM mft"},
		{"EVTX events", "SELECT COUNT(*) FROM evtx_events"},
		{"Auth events", "SELECT COUNT(*) FROM auth_events"},
		{"Prefetch entries", "SELECT COUNT(*) FROM prefetch"},
		{"Shimcache entries", "SELECT COUNT(*) FROM shimcache"},
		{"Amcache entries", "SELECT COUNT(*) FROM amcache"},
		{"Processes (RAM)", "SELECT COUNT(*) FROM mem_pslist"},
		{"Malfind hits", "SELECT COUNT(*) FROM mem_malfind"},
		{"SSH auth events", "SELECT COUNT(*) FROM linux_auth"},
		{"$UsnJrnl records", "SELECT COUNT(*) FROM usnjrnl"},
	}
	for _, c := range counts {
		var n int64
		if err := db.QueryRow(c.q).Scan(&n); err == nil && n > 0 {
			sb.WriteString(fmt.Sprintf("  %s: %d\n", c.label, n))
		}
	}

	// IOC findings
	sb.WriteString("\n--- THREAT INDICATORS (top 30) ---\n")
	rows, err := db.Query(`
		SELECT source, "type", value, confidence, COALESCE(notes,'')
		FROM ioc_indicators
		ORDER BY CASE confidence WHEN 'HIGH' THEN 1 WHEN 'MED' THEN 2 ELSE 3 END, first_seen DESC
		LIMIT 30`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var source, typ, value, confidence, notes string
			rows.Scan(&source, &typ, &value, &confidence, &notes)
			sb.WriteString(fmt.Sprintf("  [%s] %s: %s", confidence, typ, truncCtx(value, 100)))
			if notes != "" {
				sb.WriteString(fmt.Sprintf(" — %s", truncCtx(notes, 80)))
			}
			sb.WriteString(fmt.Sprintf(" (src:%s)\n", source))
		}
	}

	// Recent prefetch (execution evidence)
	sb.WriteString("\n--- RECENTLY EXECUTED (Prefetch) ---\n")
	pfRows, _ := db.Query(`SELECT filename, run_count, last_run FROM prefetch ORDER BY last_run DESC NULLS LAST LIMIT 20`)
	if pfRows != nil {
		defer pfRows.Close()
		for pfRows.Next() {
			var name string
			var count int
			var ts time.Time
			pfRows.Scan(&name, &count, &ts)
			sb.WriteString(fmt.Sprintf("  %s  runs=%d  last=%s\n", name, count, ts.Format("2006-01-02 15:04")))
		}
	}

	// Key EVTX events
	sb.WriteString("\n--- KEY SECURITY EVENTS (EVTX top 20) ---\n")
	evtxRows, _ := db.Query(`
		SELECT timestamp, event_id, LEFT(message,120)
		FROM evtx_events
		WHERE event_id IN (4624,4625,4648,4688,4698,4720,4726,4732,7045,1102,4104)
		  AND timestamp >= TIMESTAMP '2000-01-01'
		ORDER BY timestamp DESC LIMIT 20`)
	if evtxRows != nil {
		defer evtxRows.Close()
		for evtxRows.Next() {
			var ts time.Time
			var eid int
			var msg string
			evtxRows.Scan(&ts, &eid, &msg)
			sb.WriteString(fmt.Sprintf("  %s  EventID=%d  %s\n", ts.Format("2006-01-02 15:04"), eid, msg))
		}
	}

	// Shimcache suspicious
	sb.WriteString("\n--- SHIMCACHE (suspicious paths) ---\n")
	scRows, _ := db.Query(`
		SELECT path, last_modified FROM shimcache
		WHERE (lower(path) LIKE '%\temp\%' OR lower(path) LIKE '%\downloads\%' OR lower(path) LIKE '%\desktop\%' OR lower(path) LIKE '%\appdata\%')
		ORDER BY last_modified DESC NULLS LAST LIMIT 15`)
	if scRows != nil {
		defer scRows.Close()
		for scRows.Next() {
			var path string
			var ts time.Time
			scRows.Scan(&path, &ts)
			sb.WriteString(fmt.Sprintf("  %s  %s\n", ts.Format("2006-01-02 15:04"), path))
		}
	}

	// Defender detections
	sb.WriteString("\n--- DEFENDER DETECTIONS ---\n")
	defRows, _ := db.Query(`SELECT timestamp, threat_name, severity, path FROM defender_events WHERE threat_name != '' ORDER BY timestamp DESC LIMIT 10`)
	if defRows != nil {
		defer defRows.Close()
		for defRows.Next() {
			var ts time.Time
			var threat, sev, path string
			defRows.Scan(&ts, &threat, &sev, &path)
			sb.WriteString(fmt.Sprintf("  %s  [%s] %s  %s\n", ts.Format("2006-01-02 15:04"), sev, threat, path))
		}
	}

	// Memory processes (top suspicious)
	sb.WriteString("\n--- MEMORY PROCESSES (top 20) ---\n")
	psRows, _ := db.Query(`
		SELECT p.pid, p.ppid, p.name, LEFT(COALESCE(c.cmdline,''), 120)
		FROM mem_pslist p LEFT JOIN mem_cmdline c ON p.pid = c.pid
		ORDER BY p.create_time DESC NULLS LAST LIMIT 20`)
	if psRows != nil {
		defer psRows.Close()
		for psRows.Next() {
			var pid, ppid int
			var name, cmdline string
			psRows.Scan(&pid, &ppid, &name, &cmdline)
			sb.WriteString(fmt.Sprintf("  pid=%d ppid=%d %s  %s\n", pid, ppid, name, cmdline))
		}
	}

	// Linux auth summary
	var linuxCount int64
	db.QueryRow("SELECT COUNT(*) FROM linux_auth").Scan(&linuxCount)
	if linuxCount > 0 {
		sb.WriteString("\n--- LINUX AUTH EVENTS (top 20) ---\n")
		laRows, _ := db.Query(`
			SELECT timestamp, event_type, COALESCE("user",''), COALESCE(src_ip,'')
			FROM linux_auth ORDER BY timestamp DESC NULLS LAST LIMIT 20`)
		if laRows != nil {
			defer laRows.Close()
			for laRows.Next() {
				var ts time.Time
				var evType, user, ip string
				laRows.Scan(&ts, &evType, &user, &ip)
				sb.WriteString(fmt.Sprintf("  %s  %s  user=%s  ip=%s\n", ts.Format("2006-01-02 15:04"), evType, user, ip))
			}
		}
	}

	sb.WriteString("\n=== END OF CONTEXT ===\n")
	return sb.String()
}

func truncCtx(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
