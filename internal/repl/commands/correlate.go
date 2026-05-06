package commands

import (
	"database/sql"
	"fmt"
)

// Correlate searches for term across all artifact tables — the fast way to
// "connect the dots" when an analyst spots a suspicious value in the report.
func Correlate(db *sql.DB, term string) error {
	fmt.Printf("\n  Correlating: %q\n\n", term)
	like := "%" + term + "%"

	printSection(db, "IOC Indicators", []string{"Type", "Value", "Source", "Confidence", "Notes"},
		`SELECT "type", value, source, confidence, COALESCE(notes, '')
		 FROM ioc_indicators
		 WHERE lower(value) LIKE lower(?) OR lower(COALESCE(notes,'')) LIKE lower(?)
		 ORDER BY CASE confidence WHEN 'HIGH' THEN 1 WHEN 'MED' THEN 2 ELSE 3 END
		 LIMIT 30`, like, like)

	printSection(db, "Memory Processes", []string{"PID", "PPID", "Name", "Cmdline"},
		`SELECT p.pid, p.ppid, p.name, LEFT(COALESCE(c.cmdline, ''), 120)
		 FROM mem_pslist p
		 LEFT JOIN mem_cmdline c ON p.pid = c.pid
		 WHERE lower(p.name) LIKE lower(?) OR lower(COALESCE(c.cmdline, '')) LIKE lower(?)
		 LIMIT 20`, like, like)

	printSection(db, "EVTX Events", []string{"Timestamp", "EventID", "Channel", "Message"},
		`SELECT timestamp, event_id, channel, LEFT(message, 120)
		 FROM evtx_events
		 WHERE lower(message) LIKE lower(?) AND timestamp >= TIMESTAMP '2000-01-01'
		 ORDER BY timestamp DESC
		 LIMIT 20`, like)

	printSection(db, "MFT Files", []string{"Modified", "Path", "Size"},
		`SELECT modified, path, size
		 FROM mft
		 WHERE lower(path) LIKE lower(?) AND NOT is_dir
		 ORDER BY modified DESC
		 LIMIT 20`, like)

	printSection(db, "Auth Events", []string{"Timestamp", "EventID", "User", "Domain", "Source IP"},
		`SELECT timestamp, event_id, "user", domain, COALESCE(src_ip, '-')
		 FROM auth_events
		 WHERE lower("user") LIKE lower(?) OR lower(COALESCE(src_ip, '')) LIKE lower(?)
		    OR lower(domain) LIKE lower(?)
		 ORDER BY timestamp DESC
		 LIMIT 20`, like, like, like)

	printSection(db, "Defender Detections", []string{"Timestamp", "Threat", "Severity", "Path"},
		`SELECT timestamp, threat_name, severity, path
		 FROM defender_events
		 WHERE lower(threat_name) LIKE lower(?) OR lower(path) LIKE lower(?)
		 ORDER BY timestamp DESC
		 LIMIT 20`, like, like)

	printSection(db, "Prefetch / Execution", []string{"Filename", "Run Count", "Last Run"},
		`SELECT filename, run_count, last_run
		 FROM prefetch
		 WHERE lower(filename) LIKE lower(?)
		 ORDER BY last_run DESC
		 LIMIT 10`, like)

	printSection(db, "Network Connections (RAM)", []string{"PID", "Name", "Proto", "Remote", "Port", "State"},
		`SELECT n.pid, n.name, n.proto, n.remote_addr, n.remote_port, n.state
		 FROM mem_netscan n
		 WHERE lower(n.name) LIKE lower(?) OR lower(n.remote_addr) LIKE lower(?)
		 LIMIT 20`, like, like)

	printSection(db, "$UsnJrnl", []string{"Timestamp", "Reason", "Path"},
		`SELECT timestamp, reason, path
		 FROM usnjrnl
		 WHERE lower(path) LIKE lower(?)
		 ORDER BY timestamp DESC
		 LIMIT 20`, like)

	printSection(db, "Linux Auth", []string{"Timestamp", "Event", "User", "Source IP"},
		`SELECT timestamp, event_type, COALESCE("user", ''), COALESCE(src_ip, '')
		 FROM linux_auth
		 WHERE lower(COALESCE("user",'')) LIKE lower(?) OR lower(COALESCE(src_ip,'')) LIKE lower(?)
		    OR lower(message) LIKE lower(?)
		 ORDER BY timestamp DESC
		 LIMIT 20`, like, like, like)

	printSection(db, "Shell History", []string{"Timestamp", "User", "Shell", "Command"},
		`SELECT COALESCE(CAST(timestamp AS VARCHAR), '-'), COALESCE("user",''), shell, LEFT(command, 120)
		 FROM shell_history
		 WHERE lower(command) LIKE lower(?) OR lower(COALESCE("user",'')) LIKE lower(?)
		 ORDER BY timestamp DESC NULLS LAST
		 LIMIT 20`, like, like)

	printSection(db, "Linux Persistence", []string{"Type", "User", "Path", "Command"},
		`SELECT type, COALESCE("user",''), path, LEFT(COALESCE(command,''), 120)
		 FROM linux_persistence
		 WHERE lower(COALESCE(command,'')) LIKE lower(?) OR lower(COALESCE("user",'')) LIKE lower(?)
		    OR lower(path) LIKE lower(?)
		 LIMIT 20`, like, like, like)

	printSection(db, "JumpLists", []string{"App", "Target", "Last Accessed", "Count"},
		`SELECT COALESCE(NULLIF(app_name,''), app_id), LEFT(target_path, 100),
		        COALESCE(CAST(accessed AS VARCHAR), '-'), access_count
		 FROM jumplists
		 WHERE lower(target_path) LIKE lower(?) OR lower(COALESCE(app_name,'')) LIKE lower(?)
		    OR lower(app_id) LIKE lower(?)
		 ORDER BY accessed DESC NULLS LAST
		 LIMIT 20`, like, like, like)

	printSection(db, "UserAssist / BAM", []string{"Path", "Run Count", "Last Run"},
		`SELECT path, run_count, last_run FROM userassist
		 WHERE lower(path) LIKE lower(?) ORDER BY last_run DESC LIMIT 10
		 UNION ALL
		 SELECT path, NULL, last_run FROM bam_dam
		 WHERE lower(path) LIKE lower(?) ORDER BY last_run DESC LIMIT 10`, like, like)

	printSection(db, "Recycle Bin", []string{"Original Path", "Deleted At", "Size"},
		`SELECT original_path, deleted_at, size
		 FROM recycle_bin
		 WHERE lower(original_path) LIKE lower(?)
		 ORDER BY deleted_at DESC NULLS LAST
		 LIMIT 10`, like)

	printSection(db, "Shellbags (Folder History)", []string{"Path", "Last Modified", "User", "Source"},
		`SELECT path, COALESCE(CAST(last_modified AS VARCHAR), '-'),
		        COALESCE("user", '-'), COALESCE(source, '-')
		 FROM shellbags
		 WHERE lower(path) LIKE lower(?) OR lower(COALESCE("user",'')) LIKE lower(?)
		 ORDER BY last_modified DESC NULLS LAST
		 LIMIT 20`, like, like)

	return nil
}
