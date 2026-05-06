package commands

import (
	"database/sql"
	"fmt"
	"time"

	"forensiq/internal/display"
)

func Pivot(db *sql.DB, pivotType, value string) error {
	switch pivotType {
	case "process":
		return pivotProcess(db, value)
	case "ip":
		return pivotIP(db, value)
	case "user":
		return pivotUser(db, value)
	case "file":
		return pivotFile(db, value)
	default:
		return fmt.Errorf("unknown pivot type %q (use: process, ip, user, file)", pivotType)
	}
}

func pivotProcess(db *sql.DB, name string) error {
	fmt.Printf("\n  Pivot: process %q\n\n", name)

	printSection(db, "Process (memory)", []string{"PID", "PPID", "Name", "Created"},
		`SELECT pid, ppid, name, create_time FROM mem_pslist WHERE lower(name) = lower(?) LIMIT 20`, name)

	printSection(db, "Command Lines", []string{"PID", "Cmdline"},
		`SELECT pid, cmdline FROM mem_cmdline WHERE lower(name) = lower(?) LIMIT 10`, name)

	printSection(db, "Network", []string{"Proto", "Remote", "Port", "State"},
		`SELECT proto, remote_addr, remote_port, "state" FROM mem_netscan
		 WHERE pid IN (SELECT pid FROM mem_pslist WHERE lower(name) = lower(?))
		 LIMIT 20`, name)

	printSection(db, "Prefetch", []string{"Filename", "Run Count", "Last Run"},
		`SELECT filename, run_count, last_run FROM prefetch WHERE lower(filename) LIKE lower(?) LIMIT 5`,
		"%"+stripExt(name)+"%")

	printSection(db, "AV Detections", []string{"Time", "Threat", "Severity"},
		`SELECT timestamp, threat_name, severity FROM defender_events
		 WHERE lower(process_name) = lower(?) OR lower(path) LIKE lower(?)
		 LIMIT 10`, name, "%"+name+"%")

	printSection(db, "IOC Matches", []string{"Type", "Value", "Campaign"},
		`SELECT type, value, related_campaign FROM ioc_indicators
		 WHERE value IN (
			SELECT remote_addr FROM mem_netscan
			WHERE pid IN (SELECT pid FROM mem_pslist WHERE lower(name) = lower(?))
		 ) LIMIT 10`, name)

	return nil
}

func pivotIP(db *sql.DB, ip string) error {
	fmt.Printf("\n  Pivot: ip %q\n\n", ip)

	printSection(db, "Memory Connections", []string{"PID", "Process", "Proto", "State"},
		`SELECT pid, name, proto, "state" FROM mem_netscan WHERE remote_addr = ? LIMIT 20`, ip)

	printSection(db, "Auth Events (src)", []string{"Time", "User", "Logon Type"},
		`SELECT timestamp, "user", logon_type FROM auth_events WHERE src_ip = ? LIMIT 20`, ip)

	printSection(db, "IOC Intel", []string{"Type", "Value", "Campaign", "Confidence"},
		`SELECT type, value, related_campaign, confidence FROM ioc_indicators WHERE value = ? LIMIT 10`, ip)

	return nil
}

func pivotUser(db *sql.DB, user string) error {
	fmt.Printf("\n  Pivot: user %q\n\n", user)

	printSection(db, "Authentication", []string{"Time", "Event ID", "Logon Type", "Source IP"},
		`SELECT timestamp, event_id, logon_type, src_ip FROM auth_events
		 WHERE lower("user") = lower(?) ORDER BY timestamp LIMIT 30`, user)

	printSection(db, "Shell History", []string{"Command", "Time"},
		`SELECT command, timestamp FROM shell_history WHERE lower("user") = lower(?) LIMIT 20`, user)

	printSection(db, "Persistence (SID)", []string{"Type", "Name", "Command"},
		`SELECT type, name, command FROM persistence WHERE sid LIKE ? LIMIT 20`, "%"+user+"%")

	return nil
}

func pivotFile(db *sql.DB, path string) error {
	fmt.Printf("\n  Pivot: file %q\n\n", path)

	like := "%" + path + "%"

	printSection(db, "MFT", []string{"Path", "Created", "Modified", "Deleted"},
		`SELECT path, created, modified, is_deleted FROM mft WHERE lower(path) LIKE lower(?) LIMIT 10`, like)

	printSection(db, "$UsnJrnl", []string{"Time", "Reason", "Path"},
		`SELECT timestamp, reason, path FROM usnjrnl WHERE lower(path) LIKE lower(?) ORDER BY timestamp LIMIT 20`, like)

	printSection(db, "Prefetch", []string{"Filename", "Run Count", "Last Run"},
		`SELECT filename, run_count, last_run FROM prefetch WHERE lower(filename) LIKE lower(?) LIMIT 5`, like)

	printSection(db, "Memory filescan", []string{"Name", "Path"},
		`SELECT name, path FROM mem_filescan WHERE lower(path) LIKE lower(?) LIMIT 10`, like)

	return nil
}

func printSection(db *sql.DB, title string, headers []string, query string, args ...interface{}) {
	rows, err := db.Query(query, args...)
	if err != nil {
		display.Error(fmt.Sprintf("%s: %v", title, err))
		return
	}
	defer rows.Close()

	var tableRows [][]string
	cols, _ := rows.Columns()
	vals := make([]interface{}, len(cols))
	ptrs := make([]interface{}, len(cols))
	for i := range vals {
		ptrs[i] = &vals[i]
	}

	for rows.Next() {
		rows.Scan(ptrs...)
		row := make([]string, len(cols))
		for i, v := range vals {
			if t, ok := v.(time.Time); ok {
				row[i] = t.Format("2006-01-02 15:04:05")
			} else {
				row[i] = fmt.Sprintf("%v", v)
			}
		}
		tableRows = append(tableRows, row)
	}

	if len(tableRows) == 0 {
		return
	}

	fmt.Printf("  [%s]\n", title)
	display.Table(headers, tableRows)
}

func stripExt(name string) string {
	for i := len(name) - 1; i >= 0; i-- {
		if name[i] == '.' {
			return name[:i]
		}
	}
	return name
}
