package export

import (
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Format string

const (
	FormatCSV   Format = "csv"
	FormatTSV   Format = "tsv"
	FormatJSONL Format = "jsonl"
)

type Options struct {
	Format Format
	From   string
	To     string
	Source string // comma-separated source filter for timeline: "EVTX,Auth" or "" = all
	Limit  int
	Asc    bool // ascending time order (default: DESC)
}

// AllTables is the default export order.
var AllTables = []string{
	"mft", "evtx_events", "auth_events", "defender_events",
	"prefetch", "amcache", "shimcache", "lnk_files",
	"persistence", "services", "scheduled_tasks", "wmi_subs",
	"mem_pslist", "mem_cmdline", "mem_netscan", "mem_malfind",
	"ps_scriptblock", "browser_history",
	"anydesk_sessions", "anydesk_events", "anydesk_config",
	"wer_crashes", "srum_network_usage", "srum_app_usage",
	"logfile_events", "ntds_accounts",
	"bam_dam",
	"typed_urls", "run_mru", "rdp_client_history", "muicache", "opensave_mru",
	"ioc_indicators", "attack_techniques", "source_files",
	"timeline",
}

// timestampCol maps table → primary timestamp column for time filtering.
var timestampCol = map[string]string{
	"evtx_events":     "timestamp",
	"auth_events":     "timestamp",
	"defender_events": "timestamp",
	"ps_scriptblock":  "timestamp",
	"prefetch":        "last_run",
	"amcache":         "first_seen",
	"mft":             "modified",
	"lnk_files":       "modified",
	"browser_history": "visit_time",
	"persistence":     "modified",
	"services":        "modified",
}

// timelineBase is the UNION ALL that feeds the timeline view.
// Wrapped by buildTimelineQuery so filters can be applied cleanly.
const timelineBase = `(
	SELECT modified AS ts, 'MFT' AS source, 'MODIFIED' AS event, path AS detail
		FROM mft WHERE NOT is_dir AND modified >= TIMESTAMP '2000-01-01'
		AND (lower(path) LIKE '%.exe' OR lower(path) LIKE '%.dll' OR lower(path) LIKE '%.bat' OR lower(path) LIKE '%.cmd' OR lower(path) LIKE '%.ps1' OR lower(path) LIKE '%.vbs' OR lower(path) LIKE '%.js' OR lower(path) LIKE '%.pif' OR lower(path) LIKE '%.scr' OR lower(path) LIKE '%.hta' OR lower(path) LIKE '%.lnk')
	UNION ALL
	SELECT timestamp, 'EVTX', CAST(event_id AS VARCHAR), LEFT(message, 200)
		FROM evtx_events WHERE timestamp >= TIMESTAMP '2000-01-01'
	UNION ALL
	SELECT last_run, 'Prefetch', 'EXECUTED', filename
		FROM prefetch WHERE last_run IS NOT NULL AND last_run >= TIMESTAMP '2000-01-01'
	UNION ALL
	SELECT timestamp, 'Defender', threat_name, severity || ' | ' || path || ' | ' || action
		FROM defender_events WHERE timestamp >= TIMESTAMP '2000-01-01' AND threat_name != ''
	UNION ALL
	SELECT timestamp, 'Auth', 'LOGON_TYPE_' || CAST(logon_type AS VARCHAR),
		"user" || ' @ ' || domain ||
		CASE WHEN src_ip NOT IN ('-','') THEN ' from ' || src_ip ELSE '' END
		FROM auth_events WHERE timestamp >= TIMESTAMP '2000-01-01'
	UNION ALL
	SELECT first_seen, 'IOC', type, value || ' | ' || COALESCE(notes, '')
		FROM ioc_indicators WHERE first_seen IS NOT NULL AND first_seen >= TIMESTAMP '2000-01-01'
	UNION ALL
	SELECT timestamp, 'UsnJrnl', reason, path
		FROM usnjrnl WHERE timestamp IS NOT NULL AND timestamp >= TIMESTAMP '2000-01-01'
		AND (reason LIKE '%FILE_CREATE%' OR reason LIKE '%FILE_DELETE%' OR reason LIKE '%RENAME%')
	UNION ALL
	SELECT timestamp, 'LinuxAuth', event_type,
		COALESCE("user", '') || CASE WHEN src_ip != '' THEN ' from ' || src_ip ELSE '' END
		FROM linux_auth WHERE timestamp IS NOT NULL AND timestamp >= TIMESTAMP '2000-01-01'
	UNION ALL
	SELECT timestamp, 'ShellHistory', shell, "user" || ': ' || LEFT(command, 200)
		FROM shell_history WHERE timestamp IS NOT NULL AND timestamp >= TIMESTAMP '2000-01-01'
	UNION ALL
	SELECT timestamp, 'AnyDesk', direction,
		COALESCE(client_alias, '') || CASE WHEN anydesk_id IS NOT NULL AND anydesk_id != '' THEN ' [' || anydesk_id || ']' ELSE '' END
		FROM anydesk_sessions WHERE timestamp IS NOT NULL AND timestamp >= TIMESTAMP '2000-01-01'
	UNION ALL
	SELECT crash_time, 'WER', app_name,
		COALESCE(fault_module, '') || ' ' || COALESCE(exception_code, '')
		FROM wer_crashes WHERE crash_time IS NOT NULL AND crash_time >= TIMESTAMP '2000-01-01'
	UNION ALL
	SELECT timestamp, 'SRUM/Net', app_name,
		'sent=' || CAST(bytes_sent AS VARCHAR) || ' recv=' || CAST(bytes_recvd AS VARCHAR)
		FROM srum_network_usage WHERE timestamp IS NOT NULL AND timestamp >= TIMESTAMP '2000-01-01'
		AND (bytes_sent > 0 OR bytes_recvd > 0)
	UNION ALL
	SELECT modified, 'RDP-Client', server,
	    CASE WHEN username != '' THEN 'user=' || username ELSE '' END
	FROM rdp_client_history WHERE modified IS NOT NULL AND modified >= TIMESTAMP '2000-01-01'
	UNION ALL
	SELECT modified, 'RunMRU', mru_order, "user" || ': ' || command
	FROM run_mru WHERE modified IS NOT NULL AND modified >= TIMESTAMP '2000-01-01'
) _tl`

// BuildTimelineQuery returns a complete SELECT with optional time/source filters.
// Exported so cmd/timeline.go can also use it for display.
func BuildTimelineQuery(opts Options) string {
	q := "SELECT ts, source, event, detail FROM " + timelineBase

	var conds []string
	if opts.From != "" {
		conds = append(conds, fmt.Sprintf("ts >= CAST('%s' AS TIMESTAMP)", escapeSQ(opts.From)))
	}
	if opts.To != "" {
		conds = append(conds, fmt.Sprintf("ts <= CAST('%s' AS TIMESTAMP)", escapeSQ(opts.To)))
	}
	if opts.Source != "" && strings.ToLower(opts.Source) != "all" {
		parts := strings.Split(opts.Source, ",")
		quoted := make([]string, 0, len(parts))
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				quoted = append(quoted, fmt.Sprintf("'%s'", escapeSQ(p)))
			}
		}
		if len(quoted) > 0 {
			conds = append(conds, "source IN ("+strings.Join(quoted, ", ")+")")
		}
	}
	if len(conds) > 0 {
		q += "\nWHERE " + strings.Join(conds, " AND ")
	}

	order := "DESC"
	if opts.Asc {
		order = "ASC"
	}
	q += "\nORDER BY ts " + order

	if opts.Limit > 0 {
		q += fmt.Sprintf("\nLIMIT %d", opts.Limit)
	}
	return q
}

// Export writes a single table (or "timeline") to w. Returns number of rows written.
func Export(db *sql.DB, table string, opts Options, w io.Writer) (int64, error) {
	query, err := buildQuery(table, opts)
	if err != nil {
		return 0, err
	}
	rows, err := db.Query(query)
	if err != nil {
		return 0, fmt.Errorf("export %s: %w", table, err)
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return 0, err
	}

	switch opts.Format {
	case FormatTSV:
		return writeDelimited(rows, cols, '\t', w)
	case FormatJSONL:
		return writeJSONL(rows, cols, w)
	default:
		return writeDelimited(rows, cols, ',', w)
	}
}

// ExportAll exports every table in AllTables to separate files in outDir.
// Files for empty tables are removed.
func ExportAll(db *sql.DB, outDir string, opts Options) error {
	ext := string(opts.Format)
	if ext == "" {
		ext = "csv"
		opts.Format = FormatCSV
	}
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return err
	}
	for _, t := range AllTables {
		path := filepath.Join(outDir, t+"."+ext)
		f, err := os.Create(path)
		if err != nil {
			return fmt.Errorf("create %s: %w", path, err)
		}
		n, exportErr := Export(db, t, opts, f)
		f.Close()
		if exportErr != nil || n == 0 {
			_ = os.Remove(path)
			continue
		}
		fmt.Printf("  %-25s %d rows → %s\n", t, n, filepath.Base(path))
	}
	return nil
}

func buildQuery(table string, opts Options) (string, error) {
	if table == "timeline" {
		return BuildTimelineQuery(opts), nil
	}

	q := fmt.Sprintf("SELECT * FROM %s", table)
	var conds []string

	if col, ok := timestampCol[table]; ok {
		if opts.From != "" {
			conds = append(conds, fmt.Sprintf("%s >= CAST('%s' AS TIMESTAMP)", col, escapeSQ(opts.From)))
		}
		if opts.To != "" {
			conds = append(conds, fmt.Sprintf("%s <= CAST('%s' AS TIMESTAMP)", col, escapeSQ(opts.To)))
		}
	}

	if len(conds) > 0 {
		q += " WHERE " + strings.Join(conds, " AND ")
	}
	if opts.Limit > 0 {
		q += fmt.Sprintf(" LIMIT %d", opts.Limit)
	}
	return q, nil
}

func escapeSQ(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}

func writeDelimited(rows *sql.Rows, cols []string, sep rune, w io.Writer) (int64, error) {
	cw := csv.NewWriter(w)
	cw.Comma = sep
	if err := cw.Write(cols); err != nil {
		return 0, err
	}
	vals := make([]interface{}, len(cols))
	ptrs := make([]interface{}, len(cols))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	var count int64
	for rows.Next() {
		if err := rows.Scan(ptrs...); err != nil {
			return count, err
		}
		rec := make([]string, len(cols))
		for i, v := range vals {
			rec[i] = valToString(v)
		}
		if err := cw.Write(rec); err != nil {
			return count, err
		}
		count++
	}
	cw.Flush()
	return count, cw.Error()
}

func writeJSONL(rows *sql.Rows, cols []string, w io.Writer) (int64, error) {
	enc := json.NewEncoder(w)
	vals := make([]interface{}, len(cols))
	ptrs := make([]interface{}, len(cols))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	var count int64
	for rows.Next() {
		if err := rows.Scan(ptrs...); err != nil {
			return count, err
		}
		m := make(map[string]interface{}, len(cols))
		for i, v := range vals {
			switch vt := v.(type) {
			case time.Time:
				m[cols[i]] = vt.UTC().Format(time.RFC3339)
			default:
				m[cols[i]] = v
			}
		}
		if err := enc.Encode(m); err != nil {
			return count, err
		}
		count++
	}
	return count, nil
}

func valToString(v interface{}) string {
	if v == nil {
		return ""
	}
	switch vt := v.(type) {
	case time.Time:
		return vt.UTC().Format("2006-01-02 15:04:05")
	case []byte:
		return string(vt)
	case bool:
		if vt {
			return "true"
		}
		return "false"
	default:
		return fmt.Sprintf("%v", vt)
	}
}
