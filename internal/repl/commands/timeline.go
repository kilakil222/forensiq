package commands

import (
	"database/sql"
	"fmt"
	"time"

	"forensiq/internal/display"
)

func Timeline(db *sql.DB, from, to string) error {
	var cond string
	var args []interface{}

	if from != "" && to != "" {
		cond = "WHERE ts BETWEEN CAST(? AS TIMESTAMP) AND CAST(? AS TIMESTAMP)"
		args = []interface{}{from, to}
	} else if from != "" {
		cond = "WHERE ts >= CAST(? AS TIMESTAMP)"
		args = []interface{}{from}
	}

	query := fmt.Sprintf(`
		SELECT ts, source, event, detail FROM (
			SELECT modified AS ts, 'MFT' AS source, 'MODIFIED' AS event, path AS detail FROM mft WHERE NOT is_dir
			UNION ALL
			SELECT timestamp, 'EVTX', CAST(event_id AS VARCHAR), message FROM evtx_events
			UNION ALL
			SELECT last_run, 'Prefetch', 'EXECUTED', filename FROM prefetch WHERE last_run IS NOT NULL
			UNION ALL
			SELECT create_time, 'Process', 'STARTED', name || ' (PID ' || CAST(pid AS VARCHAR) || ')' FROM mem_pslist WHERE create_time IS NOT NULL
			UNION ALL
			SELECT timestamp, 'Auth', 'LOGON_TYPE_' || CAST(logon_type AS VARCHAR), "user" || ' from ' || src_ip FROM auth_events
			UNION ALL
			SELECT first_seen, 'IOC', type, value FROM ioc_indicators
		) t
		%s
		ORDER BY ts
		LIMIT 500
	`, cond)

	rows, err := db.Query(query, args...)
	if err != nil {
		return err
	}
	defer rows.Close()

	headers := []string{"Timestamp", "Source", "Event", "Detail"}
	var tableRows [][]string
	count := 0

	for rows.Next() {
		var ts time.Time
		var source, event, detail string
		rows.Scan(&ts, &source, &event, &detail)

		tableRows = append(tableRows, []string{
			ts.Format("2006-01-02 15:04:05"),
			source, event,
			truncate(detail, 80),
		})
		count++
	}

	if count == 0 {
		fmt.Println("  (no events in range)")
		return nil
	}

	display.Table(headers, tableRows)
	fmt.Printf("  %d events", count)
	if count >= 500 {
		fmt.Print(" (limit 500 — narrow time range for more precision)")
	}
	fmt.Println()
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}
