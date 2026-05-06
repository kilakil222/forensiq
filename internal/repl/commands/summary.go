package commands

import (
	"database/sql"
	"fmt"

	"forensiq/internal/display"
)

func Summary(db *sql.DB) error {
	type stat struct {
		label string
		query string
	}

	stats := []stat{
		{"MFT entries", "SELECT COUNT(*) FROM mft"},
		{"EVTX events", "SELECT COUNT(*) FROM evtx_events"},
		{"Auth events", "SELECT COUNT(*) FROM auth_events"},
		{"Processes (memory)", "SELECT COUNT(*) FROM mem_pslist"},
		{"Network connections", "SELECT COUNT(*) FROM mem_netscan"},
		{"Prefetch entries", "SELECT COUNT(*) FROM prefetch"},
		{"Persistence entries", "SELECT COUNT(*) FROM persistence"},
		{"IOC indicators", "SELECT COUNT(*) FROM ioc_indicators"},
		{"Malfind hits", "SELECT COUNT(*) FROM mem_malfind"},
		{"Defender detections", "SELECT COUNT(*) FROM defender_events"},
	}

	headers := []string{"Artifact", "Count"}
	var rows [][]string

	for _, s := range stats {
		var count int64
		db.QueryRow(s.query).Scan(&count)
		if count > 0 {
			rows = append(rows, []string{s.label, fmt.Sprintf("%d", count)})
		}
	}

	var name, createdAt string
	db.QueryRow("SELECT name, created_at FROM case_meta WHERE id = 1").Scan(&name, &createdAt)
	if name != "" {
		fmt.Printf("\n  Case: %s  (created: %s)\n\n", name, createdAt)
	}

	if len(rows) == 0 {
		fmt.Println("  (no artifacts extracted yet)")
		return nil
	}

	display.Table(headers, rows)
	return nil
}
