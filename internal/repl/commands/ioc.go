package commands

import (
	"database/sql"
	"fmt"

	"forensiq/internal/display"
)

func IOC(db *sql.DB) error {
	rows, err := db.Query(`
		SELECT type, value, source, confidence, related_campaign, first_seen
		FROM ioc_indicators
		ORDER BY confidence DESC, first_seen DESC
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	headers := []string{"Type", "Value", "Source", "Confidence", "Campaign", "First Seen"}
	var tableRows [][]string
	count := 0

	for rows.Next() {
		var typ, value, source, confidence, campaign, firstSeen string
		rows.Scan(&typ, &value, &source, &confidence, &campaign, &firstSeen)
		tableRows = append(tableRows, []string{typ, value, source, confidence, campaign, firstSeen})
		count++
	}

	if count == 0 {
		fmt.Println("  (no IOC indicators — run analysis first or add manually via sql)")
		return nil
	}

	display.Table(headers, tableRows)
	fmt.Printf("  %d indicators\n\n", count)
	return nil
}
