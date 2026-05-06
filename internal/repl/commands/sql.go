package commands

import (
	"database/sql"
	"fmt"
	"strings"

	"forensiq/internal/display"
)

func SQL(query string, db *sql.DB) error {
	if strings.TrimSpace(query) == "" {
		return fmt.Errorf("empty query")
	}

	rows, err := db.Query(query)
	if err != nil {
		return err
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return err
	}

	var tableRows [][]string
	vals := make([]interface{}, len(cols))
	ptrs := make([]interface{}, len(cols))
	for i := range vals {
		ptrs[i] = &vals[i]
	}

	count := 0
	for rows.Next() {
		if err := rows.Scan(ptrs...); err != nil {
			return err
		}
		row := make([]string, len(cols))
		for i, v := range vals {
			row[i] = fmt.Sprintf("%v", v)
		}
		tableRows = append(tableRows, row)
		count++
		if count >= 1000 {
			break
		}
	}

	if count == 0 {
		fmt.Println("  (no rows)")
		return nil
	}

	display.Table(cols, tableRows)
	if count >= 1000 {
		fmt.Printf("  (showing first 1000 rows — add LIMIT to your query)\n\n")
	}
	return nil
}
