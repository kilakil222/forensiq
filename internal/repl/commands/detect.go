package commands

import (
	"database/sql"
	"fmt"

	"forensiq/internal/detect"
)

func Detect(db *sql.DB) error {
	fmt.Println("Running built-in detectors...")
	results, err := detect.RunAll(db)
	if err != nil {
		return err
	}
	if len(results) == 0 {
		fmt.Println("  No hits detected.")
		return nil
	}
	fmt.Printf("  %-8s  %-10s  %s\n", "HITS", "SEVERITY", "DETECTOR")
	fmt.Printf("  %-8s  %-10s  %s\n", "----", "--------", "--------")
	for _, r := range results {
		fmt.Printf("  %-8d  %-10s  %s\n", r.Hits, r.Severity, r.Name)
	}
	fmt.Printf("\n  Results stored in ioc_indicators. Use: ioc  to view.\n")
	return nil
}
