package commands

import (
	"database/sql"
	"fmt"
	"os"

	"forensiq/internal/sigma"
)

func Hunt(db *sql.DB, rulesDir string) error {
	if rulesDir == "" {
		// Try default locations
		for _, candidate := range []string{"./rules/sigma", "rules/sigma"} {
			if fi, err := os.Stat(candidate); err == nil && fi.IsDir() {
				rulesDir = candidate
				break
			}
		}
	}
	if rulesDir == "" {
		return fmt.Errorf("no rules directory found; specify path: hunt <rules-dir>")
	}

	rules, errs := sigma.LoadDir(rulesDir)
	for _, e := range errs {
		fmt.Fprintf(os.Stderr, "  warn: %v\n", e)
	}
	if len(rules) == 0 {
		return fmt.Errorf("no valid rules found in %s", rulesDir)
	}
	fmt.Printf("Loaded %d rules from %s\n", len(rules), rulesDir)

	results, err := sigma.RunAll(db, rules)
	if err != nil {
		return err
	}

	for _, r := range results {
		if r.Err != nil || r.Hits == 0 {
			continue
		}
		fmt.Printf("  [%s]  %3d hit(s) — %s\n", r.Rule.Severity(), r.Hits, r.Rule.Title)
	}
	fmt.Println("\n  Results stored in ioc_indicators. Use: ioc  to view.")
	return nil
}
