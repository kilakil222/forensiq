package commands

import (
	"database/sql"
	"fmt"
	"os"

	"forensiq/internal/yaralite"
)

func Yara(db *sql.DB, rulesDir string) error {
	if rulesDir == "" {
		for _, candidate := range []string{"./rules/yara", "rules/yara"} {
			if fi, err := os.Stat(candidate); err == nil && fi.IsDir() {
				rulesDir = candidate
				break
			}
		}
	}
	if rulesDir == "" {
		return fmt.Errorf("no yara-lite rules directory found; specify path: yara <rules-dir>")
	}

	rules, errs := yaralite.LoadDir(rulesDir)
	for _, e := range errs {
		fmt.Fprintf(os.Stderr, "  warn: %v\n", e)
	}
	if len(rules) == 0 {
		return fmt.Errorf("no valid rules found in %s", rulesDir)
	}
	fmt.Printf("Loaded %d yara-lite rules from %s\n", len(rules), rulesDir)

	results, err := yaralite.ScanAll(db, rules)
	if err != nil {
		return err
	}

	ruleHits := map[string]int64{}
	for _, r := range results {
		if r.Hits > 0 {
			ruleHits[r.Rule.Name] += r.Hits
		}
	}
	for name, n := range ruleHits {
		fmt.Printf("  %4d hit(s) — %s\n", n, name)
	}
	if len(ruleHits) == 0 {
		fmt.Println("  No pattern matches found.")
	} else {
		fmt.Println("\n  Results stored in ioc_indicators. Use: ioc  to view.")
	}
	return nil
}
