package sigma

import (
	"database/sql"
	"fmt"
	"time"
)

type RunResult struct {
	Rule     *Rule
	Hits     int64
	Err      error
	InsertSQL string
}

// RunAll executes all rules against db, inserting hits into ioc_indicators.
// Previous sigma: results are cleared first.
func RunAll(db *sql.DB, rules []*Rule) ([]RunResult, error) {
	start := time.Now()

	if _, err := db.Exec(`DELETE FROM ioc_indicators WHERE source LIKE 'sigma:%'`); err != nil {
		return nil, fmt.Errorf("sigma: clear previous: %w", err)
	}

	var results []RunResult
	for _, r := range rules {
		res := RunRule(db, r)
		results = append(results, res)
	}

	total := int64(0)
	hits := 0
	errs := 0
	for _, r := range results {
		if r.Err != nil {
			errs++
		} else if r.Hits > 0 {
			total += r.Hits
			hits++
		}
	}
	fmt.Printf("\n  Rules: %d  |  Matched: %d  |  Total hits: %d  |  Errors: %d  |  %.1fs\n\n",
		len(rules), hits, total, errs, time.Since(start).Seconds())

	return results, nil
}

// RunRule executes a single rule against db.
func RunRule(db *sql.DB, rule *Rule) RunResult {
	q, err := ToInsertSQL(rule)
	if err != nil {
		return RunResult{Rule: rule, Err: err}
	}
	res, err := db.Exec(q)
	if err != nil {
		return RunResult{Rule: rule, Err: err, InsertSQL: q}
	}
	n, _ := res.RowsAffected()
	return RunResult{Rule: rule, Hits: n, InsertSQL: q}
}
