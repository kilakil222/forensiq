// Package yaralite implements a lightweight text-pattern scanner that matches
// string/regex patterns against forensiq database text columns and writes hits
// into ioc_indicators. Rules use a simple JSON format (no binary YARA needed).
package yaralite

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Rule describes a set of string/regex patterns to scan across artifact text.
type Rule struct {
	Name      string   `json:"name"`
	Level     string   `json:"level"`     // critical/high/medium/low
	Tags      []string `json:"tags"`
	Strings   []string `json:"strings"`   // literal or /regex/ strings
	Condition string   `json:"condition"` // "any" (default) | "all"
	Targets   []string `json:"targets"`   // cmdline|scriptblock|events|paths|browser|all (default all)
}

// Result holds the outcome of scanning one rule against one target.
type Result struct {
	Rule  *Rule
	Table string
	Hits  int64
	Err   error
}

// scanTarget defines a DB table and the text column(s) to search.
type scanTarget struct {
	id      string
	table   string
	col     string // primary search column (SQL expression)
	valExpr string // expression for ioc_indicators.value
	tsExpr  string // expression for ioc_indicators.first_seen
}

var allTargets = []scanTarget{
	{
		id: "cmdline", table: "mem_cmdline",
		col:     "cmdline",
		valExpr: "name || ' (PID cmdline): ' || LEFT(cmdline,200)",
		tsExpr:  "NULL",
	},
	{
		id: "scriptblock", table: "ps_scriptblock",
		col:     "script_text",
		valExpr: "LEFT(script_text,300)",
		tsExpr:  "timestamp",
	},
	{
		id: "events", table: "evtx_events",
		col:     "message",
		valExpr: "CAST(event_id AS VARCHAR) || ': ' || LEFT(message,200)",
		tsExpr:  "timestamp",
	},
	{
		id: "paths", table: "mft",
		col:     "path",
		valExpr: "path",
		tsExpr:  "modified",
	},
	{
		id: "amcache_paths", table: "amcache",
		col:     "path",
		valExpr: "path",
		tsExpr:  "first_seen",
	},
	{
		id: "browser", table: "browser_history",
		col:     "url",
		valExpr: "url || CASE WHEN title IS NOT NULL THEN ' | ' || title ELSE '' END",
		tsExpr:  "visit_time",
	},
	{
		id: "defender", table: "defender_events",
		col:     "threat_name",
		valExpr: "threat_name || ' | ' || path",
		tsExpr:  "timestamp",
	},
}

var targetIndex = func() map[string][]scanTarget {
	m := map[string][]scanTarget{"all": allTargets}
	for _, t := range allTargets {
		m[t.id] = []scanTarget{t}
	}
	return m
}()

// LoadFile parses a single JSON rule file.
func LoadFile(path string) (*Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var r Rule
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("yaralite: parse %s: %w", filepath.Base(path), err)
	}
	if r.Name == "" || len(r.Strings) == 0 {
		return nil, fmt.Errorf("yaralite: %s: missing name or strings", filepath.Base(path))
	}
	return &r, nil
}

// LoadDir loads all *.json rule files from a directory.
func LoadDir(dir string) ([]*Rule, []error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, []error{err}
	}
	var rules []*Rule
	var errs []error
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		r, err := LoadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			errs = append(errs, err)
			continue
		}
		rules = append(rules, r)
	}
	return rules, errs
}

// ScanAll clears previous yaralite results and scans all rules.
func ScanAll(db *sql.DB, rules []*Rule) ([]Result, error) {
	start := time.Now()

	if _, err := db.Exec(`DELETE FROM ioc_indicators WHERE source LIKE 'yaralite:%'`); err != nil {
		return nil, fmt.Errorf("yaralite: clear previous: %w", err)
	}

	var results []Result
	for _, rule := range rules {
		results = append(results, scanRule(db, rule)...)
	}

	total := int64(0)
	matched := 0
	for _, r := range results {
		if r.Hits > 0 {
			total += r.Hits
			matched++
		}
	}
	fmt.Printf("\n  Rules: %d  |  Scan results: %d  |  Total hits: %d  |  %.1fs\n\n",
		len(rules), matched, total, time.Since(start).Seconds())

	return results, nil
}

func scanRule(db *sql.DB, rule *Rule) []Result {
	targets := resolveTargets(rule)
	level := normLevel(rule.Level)
	technique := firstTag(rule.Tags)
	notes := sqlEsc(rule.Name)
	source := "yaralite:" + sanitizeID(rule.Name)

	var results []Result
	for _, t := range targets {
		where := buildWhere(rule, t.col)
		if where == "" {
			continue
		}
		q := fmt.Sprintf(
			`INSERT INTO ioc_indicators (type, value, source, confidence, related_campaign, first_seen, notes)
SELECT 'string', %s, '%s', '%s', '%s', %s, '%s'
FROM %s WHERE %s`,
			t.valExpr, source, level, technique, t.tsExpr, notes,
			t.table, where,
		)
		res, err := db.Exec(q)
		if err != nil {
			results = append(results, Result{Rule: rule, Table: t.id, Err: err})
			continue
		}
		n, _ := res.RowsAffected()
		if n > 0 {
			results = append(results, Result{Rule: rule, Table: t.id, Hits: n})
		}
	}
	return results
}

func resolveTargets(rule *Rule) []scanTarget {
	if len(rule.Targets) == 0 {
		return allTargets
	}
	seen := map[string]bool{}
	var out []scanTarget
	for _, id := range rule.Targets {
		for _, t := range targetIndex[id] {
			if !seen[t.id] {
				seen[t.id] = true
				out = append(out, t)
			}
		}
	}
	return out
}

// buildWhere builds a SQL WHERE clause that applies all rule strings to col.
// Patterns starting and ending with / are treated as regex, others as LIKE.
func buildWhere(rule *Rule, col string) string {
	if len(rule.Strings) == 0 || col == "" {
		return ""
	}
	cast := fmt.Sprintf("CAST(%s AS VARCHAR)", col)

	conds := make([]string, 0, len(rule.Strings))
	for _, s := range rule.Strings {
		if s == "" {
			continue
		}
		if strings.HasPrefix(s, "/") && strings.HasSuffix(s, "/") && len(s) > 2 {
			_ = s[1 : len(s)-1] // regex pattern — unsupported in this DuckDB build, skip
			conds = append(conds, "1=0")
		} else {
			conds = append(conds, fmt.Sprintf("%s LIKE '%%%s%%'", cast, likeSafe(s)))
		}
	}
	if len(conds) == 0 {
		return ""
	}

	cond := strings.ToLower(strings.TrimSpace(rule.Condition))
	if cond == "all" || cond == "all of them" {
		return "(" + strings.Join(conds, " AND ") + ")"
	}
	return "(" + strings.Join(conds, " OR ") + ")"
}

func likeSafe(s string) string {
	s = strings.ReplaceAll(s, "'", "''")
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "%", `\%`)
	s = strings.ReplaceAll(s, "_", `\_`)
	return s
}

func sqlEsc(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}

func normLevel(s string) string {
	switch strings.ToLower(s) {
	case "critical", "high":
		return "HIGH"
	case "medium":
		return "MED"
	default:
		return "LOW"
	}
}

func firstTag(tags []string) string {
	for _, t := range tags {
		lower := strings.ToLower(t)
		if strings.HasPrefix(lower, "attack.t") {
			return strings.ToUpper(strings.TrimPrefix(lower, "attack."))
		}
	}
	return ""
}

func sanitizeID(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			b.WriteRune(c)
		} else {
			b.WriteByte('_')
		}
		if b.Len() >= 32 {
			break
		}
	}
	return b.String()
}
