package sigma

import (
	"fmt"
	"sort"
	"strings"
)

// ToInsertSQL converts a rule to an INSERT INTO ioc_indicators ... SELECT query.
// Returns an error if the logsource is unsupported or the detection is malformed.
func ToInsertSQL(rule *Rule) (string, error) {
	src, ok := resolveLogsource(rule)
	if !ok {
		return "", fmt.Errorf("unsupported logsource category=%q service=%q", rule.Logsource.Category, rule.Logsource.Service)
	}

	det := rule.Detection
	condition, _ := det["condition"].(string)
	if condition == "" {
		return "", fmt.Errorf("missing detection.condition")
	}

	// Build SQL fragment for each named selection/filter in detection.
	selFrags := map[string]string{}
	var selNames []string
	for k, v := range det {
		if k == "condition" {
			continue
		}
		frag, err := buildSelectionSQL(v, src.fields)
		if err != nil {
			return "", fmt.Errorf("selection %q: %w", k, err)
		}
		selFrags[k] = frag
		selNames = append(selNames, k)
	}
	sort.Strings(selNames) // deterministic order

	where, err := conditionToSQL(condition, selFrags, selNames)
	if err != nil {
		return "", fmt.Errorf("condition: %w", err)
	}

	notesText := rule.Title
	if rule.Description != "" {
		notesText = rule.Title + " — " + rule.Description
	}
	notes := strings.ReplaceAll(notesText, "'", "''")
	source := "sigma:" + ruleSourceID(rule)
	technique := strings.ReplaceAll(rule.Technique(), "'", "''")
	confidence := rule.Severity()

	return fmt.Sprintf(`INSERT INTO ioc_indicators (type, value, source, confidence, related_campaign, first_seen, notes)
SELECT 'event', %s, '%s', '%s', '%s', %s, '%s'
FROM %s
WHERE (%s)`,
		src.valExpr, source, confidence, technique, src.tsExpr, notes,
		src.from, where,
	), nil
}

func ruleSourceID(r *Rule) string {
	if r.ID != "" {
		return r.ID[:min8(len(r.ID))]
	}
	return sanitizeID(r.Title)
}

func min8(n int) int {
	if n < 8 {
		return n
	}
	return 8
}

func sanitizeID(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	for _, c := range s {
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' {
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

// buildSelectionSQL converts a detection selection value to a SQL boolean expression.
func buildSelectionSQL(val interface{}, fields map[string]string) (string, error) {
	switch v := val.(type) {
	case map[string]interface{}:
		return buildMapSQL(v, fields)
	case []interface{}:
		// List of maps: OR them together.
		var parts []string
		for _, item := range v {
			switch m := item.(type) {
			case map[string]interface{}:
				s, err := buildMapSQL(m, fields)
				if err != nil {
					return "", err
				}
				parts = append(parts, "("+s+")")
			case string:
				// keywords list — full-text search not supported, skip
			}
		}
		if len(parts) == 0 {
			return "TRUE", nil
		}
		return strings.Join(parts, " OR "), nil
	default:
		return "TRUE", nil
	}
}

// buildMapSQL converts a field:value map to SQL — all conditions ANDed.
func buildMapSQL(m map[string]interface{}, fields map[string]string) (string, error) {
	// Sort keys for deterministic output.
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var parts []string
	for _, key := range keys {
		cond, err := buildFieldCond(key, m[key], fields)
		if err != nil {
			return "", err
		}
		parts = append(parts, cond)
	}
	if len(parts) == 0 {
		return "TRUE", nil
	}
	return strings.Join(parts, " AND "), nil
}

// buildFieldCond converts a "Field|modifier|modifier: value" pair to SQL.
func buildFieldCond(key string, val interface{}, fields map[string]string) (string, error) {
	segments := strings.Split(key, "|")
	fieldName := segments[0]
	modifiers := segments[1:]

	col, ok := fields[fieldName]
	if !ok {
		return "TRUE", nil // unknown field — skip, don't fail the rule
	}

	values := toStringSlice(val)
	if len(values) == 0 {
		if val == nil {
			return fmt.Sprintf("(%s IS NULL)", col), nil
		}
		return "TRUE", nil
	}

	return buildCondSQL(col, modifiers, values), nil
}

func buildCondSQL(col string, mods []string, values []string) string {
	containsAll := false
	windash := false
	mainMod := ""
	for _, m := range mods {
		switch m {
		case "all":
			containsAll = true
		case "windash":
			windash = true
		case "contains", "startswith", "endswith", "re", "cidr", "gt", "gte", "lt", "lte":
			mainMod = m
		}
	}

	colExpr := fmt.Sprintf("CAST(%s AS VARCHAR)", col)

	buildOne := func(v string) string {
		if v == "null" {
			return fmt.Sprintf("(%s IS NULL)", col)
		}
		switch mainMod {
		case "contains":
			if windash {
				return buildWindash(colExpr, "%"+v+"%")
			}
			return fmt.Sprintf("(%s LIKE '%s')", colExpr, sqlLikeSafe("%"+v+"%"))
		case "startswith":
			return fmt.Sprintf("(%s LIKE '%s')", colExpr, sqlLikeSafe(v+"%"))
		case "endswith":
			if windash {
				return buildWindash(colExpr, "%"+v)
			}
			return fmt.Sprintf("(%s LIKE '%s')", colExpr, sqlLikeSafe("%"+v))
		case "re":
			// regex unsupported in this DuckDB build — skip to avoid crash
			return "1=0"
		case "gt":
			return fmt.Sprintf("(%s > %s)", col, escapeSQ(v))
		case "gte":
			return fmt.Sprintf("(%s >= %s)", col, escapeSQ(v))
		case "lt":
			return fmt.Sprintf("(%s < %s)", col, escapeSQ(v))
		case "lte":
			return fmt.Sprintf("(%s <= %s)", col, escapeSQ(v))
		default:
			if strings.ContainsAny(v, "*?") {
				return fmt.Sprintf("(%s LIKE '%s')", colExpr, sqlLikeSafe(wildcardToLike(v)))
			}
			return fmt.Sprintf("(%s = '%s')", colExpr, escapeSQ(v))
		}
	}

	if len(values) == 1 {
		return buildOne(values[0])
	}

	sep := " OR "
	if containsAll {
		sep = " AND "
	}
	parts := make([]string, len(values))
	for i, v := range values {
		parts[i] = buildOne(v)
	}
	return "(" + strings.Join(parts, sep) + ")"
}

// buildWindash generates OR conditions for both - and / prefix variants.
func buildWindash(col, pattern string) string {
	slash := strings.ReplaceAll(pattern, "-", "/")
	return fmt.Sprintf("((%s LIKE '%s') OR (%s LIKE '%s'))",
		col, sqlLikeSafe(pattern),
		col, sqlLikeSafe(slash))
}

func wildcardToLike(s string) string {
	s = strings.ReplaceAll(s, "%", "\\%")
	s = strings.ReplaceAll(s, "_", "\\_")
	s = strings.ReplaceAll(s, "*", "%")
	s = strings.ReplaceAll(s, "?", "_")
	return s
}

func sqlLikeSafe(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}

func escapeSQ(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}

func toStringSlice(val interface{}) []string {
	switch v := val.(type) {
	case string:
		return []string{v}
	case float64:
		return []string{fmt.Sprintf("%g", v)}
	case int:
		return []string{fmt.Sprintf("%d", v)}
	case bool:
		if v {
			return []string{"1"}
		}
		return []string{"0"}
	case []interface{}:
		ss := make([]string, 0, len(v))
		for _, item := range v {
			ss = append(ss, fmt.Sprintf("%v", item))
		}
		return ss
	default:
		return nil
	}
}

// conditionToSQL converts a SIGMA condition string to a SQL boolean expression.
func conditionToSQL(condition string, selFrags map[string]string, selNames []string) (string, error) {
	tokens := strings.Fields(condition)
	expr, _, err := parseCondExpr(tokens, 0, selFrags, selNames)
	return expr, err
}

func parseCondExpr(tokens []string, pos int, sels map[string]string, names []string) (string, int, error) {
	left, pos, err := parseCondTerm(tokens, pos, sels, names)
	if err != nil {
		return "", pos, err
	}
	for pos < len(tokens) {
		op := strings.ToLower(tokens[pos])
		if op != "and" && op != "or" {
			break
		}
		right, newPos, err := parseCondTerm(tokens, pos+1, sels, names)
		if err != nil {
			return "", pos, err
		}
		if op == "and" {
			left = "(" + left + " AND " + right + ")"
		} else {
			left = "(" + left + " OR " + right + ")"
		}
		pos = newPos
	}
	return left, pos, nil
}

func parseCondTerm(tokens []string, pos int, sels map[string]string, names []string) (string, int, error) {
	if pos >= len(tokens) {
		return "TRUE", pos, nil
	}
	tok := strings.ToLower(tokens[pos])
	switch tok {
	case "not":
		inner, newPos, err := parseCondTerm(tokens, pos+1, sels, names)
		if err != nil {
			return "", pos, err
		}
		return "NOT (" + inner + ")", newPos, nil
	case "(":
		inner, newPos, err := parseCondExpr(tokens, pos+1, sels, names)
		if err != nil {
			return "", pos, err
		}
		if newPos < len(tokens) && tokens[newPos] == ")" {
			newPos++
		}
		return "(" + inner + ")", newPos, nil
	case "1":
		if pos+2 < len(tokens) && strings.ToLower(tokens[pos+1]) == "of" {
			pattern := tokens[pos+2]
			return expandPattern(pattern, sels, names, "OR"), pos + 3, nil
		}
		return selOrTrue("1", sels), pos + 1, nil
	case "all":
		if pos+2 < len(tokens) && strings.ToLower(tokens[pos+1]) == "of" {
			pattern := tokens[pos+2]
			return expandPattern(pattern, sels, names, "AND"), pos + 3, nil
		}
		return selOrTrue("all", sels), pos + 1, nil
	default:
		return selOrTrue(tokens[pos], sels), pos + 1, nil
	}
}

func expandPattern(pattern string, sels map[string]string, names []string, op string) string {
	pattern = strings.ToLower(pattern)
	prefix := strings.TrimSuffix(pattern, "*")
	var parts []string
	for _, n := range names {
		if strings.HasPrefix(strings.ToLower(n), prefix) {
			if s, ok := sels[n]; ok {
				parts = append(parts, "("+s+")")
			}
		}
	}
	if len(parts) == 0 {
		return "TRUE"
	}
	return strings.Join(parts, " "+op+" ")
}

func selOrTrue(name string, sels map[string]string) string {
	if s, ok := sels[name]; ok {
		return s
	}
	return "TRUE"
}
