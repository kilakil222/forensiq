package sigma

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Rule is a SIGMA-compatible detection rule (JSON-serializable).
// To convert community YAML rules:
//   python3 -c "import yaml,json,sys; json.dump(yaml.safe_load(sys.stdin),sys.stdout,indent=2)" < rule.yml > rule.json
type Rule struct {
	Title       string                 `json:"title"`
	ID          string                 `json:"id"`
	Description string                 `json:"description"`
	Level       string                 `json:"level"` // critical/high/medium/low
	Status      string                 `json:"status"`
	Tags        []string               `json:"tags"`
	Logsource   Logsource              `json:"logsource"`
	Detection   map[string]interface{} `json:"detection"`
}

type Logsource struct {
	Category   string `json:"category"`
	Product    string `json:"product"`
	Service    string `json:"service"`
	Definition string `json:"definition"`
}

// Technique extracts the first MITRE ATT&CK technique tag (T1234.001 format).
func (r *Rule) Technique() string {
	for _, tag := range r.Tags {
		tag = strings.ToLower(tag)
		if strings.HasPrefix(tag, "attack.t") {
			id := strings.TrimPrefix(tag, "attack.")
			return strings.ToUpper(id)
		}
	}
	return ""
}

// Severity normalizes the level to HIGH/MED/LOW.
func (r *Rule) Severity() string {
	switch strings.ToLower(r.Level) {
	case "critical", "high":
		return "HIGH"
	case "medium":
		return "MED"
	default:
		return "LOW"
	}
}

// LoadFile parses a single rule file (JSON or YAML).
func LoadFile(path string) (*Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	ext := strings.ToLower(filepath.Ext(path))
	var r Rule

	if ext == ".yml" || ext == ".yaml" {
		// Unmarshal YAML → generic map → JSON → Rule to reuse json struct tags.
		var raw map[string]interface{}
		if err := yaml.Unmarshal(data, &raw); err != nil {
			return nil, fmt.Errorf("sigma: parse yaml %s: %w", filepath.Base(path), err)
		}
		jsonData, err := json.Marshal(raw)
		if err != nil {
			return nil, fmt.Errorf("sigma: yaml→json %s: %w", filepath.Base(path), err)
		}
		if err := json.Unmarshal(jsonData, &r); err != nil {
			return nil, fmt.Errorf("sigma: decode %s: %w", filepath.Base(path), err)
		}
	} else {
		if err := json.Unmarshal(data, &r); err != nil {
			return nil, fmt.Errorf("sigma: parse %s: %w", filepath.Base(path), err)
		}
	}

	if r.Title == "" {
		return nil, fmt.Errorf("sigma: %s: missing title", filepath.Base(path))
	}
	return &r, nil
}

// LoadDir loads all *.json, *.yml and *.yaml rule files from a directory.
func LoadDir(dir string) ([]*Rule, []error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, []error{err}
	}
	var rules []*Rule
	var errs []error
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := strings.ToLower(e.Name())
		if !strings.HasSuffix(name, ".json") && !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml") {
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
