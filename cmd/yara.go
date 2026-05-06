package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"forensiq/internal/fcase"
	"forensiq/internal/schema"
	"forensiq/internal/yaralite"
)

var yaraCmd = &cobra.Command{
	Use:   "yara <file.fcase>",
	Short: "Scan text artifacts for string/regex patterns (yara-lite)",
	Long: `Scan cmdlines, script blocks, event messages, file paths and browser history
for known-bad strings and regex patterns.

  forensiq yara case.fcase                         # built-in rules
  forensiq yara case.fcase --rules ./my-yara/      # custom rule directory
  forensiq yara case.fcase --rule ioc.json         # single rule file

Rule format: JSON with name, level, strings[], condition, targets[].
Pattern: literal string or /regex/ (wrapped in forward slashes).`,
	Args: cobra.ExactArgs(1),
	RunE: runYara,
}

var (
	flagYaraRules string
	flagYaraRule  string
)

func init() {
	yaraCmd.Flags().StringVar(&flagYaraRules, "rules", "", "directory of JSON yara-lite rule files")
	yaraCmd.Flags().StringVar(&flagYaraRule, "rule", "", "single JSON rule file to run")
}

func runYara(_ *cobra.Command, args []string) error {
	c, err := fcase.Open(args[0], "")
	if err != nil {
		return err
	}
	defer c.Close()

	if err := schema.Apply(c); err != nil {
		return err
	}

	var rules []*yaralite.Rule

	if flagYaraRule != "" {
		r, err := yaralite.LoadFile(flagYaraRule)
		if err != nil {
			return err
		}
		rules = append(rules, r)
	} else {
		dir := flagYaraRules
		if dir == "" {
			dir = findYaraDir()
		}
		if dir == "" {
			return fmt.Errorf("no yara-lite rules directory found; use --rules to specify one")
		}
		loaded, errs := yaralite.LoadDir(dir)
		for _, e := range errs {
			fmt.Fprintf(os.Stderr, "  warn: %v\n", e)
		}
		if len(loaded) == 0 {
			return fmt.Errorf("no valid yara-lite rules found in %s", dir)
		}
		rules = loaded
		fmt.Printf("Loaded %d yara-lite rules from %s\n", len(rules), dir)
	}

	results, err := yaralite.ScanAll(c.DB(), rules)
	if err != nil {
		return err
	}

	ruleHits := map[string]int64{}
	for _, r := range results {
		if r.Hits > 0 {
			ruleHits[r.Rule.Name] += r.Hits
		}
	}

	printed := false
	for name, n := range ruleHits {
		fmt.Printf("  %4d hit(s) — %s\n", n, name)
		printed = true
	}
	if !printed {
		fmt.Println("  No pattern matches found.")
	} else {
		fmt.Printf("\n  Results stored in ioc_indicators. Run 'forensiq report %s' to include in report.\n", args[0])
	}
	return nil
}

func findYaraDir() string {
	// Check next to the running binary first.
	if exe, err := os.Executable(); err == nil {
		if candidate := filepath.Join(filepath.Dir(exe), "rules", "yara"); isDir(candidate) {
			return candidate
		}
	}
	// Fall back to current working directory.
	for _, candidate := range []string{"./rules/yara", "rules/yara"} {
		if isDir(candidate) {
			return candidate
		}
	}
	return ""
}
