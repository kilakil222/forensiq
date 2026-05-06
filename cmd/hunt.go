package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"forensiq/internal/fcase"
	"forensiq/internal/schema"
	"forensiq/internal/sigma"
)

var huntCmd = &cobra.Command{
	Use:   "hunt <file.fcase>",
	Short: "Run SIGMA detection rules against a case file",
	Long: `Hunt for threats using SIGMA-compatible JSON rules.

  forensiq hunt case.fcase                         # use built-in rules
  forensiq hunt case.fcase --rules ./my-rules/     # custom rule directory
  forensiq hunt case.fcase --rule rule.json        # single rule file

Rules are JSON-format SIGMA. To convert community YAML rules:
  python3 -c "import yaml,json,sys; json.dump(yaml.safe_load(sys.stdin),sys.stdout,indent=2)" < rule.yml > rule.json`,
	Args: cobra.ExactArgs(1),
	RunE: runHunt,
}

var (
	flagHuntRules  string
	flagHuntRule   string
	flagHuntVerbose bool
)

func init() {
	huntCmd.Flags().StringVar(&flagHuntRules, "rules", "", "directory of JSON rule files (default: rules/sigma next to binary)")
	huntCmd.Flags().StringVar(&flagHuntRule, "rule", "", "single JSON rule file to run")
	huntCmd.Flags().BoolVar(&flagHuntVerbose, "verbose", false, "show SQL for each rule")
}

func runHunt(_ *cobra.Command, args []string) error {
	c, err := fcase.Open(args[0], "")
	if err != nil {
		return err
	}
	defer c.Close()

	if err := schema.Apply(c); err != nil {
		return err
	}

	var rules []*sigma.Rule

	if flagHuntRule != "" {
		r, err := sigma.LoadFile(flagHuntRule)
		if err != nil {
			return err
		}
		rules = append(rules, r)
	} else {
		dir := flagHuntRules
		if dir == "" {
			dir = findRulesDir()
		}
		if dir == "" {
			return fmt.Errorf("no rules directory found; use --rules to specify one\n  Hint: built-in rules are in rules/sigma/ of the source tree")
		}
		loaded, errs := sigma.LoadDir(dir)
		for _, e := range errs {
			fmt.Fprintf(os.Stderr, "  warn: %v\n", e)
		}
		if len(loaded) == 0 {
			return fmt.Errorf("no valid rules found in %s", dir)
		}
		rules = loaded
		fmt.Printf("Loaded %d rules from %s\n", len(rules), dir)
	}

	results, err := sigma.RunAll(c.DB(), rules)
	if err != nil {
		return err
	}

	printed := false
	for _, r := range results {
		if r.Err != nil {
			if flagHuntVerbose {
				fmt.Printf("  [SKIP]  %s — %v\n", r.Rule.Title, r.Err)
			}
			continue
		}
		if r.Hits > 0 {
			fmt.Printf("  [%s]  %3d hit(s) — %s\n", r.Rule.Severity(), r.Hits, r.Rule.Title)
			if flagHuntVerbose {
				fmt.Printf("         SQL: %s\n\n", r.InsertSQL)
			}
			printed = true
		}
	}
	if !printed {
		fmt.Println("  No rule matches found.")
	} else {
		fmt.Printf("\n  Results stored in ioc_indicators. Run 'forensiq report %s' to include in report.\n", args[0])
	}
	return nil
}

// findRulesDir searches for the rules/sigma directory in common locations.
func findRulesDir() string {
	// 1. Next to the running binary
	if exe, err := os.Executable(); err == nil {
		candidate := filepath.Join(filepath.Dir(exe), "rules", "sigma")
		if isDir(candidate) {
			return candidate
		}
	}
	// 2. Current working directory
	if wd, err := os.Getwd(); err == nil {
		candidate := filepath.Join(wd, "rules", "sigma")
		if isDir(candidate) {
			return candidate
		}
	}
	return ""
}

func isDir(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.IsDir()
}
