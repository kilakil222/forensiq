package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"forensiq/internal/detect"
	"forensiq/internal/ioc"
	"forensiq/internal/orchestrator"
	"forensiq/internal/repl"
	"forensiq/internal/report"
)

var analyzeCmd = &cobra.Command{
	Use:   "analyze",
	Short: "Extract artifacts from triage ZIP and/or RAM dump",
	RunE:  runAnalyze,
}

var (
	flagTriage  string
	flagRAM     string
	flagDisk    string
	flagCase    string
	flagName    string
	flagNoREPL  bool
	flagReport  string
)

func init() {
	analyzeCmd.Flags().StringVar(&flagTriage, "triage", "", "path to triage ZIP")
	analyzeCmd.Flags().StringVar(&flagRAM, "ram", "", "path to memory dump")
	analyzeCmd.Flags().StringVar(&flagDisk, "disk", "", "path to disk image (E01, VMDK, or raw)")
	analyzeCmd.Flags().StringVar(&flagCase, "case", "", "output .fcase path")
	analyzeCmd.Flags().StringVar(&flagName, "name", "", "case name")
	analyzeCmd.Flags().BoolVar(&flagNoREPL, "no-repl", false, "batch mode, exit after analysis")
	analyzeCmd.Flags().StringVar(&flagReport, "report", "", "generate HTML report to this path after analysis")
}

func runAnalyze(cmd *cobra.Command, args []string) error {
	if flagTriage == "" && flagRAM == "" && flagDisk == "" {
		return fmt.Errorf("at least one of --triage, --ram or --disk is required")
	}

	casePath := flagCase
	if casePath == "" {
		name := flagName
		if name == "" {
			name = "case"
		}
		casePath = filepath.Join(".", sanitize(name)+".fcase")
	}

	opts := orchestrator.Options{
		TriagePath: flagTriage,
		RAMPath:    flagRAM,
		DiskPath:   flagDisk,
		CasePath:   casePath,
		CaseName:   flagName,
	}

	c, _, err := orchestrator.Run(opts)
	if err != nil {
		return err
	}

	fmt.Println("[Phase 1.5/3] Extracting IOCs from artifacts...")
	ioc.ExtractAll(c.DB())

	fmt.Println("[Phase 2/3] Running threat detectors...")
	if results, err := detect.RunAll(c.DB()); err == nil && len(results) > 0 {
		for _, r := range results {
			fmt.Printf("  [%s] %d hit(s) — %s\n", r.Severity, r.Hits, r.Name)
		}
	}

	if flagReport != "" {
		f, err := os.Create(flagReport)
		if err != nil {
			fmt.Fprintf(os.Stderr, "report: %v\n", err)
		} else {
			if err := report.Generate(c.DB(), f); err != nil {
				fmt.Fprintf(os.Stderr, "report: %v\n", err)
			} else {
				fmt.Printf("[Phase 3/3] Report → %s\n", flagReport)
			}
			f.Close()
		}
	}

	if flagNoREPL {
		c.Close()
		return nil
	}

	return repl.Run(c)
}

func sanitize(s string) string {
	return strings.NewReplacer(" ", "-", "/", "-", "\\", "-").Replace(s)
}
