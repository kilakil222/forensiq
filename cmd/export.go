package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"forensiq/internal/export"
	"forensiq/internal/fcase"
	"forensiq/internal/schema"
)

var exportCmd = &cobra.Command{
	Use:   "export <file.fcase> [table]",
	Short: "Export artifacts to CSV/TSV/JSONL (EmEditor-friendly)",
	Long: `Export case artifacts to flat files.

  forensiq export case.fcase                    # timeline → stdout (CSV)
  forensiq export case.fcase mft                # mft table → stdout
  forensiq export case.fcase all --dir ./out    # all tables → directory

Available tables: mft evtx_events auth_events defender_events prefetch amcache
  shimcache lnk_files persistence services scheduled_tasks mem_pslist
  mem_cmdline mem_netscan mem_malfind ps_scriptblock browser_history
  ioc_indicators attack_techniques source_files timeline`,
	Args: cobra.RangeArgs(1, 2),
	RunE: runExport,
}

var (
	flagExportFormat string
	flagExportFrom   string
	flagExportTo     string
	flagExportOut    string
	flagExportDir    string
	flagExportLimit  int
)

func init() {
	exportCmd.Flags().StringVar(&flagExportFormat, "format", "csv", "output format: csv | tsv | jsonl")
	exportCmd.Flags().StringVar(&flagExportFrom, "from", "", "start timestamp (ISO 8601, e.g. 2024-01-01)")
	exportCmd.Flags().StringVar(&flagExportTo, "to", "", "end timestamp (ISO 8601)")
	exportCmd.Flags().StringVar(&flagExportOut, "out", "", "output file (default: stdout)")
	exportCmd.Flags().StringVar(&flagExportDir, "dir", ".", "output directory for 'all' mode")
	exportCmd.Flags().IntVar(&flagExportLimit, "limit", 0, "row limit per table (0 = unlimited)")
}

func runExport(cmd *cobra.Command, args []string) error {
	casePath := args[0]
	table := "timeline"
	if len(args) == 2 {
		table = strings.ToLower(args[1])
	}

	c, err := fcase.Open(casePath, "")
	if err != nil {
		return err
	}
	defer c.Close()

	if err := schema.Apply(c); err != nil {
		return err
	}

	opts := export.Options{
		Format: export.Format(flagExportFormat),
		From:   flagExportFrom,
		To:     flagExportTo,
		Limit:  flagExportLimit,
	}

	if table == "all" {
		fmt.Println("Exporting all tables...")
		return export.ExportAll(c.DB(), flagExportDir, opts)
	}

	// Single table → file or stdout
	w := os.Stdout
	if flagExportOut != "" {
		f, err := os.Create(flagExportOut)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}

	n, err := export.Export(c.DB(), table, opts, w)
	if err != nil {
		return err
	}
	if flagExportOut != "" {
		fmt.Fprintf(os.Stderr, "Exported %d rows → %s\n", n, flagExportOut)
	}
	return nil
}
