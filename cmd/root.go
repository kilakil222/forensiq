package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"forensiq/internal/tui"
)

var rootCmd = &cobra.Command{
	Use:   "forensiq",
	Short: "Fast DFIR artifact analysis",
	Long:  "forensiq — disk image and RAM dump analysis with full artifact correlation.",
	Args:  cobra.NoArgs,
	RunE:  runTUI,
}

func runTUI(cmd *cobra.Command, args []string) error {
	return tui.Run()
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(analyzeCmd)
	rootCmd.AddCommand(replCmd)
	rootCmd.AddCommand(reportCmd)
	rootCmd.AddCommand(exportCmd)
	rootCmd.AddCommand(timelineCmd)
	rootCmd.AddCommand(detectCmd)
	rootCmd.AddCommand(huntCmd)
	rootCmd.AddCommand(yaraCmd)
	rootCmd.AddCommand(askCmd)
	rootCmd.AddCommand(serveCmd)
}
