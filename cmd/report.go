package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"forensiq/internal/fcase"
	"forensiq/internal/report"
	"forensiq/internal/schema"
)

var reportCmd = &cobra.Command{
	Use:   "report <file.fcase>",
	Short: "Generate HTML report from case file",
	Args:  cobra.ExactArgs(1),
	RunE:  runReport,
}

func runReport(cmd *cobra.Command, args []string) error {
	casePath := args[0]
	outPath := strings.TrimSuffix(casePath, ".fcase") + ".html"

	c, err := fcase.Open(casePath, "")
	if err != nil {
		return err
	}
	defer c.Close()

	if err := schema.Apply(c); err != nil {
		return err
	}

	f, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer f.Close()

	if err := report.Generate(c.DB(), f); err != nil {
		return err
	}

	fmt.Printf("Report written: %s\n", outPath)
	return nil
}
