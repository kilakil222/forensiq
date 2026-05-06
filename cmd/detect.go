package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"forensiq/internal/detect"
	"forensiq/internal/fcase"
	"forensiq/internal/schema"
)

var detectCmd = &cobra.Command{
	Use:   "detect <file.fcase>",
	Short: "Run built-in threat detectors against a case file",
	Args:  cobra.ExactArgs(1),
	RunE:  runDetect,
}

func runDetect(_ *cobra.Command, args []string) error {
	c, err := fcase.Open(args[0], "")
	if err != nil {
		return err
	}
	defer c.Close()

	if err := schema.Apply(c); err != nil {
		return err
	}

	fmt.Println("Running built-in detectors...")
	results, err := detect.RunAll(c.DB())
	if err != nil {
		return err
	}

	if len(results) == 0 {
		fmt.Println("  No hits detected.")
		return nil
	}

	fmt.Printf("  %-8s  %-10s  %s\n", "HITS", "SEVERITY", "DETECTOR")
	fmt.Printf("  %-8s  %-10s  %s\n", "----", "--------", "--------")
	for _, r := range results {
		fmt.Printf("  %-8d  %-10s  %s\n", r.Hits, r.Severity, r.Name)
	}
	fmt.Printf("\n  Results stored in ioc_indicators (source LIKE 'detect:%%')\n")
	fmt.Printf("  Run: forensiq report %s  to include them in the HTML report\n", args[0])
	return nil
}
