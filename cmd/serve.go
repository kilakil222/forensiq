package cmd

import (
	"fmt"
	"os"

	"forensiq/internal/server"

	"github.com/spf13/cobra"
)

var servePort int
var serveRAM string

var serveCmd = &cobra.Command{
	Use:   "serve <case.fcase>",
	Short: "Start interactive web UI for a case",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		path := args[0]
		if _, err := os.Stat(path); err != nil {
			return fmt.Errorf("case file not found: %s", path)
		}
		return server.Start(path, serveRAM, servePort)
	},
}

func init() {
	serveCmd.Flags().IntVarP(&servePort, "port", "p", 8080, "HTTP listen port")
	serveCmd.Flags().StringVar(&serveRAM, "ram", "", "path to RAM dump — runs Volatility3 and adds memory artifacts to the case")
}
