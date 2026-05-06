package cmd

import (
	"github.com/spf13/cobra"
	"forensiq/internal/fcase"
	"forensiq/internal/repl"
	"forensiq/internal/schema"
)

var replCmd = &cobra.Command{
	Use:   "repl [flags] <file.fcase>",
	Short: "Open existing case in interactive REPL",
	Args:  cobra.ExactArgs(1),
	RunE:  runRepl,
}

func runRepl(cmd *cobra.Command, args []string) error {
	c, err := fcase.Open(args[0], "")
	if err != nil {
		return err
	}
	if err := schema.Apply(c); err != nil {
		return err
	}
	return repl.Run(c)
}
