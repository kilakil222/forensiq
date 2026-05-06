package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"forensiq/internal/export"
	"forensiq/internal/fcase"
	"forensiq/internal/schema"
)

var timelineCmd = &cobra.Command{
	Use:   "timeline <file.fcase>",
	Short: "Extract forensic timeline to stdout or a file",
	Long: `Fast timeline extraction from an existing case file (no re-parsing).

  forensiq timeline case.fcase                               # all events → stdout CSV
  forensiq timeline case.fcase --out timeline.csv            # to file
  forensiq timeline case.fcase --from 2024-01-15T10:00 --to 2024-01-15T11:00
  forensiq timeline case.fcase --source EVTX,Auth            # filter sources
  forensiq timeline case.fcase --asc --limit 5000            # oldest-first, capped
  forensiq timeline case.fcase --format tsv --out tl.tsv     # TSV for EmEditor

Sources: MFT  EVTX  Prefetch  Auth  Defender  IOC  (comma-separated, default: all)`,
	Args: cobra.ExactArgs(1),
	RunE: runTimeline,
}

var (
	flagTLFrom   string
	flagTLTo     string
	flagTLOut    string
	flagTLFormat string
	flagTLSource string
	flagTLLimit  int
	flagTLAsc    bool
)

func init() {
	timelineCmd.Flags().StringVar(&flagTLFrom, "from", "", "start timestamp (e.g. 2024-01-15 or 2024-01-15T10:00:00)")
	timelineCmd.Flags().StringVar(&flagTLTo, "to", "", "end timestamp")
	timelineCmd.Flags().StringVar(&flagTLOut, "out", "", "output file (default: stdout)")
	timelineCmd.Flags().StringVar(&flagTLFormat, "format", "csv", "output format: csv | tsv | jsonl")
	timelineCmd.Flags().StringVar(&flagTLSource, "source", "", "filter sources: MFT,EVTX,Prefetch,Auth,Defender,IOC (default: all)")
	timelineCmd.Flags().IntVar(&flagTLLimit, "limit", 0, "maximum rows to output (0 = unlimited)")
	timelineCmd.Flags().BoolVar(&flagTLAsc, "asc", false, "chronological order (default: newest-first)")
}

func runTimeline(_ *cobra.Command, args []string) error {
	c, err := fcase.Open(args[0], "")
	if err != nil {
		return err
	}
	defer c.Close()

	if err := schema.Apply(c); err != nil {
		return err
	}

	opts := export.Options{
		Format: export.Format(flagTLFormat),
		From:   flagTLFrom,
		To:     flagTLTo,
		Source: flagTLSource,
		Limit:  flagTLLimit,
		Asc:    flagTLAsc,
	}

	w := os.Stdout
	if flagTLOut != "" {
		f, err := os.Create(flagTLOut)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}

	n, err := export.Export(c.DB(), "timeline", opts, w)
	if err != nil {
		return err
	}
	if flagTLOut != "" {
		fmt.Fprintf(os.Stderr, "Timeline: %d events → %s\n", n, flagTLOut)
	}
	return nil
}
