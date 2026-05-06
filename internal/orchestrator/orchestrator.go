package orchestrator

import (
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"forensiq/internal/display"
	"forensiq/internal/fcase"
	"forensiq/internal/parsers"
	"forensiq/internal/parsers/disk"
	"forensiq/internal/parsers/memparse"
	"forensiq/internal/parsers/triage"
	"forensiq/internal/schema"
	"forensiq/internal/volatility"
)

type Options struct {
	TriagePath string
	RAMPath    string
	DiskPath   string
	CasePath   string
	CaseName   string
}

type RunResult struct {
	TotalArtifacts int64
	Elapsed        time.Duration
	Errors         []error
}

func Run(opts Options) (*fcase.Case, *RunResult, error) {
	os.Remove(opts.CasePath) // clean slate — re-runs must not accumulate rows
	c, err := fcase.Open(opts.CasePath, opts.CaseName)
	if err != nil {
		return nil, nil, fmt.Errorf("open case: %w", err)
	}
	if err := schema.Apply(c); err != nil {
		c.Close()
		return nil, nil, fmt.Errorf("apply schema: %w", err)
	}
	if err := c.SetMeta(opts.CaseName, "Windows", ""); err != nil {
		c.Close()
		return nil, nil, err
	}

	display.Header(opts.CaseName, "v0.1.0")
	fmt.Println()

	start := time.Now()
	ch := make(chan parsers.Progress, 256)
	var wg sync.WaitGroup
	result := &RunResult{}

	pd := display.NewProgress(os.Stdout)
	cleanup := display.InstallSignalHandler()
	defer cleanup()
	pd.Start()

	if opts.TriagePath != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := triage.ParseZIP(opts.TriagePath, c.DB(), ch); err != nil {
				ch <- parsers.Progress{Parser: "triage", Err: err, Done: true}
			}
		}()
	}

	if opts.DiskPath != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := disk.Analyze(opts.DiskPath, c.DB(), ch); err != nil {
				ch <- parsers.Progress{Parser: "disk", Err: err, Done: true}
			}
		}()
	}

	if opts.RAMPath != "" {
		ramPath := opts.RAMPath
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Try the native Go parser first; fall back to Volatility3 only if it fails.
			if err := memparse.Parse(ramPath, c.DB(), ch); err == nil {
				return
			} else {
				log.Printf("native memparse failed (%v), falling back to Volatility3", err)
			}
			vol := volatility.New(ramPath)
			if !vol.IsAvailable() {
				ch <- parsers.Progress{Parser: "Volatility3", Err: fmt.Errorf("not found in PATH"), Done: true}
				return
			}
			var subWg sync.WaitGroup
			for _, plugin := range vol.Plugins() {
				plugin := plugin
				subWg.Add(1)
				go func() {
					defer subWg.Done()
					vol.RunPlugin(plugin, c.DB(), ch)
				}()
			}
			subWg.Wait()
		}()
	}

	go func() {
		wg.Wait()
		close(ch)
	}()

	for p := range ch {
		pd.Update(p.Parser, p.Count, p.Elapsed, p.Done, p.Err)
		if p.Err != nil {
			result.Errors = append(result.Errors, p.Err)
		} else if p.Done {
			result.TotalArtifacts += p.Count
		}
	}

	pd.Stop()
	result.Elapsed = time.Since(start)
	display.Summary(result.TotalArtifacts, result.Elapsed, opts.CasePath)
	return c, result, nil
}
