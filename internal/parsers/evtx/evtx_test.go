package evtx_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"forensiq/internal/fcase"
	"forensiq/internal/parsers"
	evtxparser "forensiq/internal/parsers/evtx"
	"forensiq/internal/schema"
)

func setupDB(t *testing.T) *fcase.Case {
	t.Helper()
	c, err := fcase.Open(filepath.Join(t.TempDir(), "t.fcase"), "t")
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.Apply(c); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestParserName(t *testing.T) {
	p := evtxparser.New("Security")
	if p.Name() != "EVTX/Security" {
		t.Fatalf("got %q", p.Name())
	}
}

func TestParseEmpty(t *testing.T) {
	c := setupDB(t)
	defer c.Close()
	p := evtxparser.New("Security")
	ch := make(chan parsers.Progress, 100)
	// Empty reader — should return error or 0 rows, not panic
	err := p.Parse(bytes.NewReader([]byte{}), c.DB(), ch)
	if err == nil {
		t.Log("no error on empty input (acceptable)")
	}
}

func TestParseRealFile(t *testing.T) {
	// Look for a testdata file relative to the module root.
	// From internal/parsers/evtx/ we go up two levels to reach the module root,
	// then into tests/testdata/.
	testFile := filepath.Join("..", "..", "..", "tests", "testdata", "security.evtx")

	data, err := os.ReadFile(testFile)
	if err != nil {
		t.Skipf("test evtx not available: %v", err)
	}

	c := setupDB(t)
	defer c.Close()

	p := evtxparser.New("Security")
	ch := make(chan parsers.Progress, 1000)

	err = p.Parse(bytes.NewReader(data), c.DB(), ch)
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	// Drain progress channel
	var lastProgress parsers.Progress
	for prog := range ch {
		lastProgress = prog
		if prog.Done {
			break
		}
	}

	t.Logf("Parsed %d events in %v", lastProgress.Count, lastProgress.Elapsed)

	// Verify rows were inserted
	var count int64
	row := c.DB().QueryRow("SELECT COUNT(*) FROM evtx_events")
	if err := row.Scan(&count); err != nil {
		t.Fatalf("count query: %v", err)
	}
	if count == 0 {
		t.Error("expected at least one row in evtx_events")
	}
	t.Logf("evtx_events rows: %d", count)
}
