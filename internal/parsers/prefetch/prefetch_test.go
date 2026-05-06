package prefetch_test

import (
	"bytes"
	"encoding/binary"
	"path/filepath"
	"testing"

	"forensiq/internal/fcase"
	"forensiq/internal/parsers"
	"forensiq/internal/parsers/prefetch"
	"forensiq/internal/schema"
)

func TestParserName(t *testing.T) {
	p := prefetch.New()
	if p.Name() != "Prefetch" {
		t.Fatalf("got %q", p.Name())
	}
}

// buildMinimalPF builds a minimal Windows 8 .pf buffer (version 26).
// Must be at least 156 bytes so run_count offset (152-155) is readable.
func buildMinimalPF() []byte {
	buf := make([]byte, 256) // zero-filled, big enough for all offsets
	binary.LittleEndian.PutUint32(buf[0:4], 26) // version
	copy(buf[4:8], "SCCA")                       // signature
	// Filename at offset 16: "NOTEPAD.EXE" as UTF-16LE
	name := "NOTEPAD.EXE"
	for i, c := range name {
		binary.LittleEndian.PutUint16(buf[16+i*2:], uint16(c))
	}
	// run_count at offset 152 (Win8 format)
	binary.LittleEndian.PutUint32(buf[152:156], 3)
	// last_run FILETIME at offset 100 (Win7/8 format) — zero = no time
	return buf
}

func TestParseMinimal(t *testing.T) {
	c, err := fcase.Open(filepath.Join(t.TempDir(), "t.fcase"), "t")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := schema.Apply(c); err != nil {
		t.Fatal(err)
	}

	p := prefetch.New()
	ch := make(chan parsers.Progress, 10)
	err = p.Parse(bytes.NewReader(buildMinimalPF()), c.DB(), ch)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify row was inserted
	rows, err := c.Query("SELECT filename, run_count FROM prefetch")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	if !rows.Next() {
		t.Fatal("expected one row in prefetch table")
	}
	var filename string
	var runCount int
	if err := rows.Scan(&filename, &runCount); err != nil {
		t.Fatal(err)
	}
	if filename != "NOTEPAD.EXE" {
		t.Errorf("filename: got %q, want NOTEPAD.EXE", filename)
	}
	if runCount != 3 {
		t.Errorf("run_count: got %d, want 3", runCount)
	}
}
