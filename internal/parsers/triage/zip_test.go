package triage_test

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"forensiq/internal/parsers"
	"forensiq/internal/parsers/triage"
)

// TestRoute verifies that Route maps known file paths to non-nil parsers
// and unknown paths to nil.
func TestRoute(t *testing.T) {
	cases := []struct {
		path    string
		wantNil bool
	}{
		{"Security.evtx", false},
		{"evtlogs/System.evtx", false},
		{"Microsoft-Windows-Sysmon%4Operational.evtx", false},
		{"Prefetch/NOTEPAD.EXE-ABC12345.pf", false},
		{"$MFT", false},
		{"mft", false},
		{"Amcache.hve", false},
		{"Registry/SYSTEM", false},
		{"SYSTEM", false},
		{"NTUSER.DAT", false},
		{"SOFTWARE", false},
		{"Recent/foo.lnk", false},
		{"unknown.bin", true},
		{"readme.txt", true},
	}

	for _, tc := range cases {
		p := triage.Route(tc.path)
		if tc.wantNil && p != nil {
			t.Errorf("Route(%q) = %T, want nil", tc.path, p)
		}
		if !tc.wantNil && p == nil {
			t.Errorf("Route(%q) = nil, want a parser", tc.path)
		}
	}
}

// TestChannelFromPathViaRoute checks that EVTX channel names are derived correctly.
func TestChannelFromPathViaRoute(t *testing.T) {
	cases := []struct {
		path   string
		wantCh string
	}{
		{"Security.evtx", "Security"},
		{"System.evtx", "System"},
		{"Microsoft-Windows-Sysmon%4Operational.evtx", "Operational"},
	}
	for _, tc := range cases {
		p := triage.Route(tc.path)
		if p == nil {
			t.Fatalf("Route(%q) returned nil", tc.path)
		}
		want := "EVTX/" + tc.wantCh
		if p.Name() != want {
			t.Errorf("Route(%q).Name() = %q, want %q", tc.path, p.Name(), want)
		}
	}
}

// TestParseZIPSkipsUnknown creates a minimal ZIP with one unknown file and one
// invalid prefetch file. ParseZIP must not return an error — parse failures are
// sent to the progress channel, not bubbled up.
func TestParseZIPSkipsUnknown(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	// Unknown file — should be silently skipped.
	w, err := zw.Create("random.bin")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write([]byte("garbage"))

	// Invalid prefetch — triggers a parse error sent to ch, not returned.
	w2, err := zw.Create("Prefetch/NOTEPAD.EXE-ABC12345.pf")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w2.Write([]byte("tooshort"))

	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	tmp := filepath.Join(t.TempDir(), "test.zip")
	if err := os.WriteFile(tmp, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	// Buffered channel so ParseZIP doesn't block on sends.
	ch := make(chan parsers.Progress, 32)

	// nil db is fine here: the prefetch parser fails before touching the db.
	if err := triage.ParseZIP(tmp, nil, ch); err != nil {
		t.Errorf("ParseZIP returned unexpected error: %v", err)
	}
}
