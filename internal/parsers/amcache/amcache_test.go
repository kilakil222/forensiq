package amcache_test

import (
	"bytes"
	"path/filepath"
	"testing"

	"forensiq/internal/fcase"
	"forensiq/internal/parsers"
	"forensiq/internal/parsers/amcache"
	"forensiq/internal/schema"
)

func TestName(t *testing.T) {
	p := amcache.New()
	if p.Name() != "Amcache" {
		t.Fatalf("Name() = %q, want %q", p.Name(), "Amcache")
	}
}

func TestParseEmptyReader(t *testing.T) {
	c, err := fcase.Open(filepath.Join(t.TempDir(), "t.fcase"), "t")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := schema.Apply(c); err != nil {
		t.Fatal(err)
	}

	p := amcache.New()
	ch := make(chan parsers.Progress, 10)
	err = p.Parse(bytes.NewReader(nil), c.DB(), ch)
	if err == nil {
		t.Fatal("expected error for empty reader, got nil")
	}
}

func TestParseInvalidData(t *testing.T) {
	c, err := fcase.Open(filepath.Join(t.TempDir(), "t.fcase"), "t")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := schema.Apply(c); err != nil {
		t.Fatal(err)
	}

	p := amcache.New()
	ch := make(chan parsers.Progress, 10)
	// Random garbage — not a valid REGF hive.
	garbage := bytes.Repeat([]byte{0xAA, 0xBB, 0xCC, 0xDD}, 2048)
	err = p.Parse(bytes.NewReader(garbage), c.DB(), ch)
	if err == nil {
		t.Fatal("expected error for invalid hive data, got nil")
	}
}
