package lnk

import (
	"bytes"
	"strings"
	"testing"

	"forensiq/internal/parsers"
)

func TestName(t *testing.T) {
	p := New("C:\\Users\\test\\Desktop\\file.lnk")
	if got := p.Name(); got != "LNK" {
		t.Errorf("Name() = %q, want %q", got, "LNK")
	}
}

func TestParseTooShort(t *testing.T) {
	p := New("test.lnk")
	ch := make(chan parsers.Progress, 1)
	err := p.Parse(bytes.NewReader([]byte{0x01, 0x02}), nil, ch)
	if err == nil {
		t.Fatal("expected error for short input, got nil")
	}
	if !strings.Contains(err.Error(), "too short") {
		t.Errorf("expected 'too short' error, got: %v", err)
	}
}

func TestParseBadCLSID(t *testing.T) {
	// 76 bytes of zeros — CLSID bytes at offset 4,5 will be 0x00,0x00 → invalid
	data := make([]byte, lnkHeaderSize)
	p := New("test.lnk")
	ch := make(chan parsers.Progress, 1)
	err := p.Parse(bytes.NewReader(data), nil, ch)
	if err == nil {
		t.Fatal("expected error for bad CLSID, got nil")
	}
	if !strings.Contains(err.Error(), "bad CLSID") {
		t.Errorf("expected 'bad CLSID' error, got: %v", err)
	}
}
