package mft

import "testing"

func TestName(t *testing.T) {
	p := New()
	if got := p.Name(); got != "$MFT" {
		t.Errorf("Name() = %q, want %q", got, "$MFT")
	}
}
