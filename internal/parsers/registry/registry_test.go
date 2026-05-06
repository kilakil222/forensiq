package registry

import "testing"

func TestName(t *testing.T) {
	p := New("SOFTWARE")
	if got := p.Name(); got != "Registry/SOFTWARE" {
		t.Errorf("Name() = %q, want %q", got, "Registry/SOFTWARE")
	}

	p2 := New("SYSTEM")
	if got := p2.Name(); got != "Registry/SYSTEM" {
		t.Errorf("Name() = %q, want %q", got, "Registry/SYSTEM")
	}
}
