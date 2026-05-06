package volatility_test

import (
	"testing"

	"forensiq/internal/volatility"
)

func TestAvailable(t *testing.T) {
	v := volatility.New("/nonexistent/ram.dmp")
	t.Logf("Volatility3 available: %v", v.IsAvailable())
}

func TestPlugins(t *testing.T) {
	v := volatility.New("/nonexistent/ram.dmp")
	if len(v.Plugins()) == 0 {
		t.Fatal("expected at least one plugin")
	}
}
