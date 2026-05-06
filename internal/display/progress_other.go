//go:build !windows

package display

// EnableANSI is a no-op on non-Windows — ANSI is native on Unix terminals.
func EnableANSI() {}

// RestoreANSI is a no-op on non-Windows.
func RestoreANSI() {}
