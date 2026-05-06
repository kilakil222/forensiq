//go:build windows

package display

import "github.com/muesli/termenv"

var savedConsoleMode uint32

// EnableANSI enables Virtual Terminal Processing on Windows (ANSI escape support).
func EnableANSI() {
	mode, err := termenv.EnableWindowsANSIConsole()
	if err == nil {
		savedConsoleMode = mode
	}
}

// RestoreANSI restores the original Windows console mode.
func RestoreANSI() {
	if savedConsoleMode != 0 {
		termenv.RestoreWindowsConsole(savedConsoleMode)
	}
}
