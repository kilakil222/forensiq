package display

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/charmbracelet/x/ansi"
)

// InstallSignalHandler ensures cursor is restored if the process is interrupted.
// Returns a cleanup function to call on normal exit.
func InstallSignalHandler() func() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-ch
		fmt.Fprint(os.Stdout, ansi.ShowCursor)
		fmt.Fprintln(os.Stdout)
		RestoreANSI()
		os.Exit(130)
	}()

	return func() {
		signal.Stop(ch)
		fmt.Fprint(os.Stdout, ansi.ShowCursor)
		RestoreANSI()
	}
}
