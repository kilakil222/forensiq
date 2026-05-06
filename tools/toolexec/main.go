// toolexec wraps the Go linker to wait out AV's scan of the output .exe.
//
// AV blocks READ access from untrusted processes (like this wrapper)
// while scanning a new PE — so os.Open never succeeds here. Instead we probe
// readability via cmd.exe (a trusted system binary), which AV allows after the
// scan completes. Once cmd.exe can read the file we know the AV cache is warm
// and go build (also trusted) will succeed.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		os.Exit(1)
	}

	tool := args[0]
	toolArgs := make([]string, len(args)-1)
	copy(toolArgs, args[1:])

	base := strings.ToLower(filepath.Base(tool))
	isGoLink := base == "link.exe" || base == "link"

	if !isGoLink {
		runTool(tool, toolArgs)
		return
	}

	outPath := ""
	for i, a := range toolArgs {
		if a == "-o" && i+1 < len(toolArgs) {
			outPath = expandWork(toolArgs[i+1])
			break
		}
	}

	runTool(tool, toolArgs)

	if outPath == "" || !strings.HasSuffix(strings.ToLower(outPath), ".exe") {
		return
	}

	fmt.Fprintf(os.Stderr, "[toolexec] waiting for AV to allow read of %q\n", outPath)
	deadline := time.Now().Add(120 * time.Second)
	consecutive := 0
	for time.Now().Before(deadline) {
		if cmdCanRead(outPath) {
			consecutive++
			if consecutive >= 2 {
				break
			}
		} else {
			consecutive = 0
		}
		time.Sleep(300 * time.Millisecond)
	}
	time.Sleep(500 * time.Millisecond)
	fmt.Fprintf(os.Stderr, "[toolexec] AV cleared (consecutive=%d), handing back\n", consecutive)
}

// cmdCanRead returns true if cmd.exe can successfully read the file.
// cmd.exe is a trusted system binary that AV allows through after scan completes.
func cmdCanRead(path string) bool {
	c := exec.Command("cmd", "/c", fmt.Sprintf(`type "%s" >NUL 2>&1`, path))
	return c.Run() == nil
}

func runTool(tool string, args []string) {
	cmd := exec.Command(tool, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		os.Exit(1)
	}
}

func expandWork(s string) string {
	if w := os.Getenv("WORK"); w != "" {
		return strings.ReplaceAll(s, "$WORK", w)
	}
	return s
}
