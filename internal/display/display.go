package display

import (
	"fmt"
	"time"

	"github.com/charmbracelet/lipgloss"
)

var (
	styleHeader  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("99"))
	styleOK      = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	styleErr     = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	styleRunning = lipgloss.NewStyle().Foreground(lipgloss.Color("226"))
	styleDim     = lipgloss.NewStyle().Faint(true)
	styleBold    = lipgloss.NewStyle().Bold(true)
)

func Header(caseName, version string) {
	fmt.Printf("\n%s  ·  Case: %s\n",
		styleHeader.Render("forensiq "+version),
		styleBold.Render(caseName),
	)
	fmt.Println(styleHeader.Render("──────────────────────────────────────────────────────"))
	fmt.Println()
}

func ParserOK(name string, count int64, elapsed time.Duration) {
	fmt.Printf("  %s  %-28s %10s   %s\n",
		styleOK.Render("✓"),
		name,
		fmt.Sprintf("%d entries", count),
		styleDim.Render(elapsed.Round(time.Millisecond).String()),
	)
}

func ParserErr(name string, err error) {
	fmt.Printf("  %s  %-28s %s\n",
		styleErr.Render("✗"),
		name,
		styleErr.Render(err.Error()),
	)
}

func ParserRunning(name string) {
	fmt.Printf("  %s  %-28s %s\n",
		styleRunning.Render("↻"),
		name,
		styleDim.Render("[parsing]"),
	)
}

func Summary(total int64, elapsed time.Duration, casePath string) {
	fmt.Println()
	fmt.Println(styleHeader.Render("──────────────────────────────────────────────────────"))
	fmt.Printf("  Total: %s artifacts  ·  %s\n",
		styleBold.Render(fmt.Sprintf("%d", total)),
		elapsed.Round(time.Millisecond).String(),
	)
	fmt.Printf("  Saved: %s\n\n", styleDim.Render(casePath))
}

func Banner() {
	fmt.Println()
	fmt.Println(styleHeader.Render("  ⚡ forensiq v0.4") + "  " + styleDim.Render("DFIR artifact analysis"))
	fmt.Println(styleDim.Render("  ──────────────────────────────────────────"))
	fmt.Println(styleDim.Render("  Type 'help' for commands, 'exit' to quit."))
	fmt.Println()
}

func REPLPrompt(caseName string) string {
	if caseName != "" {
		return styleHeader.Render("forensiq") + styleDim.Render("["+caseName+"]") + styleHeader.Render(">")
	}
	return styleHeader.Render("forensiq") + styleHeader.Render(">")
}

func Table(headers []string, rows [][]string) {
	colWidths := make([]int, len(headers))
	for i, h := range headers {
		colWidths[i] = len(h)
	}
	for _, row := range rows {
		for i, cell := range row {
			if i < len(colWidths) && len(cell) > colWidths[i] {
				colWidths[i] = len(cell)
			}
		}
	}

	line := "  "
	sep := "  "
	for i, h := range headers {
		line += fmt.Sprintf("%-*s  ", colWidths[i], h)
		sep += fmt.Sprintf("%s  ", repeatChar("─", colWidths[i]))
	}
	fmt.Println(styleBold.Render(line))
	fmt.Println(styleDim.Render(sep))
	for _, row := range rows {
		r := "  "
		for i, cell := range row {
			if i < len(colWidths) {
				r += fmt.Sprintf("%-*s  ", colWidths[i], cell)
			}
		}
		fmt.Println(r)
	}
	fmt.Println()
}

func repeatChar(c string, n int) string {
	s := ""
	for i := 0; i < n; i++ {
		s += c
	}
	return s
}

func Tip(msg string) {
	fmt.Printf("  %s %s\n\n", styleDim.Render("Tip:"), msg)
}

func Error(msg string) {
	fmt.Printf("  %s %s\n\n", styleErr.Render("ERROR:"), msg)
}
