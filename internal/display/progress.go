package display

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/mattn/go-isatty"
)

// ── Spinner ───────────────────────────────────────────────────────────────────

var spinFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// ── Styles ────────────────────────────────────────────────────────────────────

var (
	pStyleOK      = lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Bold(true)
	pStyleErr     = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
	pStyleSpin    = lipgloss.NewStyle().Foreground(lipgloss.Color("99")).Bold(true)
	pStyleName    = lipgloss.NewStyle().Foreground(lipgloss.Color("255"))
	pStyleCount   = lipgloss.NewStyle().Foreground(lipgloss.Color("39")).Bold(true)
	pStyleElapsed = lipgloss.NewStyle().Faint(true)
	pStyleGroup   = lipgloss.NewStyle().Foreground(lipgloss.Color("99")).Faint(true)
	pStyleBar     = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	pStyleBarBg   = lipgloss.NewStyle().Faint(true)
	pStyleTotal   = lipgloss.NewStyle().Foreground(lipgloss.Color("255")).Bold(true)
	pStyleDim     = lipgloss.NewStyle().Faint(true)
)

// ── State ─────────────────────────────────────────────────────────────────────

const (
	stRunning = iota
	stOK
	stErr
)

type parserRow struct {
	name    string
	group   string
	count   int64
	elapsed time.Duration
	status  int
	err     error
	started time.Time
}

// ProgressDisplay renders a live animated list of parser rows to a terminal.
// Falls back to static line-by-line output when stdout is not a TTY.
type ProgressDisplay struct {
	mu      sync.Mutex
	w       io.Writer
	rows    []*parserRow
	index   map[string]*parserRow
	frame   int
	lines   int // lines written in last render (for cursor-up)
	started time.Time
	isTTY   bool
	stopCh  chan struct{}
}

// NewProgress creates a new display writing to w (typically os.Stdout).
func NewProgress(w io.Writer) *ProgressDisplay {
	tty := false
	if f, ok := w.(*os.File); ok {
		tty = isatty.IsTerminal(f.Fd()) || isatty.IsCygwinTerminal(f.Fd())
	}
	return &ProgressDisplay{
		w:       w,
		index:   make(map[string]*parserRow),
		started: time.Now(),
		isTTY:   tty,
		stopCh:  make(chan struct{}),
	}
}

// Update records a progress event. Unknown parsers are auto-registered.
func (pd *ProgressDisplay) Update(name string, count int64, elapsed time.Duration, done bool, err error) {
	pd.mu.Lock()
	row, ok := pd.index[name]
	if !ok {
		row = &parserRow{name: name, group: classifyGroup(name), started: time.Now()}
		pd.rows = append(pd.rows, row)
		pd.index[name] = row
	}
	if count > row.count {
		row.count = count
	}
	if elapsed > 0 {
		row.elapsed = elapsed
	}
	if err != nil {
		row.status = stErr
		row.err = err
	} else if done {
		row.status = stOK
		if row.elapsed == 0 {
			row.elapsed = time.Since(row.started)
		}
	}
	pd.mu.Unlock()

	// In static mode, print immediately on terminal events
	if !pd.isTTY {
		if done || err != nil {
			pd.staticLine(row)
		}
	}
}

// Start begins the animation loop (TTY mode) or does nothing (static mode).
func (pd *ProgressDisplay) Start() {
	if !pd.isTTY {
		return
	}
	EnableANSI()
	fmt.Fprint(pd.w, ansi.HideCursor)
	go pd.loop()
}

// Stop ends the animation, does a final render, and restores the cursor.
func (pd *ProgressDisplay) Stop() {
	if !pd.isTTY {
		return
	}
	close(pd.stopCh)
	pd.render(true) // final render: all rows in terminal state
	fmt.Fprint(pd.w, ansi.ShowCursor)
	fmt.Fprintln(pd.w)
}

// TotalArtifacts sums OK row counts.
func (pd *ProgressDisplay) TotalArtifacts() int64 {
	pd.mu.Lock()
	defer pd.mu.Unlock()
	var total int64
	for _, r := range pd.rows {
		if r.status == stOK {
			total += r.count
		}
	}
	return total
}

// ── Internal ──────────────────────────────────────────────────────────────────

func (pd *ProgressDisplay) loop() {
	ticker := time.NewTicker(80 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-pd.stopCh:
			return
		case <-ticker.C:
			pd.mu.Lock()
			pd.frame++
			pd.mu.Unlock()
			pd.render(false)
		}
	}
}

func (pd *ProgressDisplay) render(final bool) {
	pd.mu.Lock()
	// Snapshot to local slice to avoid long lock hold during string building
	rows := make([]*parserRow, len(pd.rows))
	copy(rows, pd.rows)
	frame := pd.frame
	lines := pd.lines
	elapsed := time.Since(pd.started)
	pd.mu.Unlock()

	var buf strings.Builder

	// Move cursor up to overwrite previous frame
	if lines > 0 {
		buf.WriteString(ansi.CursorUp(lines))
	}

	newLines := 0
	prevGroup := ""

	for _, r := range rows {
		// Group separator line
		if r.group != prevGroup {
			prevGroup = r.group
			buf.WriteString(ansi.EraseEntireLine)
			buf.WriteString("\r")
			label := "  " + pStyleGroup.Render("── "+r.group+" ──")
			buf.WriteString(label)
			buf.WriteByte('\n')
			newLines++
		}

		buf.WriteString(ansi.EraseEntireLine)
		buf.WriteString("\r")

		// Status icon
		switch r.status {
		case stOK:
			buf.WriteString("  " + pStyleOK.Render("✓") + "  ")
		case stErr:
			buf.WriteString("  " + pStyleErr.Render("✗") + "  ")
		default:
			sp := spinFrames[frame%len(spinFrames)]
			buf.WriteString("  " + pStyleSpin.Render(sp) + "  ")
		}

		// Name — fixed 22 chars
		name := r.name
		if len(name) > 22 {
			name = name[:21] + "…"
		}
		buf.WriteString(pStyleName.Render(fmt.Sprintf("%-22s", name)))

		// Count
		cnt := ""
		if r.count > 0 || r.status == stOK {
			cnt = commaNum(r.count)
		}
		buf.WriteString(pStyleCount.Render(fmt.Sprintf("%10s", cnt)))

		// Elapsed
		dur := r.elapsed
		if r.status == stRunning {
			dur = time.Since(r.started)
		}
		buf.WriteString("  " + pStyleElapsed.Render(fmtDur(dur)))

		// Error suffix
		if r.status == stErr && r.err != nil {
			msg := r.err.Error()
			if len(msg) > 35 {
				msg = msg[:34] + "…"
			}
			buf.WriteString("  " + pStyleErr.Render(msg))
		}

		buf.WriteByte('\n')
		newLines++
	}

	// Progress bar
	buf.WriteString(ansi.EraseEntireLine)
	buf.WriteString("\r")
	done, total := countDone(rows)
	var totalArt int64
	for _, r := range rows {
		if r.status == stOK {
			totalArt += r.count
		}
	}
	bar := renderBar(done, total, 28)
	buf.WriteString("  " + bar)
	buf.WriteString(pStyleDim.Render(fmt.Sprintf("  %d/%d parsers", done, total)))
	if totalArt > 0 {
		buf.WriteString("  " + pStyleTotal.Render(commaNum(totalArt)+" artifacts"))
	}
	buf.WriteString("  " + pStyleElapsed.Render(fmtDur(elapsed)))
	buf.WriteByte('\n')
	newLines++

	pd.mu.Lock()
	pd.lines = newLines
	pd.mu.Unlock()

	fmt.Fprint(pd.w, buf.String())
}

func (pd *ProgressDisplay) staticLine(r *parserRow) {
	pd.mu.Lock()
	defer pd.mu.Unlock()
	switch r.status {
	case stOK:
		ParserOK(r.name, r.count, r.elapsed)
	case stErr:
		ParserErr(r.name, r.err)
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func classifyGroup(name string) string {
	switch {
	case strings.HasPrefix(name, "mem:") || strings.HasPrefix(name, "vol:"):
		return "Memory"
	case name == "MFT" || name == "USN Journal" || name == "Recycle Bin" ||
		name == "Prefetch" || name == "Shimcache" || name == "Amcache" ||
		name == "Registry" || name == "Services" || name == "Scheduled Tasks" ||
		name == "Shellbags" || name == "JumpLists" || name == "LNK Files" ||
		name == "UserAssist" || name == "EVTX" || name == "Sysmon" ||
		name == "Browser History" || name == "Browser Downloads":
		return "Disk / Triage"
	default:
		return "Disk / Triage"
	}
}

func countDone(rows []*parserRow) (done, total int) {
	total = len(rows)
	for _, r := range rows {
		if r.status != stRunning {
			done++
		}
	}
	return
}

func renderBar(done, total, width int) string {
	if total == 0 {
		return pStyleBarBg.Render(strings.Repeat("░", width))
	}
	filled := 0
	if total > 0 {
		filled = (done * width) / total
	}
	return pStyleBar.Render(strings.Repeat("█", filled)) +
		pStyleBarBg.Render(strings.Repeat("░", width-filled))
}

func commaNum(n int64) string {
	s := fmt.Sprintf("%d", n)
	if len(s) <= 3 {
		return s
	}
	out := ""
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			out += ","
		}
		out += string(c)
	}
	return out
}

func fmtDur(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	return fmt.Sprintf("%dm%ds", int(d.Minutes()), int(d.Seconds())%60)
}
