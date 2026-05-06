package tui

import (
	"bufio"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/lipgloss"

	"forensiq/internal/detect"
	"forensiq/internal/display"
	"forensiq/internal/fcase"
	"forensiq/internal/ioc"
	"forensiq/internal/orchestrator"
	"forensiq/internal/repl"
	"forensiq/internal/schema"
	"forensiq/internal/server"
)

// ── ASCII art ─────────────────────────────────────────────────────────────────

var forensiqLogo = [6]string{
	`███████╗ ██████╗ ██████╗ ███████╗███╗   ██╗███████╗██╗ ██████╗ `,
	`██╔════╝██╔═══██╗██╔══██╗██╔════╝████╗  ██║██╔════╝██║██╔═══██╗`,
	`█████╗  ██║   ██║██████╔╝█████╗  ██╔██╗ ██║███████╗██║██║   ██║`,
	`██╔══╝  ██║   ██║██╔══██╗██╔══╝  ██║╚██╗██║╚════██║██║██║▄▄ ██║`,
	`██║     ╚██████╔╝██║  ██║███████╗██║ ╚████║███████║██║╚██████╔╝`,
	`╚═╝      ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝ ╚══▀▀═╝`,
}

var matrixRunes = []rune("0123456789ABCDEF∑∆Ω≡∞∂∇◆▲▼░▒▓│┤┬├┴┼")

// ── Palette ───────────────────────────────────────────────────────────────────

var (
	cPurple = lipgloss.Color("99")
	cCyan   = lipgloss.Color("39")
	cGreen  = lipgloss.Color("42")
	cRed    = lipgloss.Color("196")
	cYellow = lipgloss.Color("226")
	cDim    = lipgloss.Color("241")
	cWhite  = lipgloss.Color("255")

	sPrimary    = lipgloss.NewStyle().Bold(true).Foreground(cPurple)
	sAccent     = lipgloss.NewStyle().Foreground(cCyan)
	sGreen      = lipgloss.NewStyle().Foreground(cGreen).Bold(true)
	sRed        = lipgloss.NewStyle().Foreground(cRed).Bold(true)
	sYellow     = lipgloss.NewStyle().Foreground(cYellow).Bold(true)
	sDim        = lipgloss.NewStyle().Faint(true)
	sBold       = lipgloss.NewStyle().Bold(true).Foreground(cWhite)
	promptStyle = lipgloss.NewStyle().Foreground(cCyan).Bold(true)

	menuBox = lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(cPurple).
		Padding(0, 3).
		Width(66)

	sectionHdr = lipgloss.NewStyle().
		Bold(true).
		Foreground(cPurple).
		BorderStyle(lipgloss.NormalBorder()).
		BorderBottom(true).
		BorderForeground(cDim).
		Width(58)

	resultBox = lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(cGreen).
		Padding(0, 3).
		Width(62)

	alertBox = lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(cRed).
		Padding(0, 3).
		Width(62)

	serverBox = lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(cCyan).
		Padding(1, 4).
		Width(50)
)

// ── Input helpers ─────────────────────────────────────────────────────────────

var reader = bufio.NewReader(os.Stdin)

func ask(label string) string {
	fmt.Printf("  %s %s ", sDim.Render("›"), promptStyle.Render(label+":"))
	line, _ := reader.ReadString('\n')
	return strings.TrimSpace(strings.TrimRight(line, "\r\n"))
}

func askDefault(label, def string) string {
	fmt.Printf("  %s %s%s ", sDim.Render("›"), promptStyle.Render(label+":"), sDim.Render(" ["+def+"]"))
	line, _ := reader.ReadString('\n')
	s := strings.TrimSpace(strings.TrimRight(line, "\r\n"))
	if s == "" {
		return def
	}
	return s
}

// ── Intro animation ───────────────────────────────────────────────────────────

var introOnce sync.Once

// runIntro plays the animated startup sequence once per process.
func runIntro() {
	matrixScatter(380 * time.Millisecond)
	clear()
	bootSequence()
	time.Sleep(600 * time.Millisecond)
	clear()
}

// matrixScatter fills the screen with random glyphs for duration d.
func matrixScatter(d time.Duration) {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	fmt.Print("\033[?25l") // hide cursor
	start := time.Now()
	for time.Since(start) < d {
		row := rng.Intn(22) + 1
		col := rng.Intn(76) + 2
		ch := string(matrixRunes[rng.Intn(len(matrixRunes))])
		switch rng.Intn(4) {
		case 0:
			fmt.Printf("\033[%d;%dH%s", row, col, sPrimary.Render(ch))
		case 1:
			fmt.Printf("\033[%d;%dH%s", row, col, sAccent.Render(ch))
		default:
			fmt.Printf("\033[%d;%dH%s", row, col, sDim.Render(ch))
		}
		time.Sleep(10 * time.Millisecond)
	}
	fmt.Print("\033[?25h") // show cursor
}

// bootSequence displays the ASCII art logo and a module-check animation.
func bootSequence() {
	fmt.Println()
	fmt.Println()

	// Logo appears line by line with a dim→bright flicker effect
	for _, l := range forensiqLogo {
		fmt.Printf("  %s\n", sDim.Render(l))
		time.Sleep(18 * time.Millisecond)
		fmt.Print("\033[1A\r\033[2K") // cursor up + erase
		fmt.Printf("  %s\n", sPrimary.Render(l))
		time.Sleep(30 * time.Millisecond)
	}

	fmt.Println()
	fmt.Println("  " + sDim.Render("v0.7  ·  Digital Forensics & Incident Response Platform"))
	fmt.Println("  " + sDim.Render("·· "+strings.Repeat("─", 60)+" ··"))
	fmt.Println()

	modules := []string{
		"Artifact extraction engine",
		"Threat detection rules",
		"IOC correlation layer",
		"Platform ready",
	}
	for i, mod := range modules {
		fmt.Printf("  %s  %s\n", sDim.Render("→"), sDim.Render(mod))
		time.Sleep(85 * time.Millisecond)
		fmt.Print("\033[1A\r\033[2K")
		if i == len(modules)-1 {
			fmt.Printf("  %s  %s\n", sGreen.Render("✓"), sBold.Render(mod))
		} else {
			fmt.Printf("  %s  %s\n", sGreen.Render("✓"), sDim.Render(mod))
		}
	}

	fmt.Println()
	fmt.Println("  " + sDim.Render("·· "+strings.Repeat("─", 60)+" ··"))
}

// ── Entry point ───────────────────────────────────────────────────────────────

func Run() error {
	display.EnableANSI() // must be first — enables Windows VTP before any ANSI output
	clear()
	introOnce.Do(runIntro)
	splash()
	for {
		choice := mainMenu()
		switch choice {
		case "1":
			clear()
			if err := analyzeWizard(); err != nil {
				printErr(err.Error())
				pause()
			}
		case "2":
			clear()
			if err := openCaseWizard(); err != nil {
				printErr(err.Error())
				pause()
			}
		case "3":
			clear()
			if err := replWizard(); err != nil {
				printErr(err.Error())
				pause()
			}
		case "q", "quit", "exit", "0":
			fmt.Println()
			return nil
		}
		clear()
		splash()
	}
}

func clear() {
	fmt.Print("\033[2J\033[H")
}

// ── Splash ────────────────────────────────────────────────────────────────────

func splash() {
	logo := sPrimary.Render("⚡  FORENSIQ") + "  " + sDim.Render("v0.7")
	sub := sDim.Render("Artifact Extraction  ·  Threat Detection  ·  DFIR Intelligence")

	box := lipgloss.NewStyle().
		Border(lipgloss.DoubleBorder()).
		BorderForeground(cPurple).
		Padding(1, 5).
		Width(76)

	fmt.Println()
	fmt.Println(box.Render(logo + "\n" + sub))
	fmt.Println()
}

// ── Main menu ─────────────────────────────────────────────────────────────────

func mainMenu() string {
	type item struct{ key, name, desc string }
	items := []item{
		{"1", "Analyze", "Artifacts, IOCs & threat detection"},
		{"2", "Open Case", "Serve .fcase in web browser"},
		{"3", "REPL", "Interactive SQL & pivot queries"},
	}

	var lines []string
	lines = append(lines, "")
	for _, it := range items {
		key  := sGreen.Width(2).Render(it.key)
		name := sBold.Width(12).Render(it.name)
		desc := sDim.Render(it.desc)
		lines = append(lines, "  "+key+"  "+name+desc)
	}
	lines = append(lines, "")
	lines = append(lines, "  "+sDim.Width(2).Render("q")+"  "+sDim.Width(12).Render("Quit"))
	lines = append(lines, "")

	fmt.Print(menuBox.Render(strings.Join(lines, "\n")))
	fmt.Println()
	fmt.Println()
	return ask("Choice")
}

// ── Step breadcrumb ───────────────────────────────────────────────────────────

var (
	stepNames = [3]string{"Disk", "ZIP", "RAM"}
	stepNums  = [3]string{"①", "②", "③"}
)

func stepBreadcrumb(current int) string {
	var parts []string
	for i := 0; i < 3; i++ {
		label := stepNums[i] + "  " + stepNames[i]
		var s string
		switch {
		case i+1 < current:
			s = sGreen.Render(label)
		case i+1 == current:
			s = sBold.Foreground(cCyan).Render(label)
		default:
			s = sDim.Render(label)
		}
		parts = append(parts, s)
	}
	return "  " + strings.Join(parts, sDim.Render("  ──  "))
}

// scanBar renders a decorative progress-style separator.
func scanBar() string {
	seg := "░▒▓█▓▒░"
	rep := strings.Repeat(seg, 9)
	return sDim.Render("  " + rep[:58])
}

// ── Analyze wizard ────────────────────────────────────────────────────────────

func analyzeWizard() error {
	fmt.Println()
	fmt.Println(sectionHdr.Render("  New Analysis"))
	fmt.Println()

	defaultName := "case-" + time.Now().Format("20060102-1504")
	name := askDefault("Case name", defaultName)

	var triage, disk, ram string
	var err error

	// Step 1: Disk image
	fmt.Println()
	fmt.Println(scanBar())
	fmt.Println(stepBreadcrumb(1))
	disk, err = pickSource(
		"Disk Image",
		"E01 / VMDK / VHD / raw",
		findByExt([]string{".e01", ".vmdk", ".vhd", ".vhdx", ".img"}),
	)
	if err != nil {
		return err
	}

	// Step 2: Triage ZIP
	fmt.Println()
	fmt.Println(scanBar())
	fmt.Println(stepBreadcrumb(2))
	triage, err = pickSource(
		"Triage ZIP",
		"pre-collected artifacts (.zip)",
		findByExt([]string{".zip"}),
	)
	if err != nil {
		return err
	}

	// Step 3: RAM dump
	fmt.Println()
	fmt.Println(scanBar())
	fmt.Println(stepBreadcrumb(3))
	ram, err = pickSource(
		"RAM Dump",
		".dmp / .raw / .mem / .vmem",
		findByExt([]string{".dmp", ".raw", ".mem", ".vmem"}),
	)
	if err != nil {
		return err
	}

	if triage == "" && disk == "" && ram == "" {
		return fmt.Errorf("nothing selected — at least one source is required")
	}

	// Pre-run confirmation summary
	casePath := sanitize(name) + ".fcase"
	fmt.Println()
	fmt.Println(scanBar())
	fmt.Printf("  %s  %s\n", sDim.Width(6).Render("Case:"), sBold.Render(name))
	if disk != "" {
		fmt.Printf("  %s  %s\n", sGreen.Width(6).Render("Disk:"), disk)
	}
	if triage != "" {
		fmt.Printf("  %s  %s\n", sGreen.Width(6).Render("ZIP:"), triage)
	}
	if ram != "" {
		fmt.Printf("  %s  %s\n", sGreen.Width(6).Render("RAM:"), ram)
	}
	fmt.Printf("  %s  %s\n", sDim.Width(6).Render("Out:"), sDim.Render(casePath))
	fmt.Println(scanBar())
	fmt.Println()
	fmt.Printf("  %s", sDim.Render("Press Enter to start, Ctrl+C to cancel "))
	reader.ReadString('\n')
	fmt.Println()

	start := time.Now()
	c, res, err := orchestrator.Run(orchestrator.Options{
		TriagePath: triage,
		RAMPath:    ram,
		DiskPath:   disk,
		CasePath:   casePath,
		CaseName:   name,
	})
	if err != nil {
		return err
	}

	fmt.Println()
	fmt.Printf("  %s  Extracting IOCs...\n", sDim.Render("→"))
	ioc.ExtractAll(c.DB())

	fmt.Printf("  %s  Running threat detectors...\n", sDim.Render("→"))
	detResults, _ := detect.RunAll(c.DB())

	elapsed := time.Since(start)
	if res != nil {
		elapsed = res.Elapsed
	}

	total := int64(0)
	if res != nil {
		total = res.TotalArtifacts
	}

	fmt.Println()
	printSummary(casePath, total, elapsed, detResults)
	return postAnalysis(c, casePath)
}

// printSummary renders the post-analysis result panel.
func printSummary(casePath string, total int64, elapsed time.Duration, detResults []detect.Result) {
	var hi, med int64
	type finding struct {
		name string
		hits int64
	}
	var topHigh []finding
	for _, r := range detResults {
		if r.Hits == 0 {
			continue
		}
		switch strings.ToUpper(r.Severity) {
		case "HIGH":
			hi += r.Hits
			topHigh = append(topHigh, finding{r.Name, r.Hits})
		case "MED", "MEDIUM":
			med += r.Hits
		}
	}
	sort.Slice(topHigh, func(i, j int) bool { return topHigh[i].hits > topHigh[j].hits })

	var lines []string
	lines = append(lines, "")
	lines = append(lines, "  "+sGreen.Render("✓")+"  "+sBold.Render("Analysis Complete")+"  "+sDim.Render(elapsed.Round(time.Second).String()))
	lines = append(lines, "")
	lines = append(lines, "  "+sDim.Render("Artifacts : ")+sBold.Render(fmtNum(total)))
	lines = append(lines, "  "+sDim.Render("Saved     : ")+sDim.Render(casePath))

	if hi > 0 || med > 0 {
		lines = append(lines, "")
		if hi > 0 {
			lines = append(lines, "  "+sRed.Render("⚠")+"  "+sRed.Render(strconv.FormatInt(hi, 10)+" HIGH severity hits"))
			for i, f := range topHigh {
				if i >= 3 {
					break
				}
				lines = append(lines, "     "+sDim.Render("·  "+f.name+fmt.Sprintf("  (%d)", f.hits)))
			}
		}
		if med > 0 {
			lines = append(lines, "  "+sYellow.Render("⚠")+"  "+sYellow.Render(strconv.FormatInt(med, 10)+" MEDIUM severity hits"))
		}
	} else {
		lines = append(lines, "")
		lines = append(lines, "  "+sGreen.Render("✓")+"  "+sDim.Render("No high/medium severity detections"))
	}
	lines = append(lines, "")

	box := resultBox
	if hi > 0 {
		box = alertBox
	}
	fmt.Println(box.Render(strings.Join(lines, "\n")))
	fmt.Println()
}

// postAnalysis prompts what to do after a completed analysis run.
func postAnalysis(c *fcase.Case, casePath string) error {
	fmt.Printf("  %s  %s  %s\n", sGreen.Width(2).Render("1"), sBold.Width(14).Render("Open Browser"), sDim.Render("start web server"))
	fmt.Printf("  %s  %s  %s\n", sGreen.Width(2).Render("2"), sBold.Width(14).Render("REPL"), sDim.Render("interactive SQL queries"))
	fmt.Printf("  %s  %s\n", sDim.Width(2).Render("3"), sDim.Width(14).Render("Back to menu"))
	fmt.Println()

	choice := ask("Choice")
	switch choice {
	case "1":
		c.Close()
		return servePath(casePath)
	case "2":
		return repl.Run(c)
	default:
		c.Close()
		return nil
	}
}

// ── Open Case wizard ──────────────────────────────────────────────────────────

func openCaseWizard() error {
	fmt.Println()
	fmt.Println(sectionHdr.Render("  Open Case"))
	fmt.Println()

	path, err := pickFcase()
	if err != nil || path == "" {
		return err
	}

	fmt.Println()
	fmt.Printf("  %s  %s  %s\n", sGreen.Width(2).Render("1"), sBold.Width(14).Render("Open Browser"), sDim.Render("start web server"))
	fmt.Printf("  %s  %s  %s\n", sGreen.Width(2).Render("2"), sBold.Width(14).Render("REPL"), sDim.Render("interactive SQL queries"))
	fmt.Println()

	switch ask("Choice") {
	case "2":
		return replFromPath(path)
	default:
		return servePath(path)
	}
}

// ── REPL wizard ───────────────────────────────────────────────────────────────

func replWizard() error {
	fmt.Println()
	fmt.Println(sectionHdr.Render("  Open in REPL"))
	fmt.Println()

	path, err := pickFcase()
	if err != nil || path == "" {
		return err
	}
	return replFromPath(path)
}

// ── Shared helpers ────────────────────────────────────────────────────────────

func pickFcase() (string, error) {
	files := findFcases()

	if len(files) == 0 {
		p := ask("Path to .fcase file")
		return p, nil
	}

	fmt.Println(sDim.Render("  Found cases:"))
	fmt.Println()
	for i, f := range files {
		info, _ := os.Stat(f)
		age := ""
		if info != nil {
			age = sDim.Render("  " + info.ModTime().Format("2006-01-02 15:04"))
		}
		fmt.Printf("  %s  %s%s\n",
			sGreen.Render(fmt.Sprintf("%d", i+1)),
			sAccent.Render(filepath.Base(f)),
			age,
		)
		fmt.Printf("     %s\n", sDim.Render(filepath.Dir(f)))
	}
	fmt.Printf("  %s  Enter path manually\n", sDim.Render("m"))
	fmt.Println()

	choice := ask("Choice")

	var casePath string
	if n, err := strconv.Atoi(choice); err == nil && n >= 1 && n <= len(files) {
		casePath = files[n-1]
	} else if strings.ToLower(choice) == "m" {
		casePath = ask("Path to .fcase file")
	} else if choice != "" {
		casePath = choice
	}

	if casePath == "" {
		return "", nil
	}
	if _, err := os.Stat(casePath); err != nil {
		return "", fmt.Errorf("file not found: %s", casePath)
	}
	return casePath, nil
}

func servePath(casePath string) error {
	portStr := askDefault("Port", "8080")
	port := 8080
	if n, err := strconv.Atoi(portStr); err == nil && n > 0 {
		port = n
	}

	url := fmt.Sprintf("http://localhost:%d", port)
	inner := sGreen.Render("►") + "  " + sBold.Render(url) + "\n\n" + sDim.Render("Ctrl+C to stop")

	fmt.Println()
	fmt.Println(serverBox.Render(inner))
	fmt.Println()

	return server.Start(casePath, "", port)
}

func replFromPath(casePath string) error {
	c, err := fcase.Open(casePath, "")
	if err != nil {
		return err
	}
	if err := schema.Apply(c); err != nil {
		c.Close()
		return err
	}
	return repl.Run(c)
}

// findFcases scans common locations for .fcase files, sorted newest first.
func findFcases() []string {
	var found []string
	seen := map[string]bool{}

	dirs := []string{"."}
	if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs,
			filepath.Join(home, "Desktop"),
			filepath.Join(home, "Documents"),
			home,
		)
	}
	dirs = append(dirs, `C:\cases`, `C:\images`)

	for _, dir := range dirs {
		matches, _ := filepath.Glob(filepath.Join(dir, "*.fcase"))
		for _, m := range matches {
			abs, _ := filepath.Abs(m)
			if !seen[abs] {
				seen[abs] = true
				found = append(found, m)
			}
		}
	}

	sort.Slice(found, func(i, j int) bool {
		si, _ := os.Stat(found[i])
		sj, _ := os.Stat(found[j])
		if si == nil || sj == nil {
			return false
		}
		return si.ModTime().After(sj.ModTime())
	})

	if len(found) > 8 {
		found = found[:8]
	}
	return found
}

// pickSource shows a titled step, optional candidate list, and a prompt.
// Returns the chosen path or "" if the user skipped.
func pickSource(title, hint string, candidates []string) (string, error) {
	fmt.Println()
	fmt.Printf("  %s\n", sBold.Render(title))
	fmt.Printf("  %s\n", sDim.Render(hint+"  ·  Enter to skip"))
	fmt.Println()

	for i, f := range candidates {
		info, _ := os.Stat(f)
		sz := ""
		if info != nil {
			sz = sDim.Render("  " + fmtBytes(info.Size()))
		}
		fmt.Printf("  %s  %s%s\n",
			sGreen.Render(fmt.Sprintf("%d", i+1)),
			sAccent.Render(filepath.Base(f)), sz)
		fmt.Printf("     %s\n", sDim.Render(filepath.Dir(f)))
	}
	if len(candidates) > 0 {
		fmt.Println()
	}

	var prompt string
	if len(candidates) > 0 {
		prompt = fmt.Sprintf("%s  [1-%d / path / ↵ skip]", title, len(candidates))
	} else {
		prompt = title + "  [path / ↵ skip]"
	}

	choice := ask(prompt)
	if choice == "" {
		return "", nil
	}

	if n, err := strconv.Atoi(choice); err == nil && n >= 1 && n <= len(candidates) {
		return candidates[n-1], nil
	}

	if _, err := os.Stat(choice); err != nil {
		return "", fmt.Errorf("not found: %s", choice)
	}
	return choice, nil
}

// isBuildArtifact returns true for ZIP files that are dev tools, not evidence.
func isBuildArtifact(name string) bool {
	lower := strings.ToLower(name)
	for _, kw := range []string{
		"forensiq", "mingw", "msys", "ucrt", "llvm", "clang",
		"go1.", "nodejs", "python-", "cmake", "gcc",
	} {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

// findByExt scans common locations for files with the given extensions.
func findByExt(exts []string) []string {
	extSet := map[string]bool{}
	for _, e := range exts {
		extSet[strings.ToLower(e)] = true
	}

	dirs := []string{"."}
	if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs,
			filepath.Join(home, "Desktop"),
			filepath.Join(home, "Downloads"),
			filepath.Join(home, "Documents"),
			home,
		)
	}
	dirs = append(dirs,
		`C:\cases`,
		`C:\images`,
		`D:\`,
		`D:\cases`,
		`D:\images`,
		`E:\`,
	)

	var found []string
	seen := map[string]bool{}
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			ext := strings.ToLower(filepath.Ext(e.Name()))
			if !extSet[ext] {
				continue
			}
			if ext == ".zip" && isBuildArtifact(e.Name()) {
				continue
			}
			abs := filepath.Join(dir, e.Name())
			if !seen[abs] {
				seen[abs] = true
				found = append(found, abs)
			}
		}
	}

	sort.Slice(found, func(i, j int) bool {
		si, _ := os.Stat(found[i])
		sj, _ := os.Stat(found[j])
		if si == nil || sj == nil {
			return false
		}
		return si.ModTime().After(sj.ModTime())
	})
	if len(found) > 8 {
		found = found[:8]
	}
	return found
}

// ── Format helpers ────────────────────────────────────────────────────────────

func fmtBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.0f MB", float64(n)/(1<<20))
	default:
		return fmt.Sprintf("%d KB", n>>10)
	}
}

func printErr(msg string) {
	fmt.Println()
	fmt.Printf("  %s  %s\n", sRed.Render("✗"), sRed.Render(msg))
}

func pause() {
	fmt.Println()
	fmt.Print(sDim.Render("  Press Enter to continue..."))
	reader.ReadString('\n')
}

func fmtNum(n int64) string {
	s := strconv.FormatInt(n, 10)
	out := ""
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			out += ","
		}
		out += string(c)
	}
	return out
}

func sanitize(s string) string {
	return strings.NewReplacer(" ", "-", "/", "-", "\\", "-", ":", "").Replace(s)
}
