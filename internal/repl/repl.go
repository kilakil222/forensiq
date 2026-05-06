package repl

import (
	"bufio"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/chzyer/readline"
	"github.com/mattn/go-isatty"
	"forensiq/internal/display"
	"forensiq/internal/fcase"
	"forensiq/internal/repl/commands"
	"forensiq/internal/schema"
)

// Start is the entry point when forensiq is launched without a subcommand.
// It shows the banner, resolves the case file, then drops into Run().
func Start(casePath string) error {
	display.Banner()

	if casePath == "" {
		casePath = resolveCasePath()
		if casePath == "" {
			return nil
		}
	}

	fmt.Printf("  Opening %s…\n\n", casePath)
	c, err := fcase.Open(casePath, "")
	if err != nil {
		display.Error("cannot open case: " + err.Error())
		return nil
	}
	if err := schema.Apply(c); err != nil {
		c.Close()
		display.Error("schema error: " + err.Error())
		return nil
	}

	// Show quick summary on startup
	_ = commands.Summary(c.DB())

	return Run(c)
}

// resolveCasePath looks for .fcase files in cwd and prompts the user.
func resolveCasePath() string {
	matches, _ := filepath.Glob("*.fcase")
	if len(matches) == 1 {
		fmt.Printf("  Found: %s\n", matches[0])
		fmt.Print("  Open it? [Y/n]: ")
		var ans string
		fmt.Scanln(&ans)
		ans = strings.TrimSpace(strings.ToLower(ans))
		if ans == "" || ans == "y" || ans == "yes" {
			return matches[0]
		}
	} else if len(matches) > 1 {
		fmt.Println("  Multiple .fcase files found:")
		for i, m := range matches {
			fmt.Printf("    [%d] %s\n", i+1, m)
		}
		fmt.Print("  Enter number or path: ")
		var ans string
		fmt.Scanln(&ans)
		ans = strings.TrimSpace(ans)
		var n int
		if _, err := fmt.Sscanf(ans, "%d", &n); err == nil && n >= 1 && n <= len(matches) {
			return matches[n-1]
		}
		return ans
	}

	fmt.Print("  Path to .fcase file: ")
	var p string
	fmt.Scanln(&p)
	p = strings.TrimSpace(p)
	if p == "" {
		fmt.Println()
		return ""
	}
	return p
}

// caseName extracts a short display name from the case (DB meta or filename).
func caseName(c *fcase.Case) string {
	var name string
	c.DB().QueryRow("SELECT name FROM case_meta WHERE id=1").Scan(&name)
	if name != "" {
		return name
	}
	base := filepath.Base(c.Path)
	return strings.TrimSuffix(base, filepath.Ext(base))
}

func Run(c *fcase.Case) error {
	defer c.Close()

	name := caseName(c)

	if !isatty.IsTerminal(os.Stdin.Fd()) && !isatty.IsCygwinTerminal(os.Stdin.Fd()) {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			if err := dispatch(c, line); err == errExit {
				return nil
			}
		}
		return nil
	}

	rl, err := readline.NewEx(&readline.Config{
		Prompt:          display.REPLPrompt(name) + " ",
		HistoryFile:     "/tmp/forensiq_history",
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",
	})
	if err != nil {
		return err
	}
	defer rl.Close()

	for {
		line, err := rl.Readline()
		if err != nil {
			break
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if err := dispatch(c, line); err == errExit {
			return nil
		}
	}
	return nil
}

var errExit = fmt.Errorf("exit")

func dispatch(c *fcase.Case, line string) error {
	line = strings.TrimPrefix(line, "\xef\xbb\xbf")
	parts := strings.Fields(line)
	cmd := parts[0]
	args := parts[1:]

	var runErr error
	switch cmd {
	case "exit", "quit":
		return errExit
	case "help":
		printHelp()
	case "sql":
		runErr = commands.SQL(strings.Join(args, " "), c.DB())
	case "summary":
		runErr = commands.Summary(c.DB())
	case "ioc":
		runErr = commands.IOC(c.DB())
	case "timeline":
		from, to := parseTimelineArgs(args)
		runErr = commands.Timeline(c.DB(), from, to)
	case "pivot":
		if len(args) < 2 {
			display.Error("usage: pivot <process|ip|user|file> <value>")
		} else {
			runErr = commands.Pivot(c.DB(), args[0], strings.Join(args[1:], " "))
		}
	case "correlate":
		if len(args) == 0 {
			display.Error("usage: correlate <term>")
		} else {
			runErr = commands.Correlate(c.DB(), strings.Join(args, " "))
		}
	case "detect":
		runErr = commands.Detect(c.DB())
	case "hunt":
		dir := ""
		if len(args) > 0 {
			dir = args[0]
		}
		runErr = commands.Hunt(c.DB(), dir)
	case "yara":
		dir := ""
		if len(args) > 0 {
			dir = args[0]
		}
		runErr = commands.Yara(c.DB(), dir)
	case "events":
		eid := ""
		if len(args) > 0 {
			eid = args[0]
		}
		runErr = cmdEvents(c.DB(), eid)
	case "auth":
		filter := ""
		if len(args) > 0 {
			filter = strings.Join(args, " ")
		}
		runErr = cmdAuth(c.DB(), filter)
	case "files":
		filter := "suspicious"
		if len(args) > 0 {
			filter = strings.Join(args, " ")
		}
		runErr = cmdFiles(c.DB(), filter)
	case "defender":
		runErr = cmdDefender(c.DB())
	case "report":
		display.Error("run: forensiq report <file.fcase>")
	default:
		display.Error(fmt.Sprintf("unknown command: %q (type 'help')", cmd))
	}

	if runErr != nil {
		display.Error(runErr.Error())
	}
	return nil
}

func cmdEvents(db *sql.DB, eid string) error {
	q := `SELECT timestamp, event_id, channel, computer, user_sid, LEFT(message, 120) AS msg
	      FROM evtx_events WHERE 1=1`
	args := []any{}
	if eid != "" {
		q += " AND CAST(event_id AS VARCHAR) = ?"
		args = append(args, eid)
	}
	q += " ORDER BY timestamp DESC LIMIT 50"

	rows, err := db.Query(q, args...)
	if err != nil {
		return err
	}
	defer rows.Close()

	headers := []string{"Timestamp", "ID", "Channel", "Computer", "User/SID", "Message"}
	var data [][]string
	for rows.Next() {
		var ts, ch, comp, sid, msg sql.NullString
		var evtID sql.NullInt64
		rows.Scan(&ts, &evtID, &ch, &comp, &sid, &msg)
		ch_short := ch.String
		if i := strings.LastIndexAny(ch_short, "/\\"); i >= 0 {
			ch_short = ch_short[i+1:]
		}
		data = append(data, []string{
			ts.String, fmt.Sprintf("%d", evtID.Int64),
			ch_short, comp.String, sid.String, msg.String,
		})
	}
	if len(data) == 0 {
		fmt.Println("  (no events)")
		return nil
	}
	display.Table(headers, data)
	return nil
}

func cmdAuth(db *sql.DB, filter string) error {
	q := `SELECT timestamp, event_id, "user", domain, logon_type, src_ip, workstation
	      FROM auth_events WHERE 1=1`
	args := []any{}
	if filter != "" {
		q += ` AND ("user" ILIKE ? OR src_ip ILIKE ? OR CAST(logon_type AS VARCHAR) = ?)`
		like := "%" + filter + "%"
		args = append(args, like, like, filter)
	}
	q += " ORDER BY timestamp DESC LIMIT 50"

	rows, err := db.Query(q, args...)
	if err != nil {
		return err
	}
	defer rows.Close()

	headers := []string{"Timestamp", "Event", "User", "Domain", "Type", "Source IP", "Workstation"}
	var data [][]string
	for rows.Next() {
		var ts, user, domain, srcIP, ws sql.NullString
		var evtID, ltype sql.NullInt64
		rows.Scan(&ts, &evtID, &user, &domain, &ltype, &srcIP, &ws)
		data = append(data, []string{
			ts.String, fmt.Sprintf("%d", evtID.Int64),
			user.String, domain.String, fmt.Sprintf("%d", ltype.Int64),
			srcIP.String, ws.String,
		})
	}
	if len(data) == 0 {
		fmt.Println("  (no auth events)")
		return nil
	}
	display.Table(headers, data)
	return nil
}

func cmdFiles(db *sql.DB, filter string) error {
	var q string
	var args []any
	switch filter {
	case "deleted":
		q = `SELECT path, size, modified FROM mft WHERE is_deleted=true AND is_dir=false ORDER BY modified DESC NULLS LAST LIMIT 50`
	case "exec", "executables":
		q = `SELECT path, size, modified FROM mft WHERE is_dir=false AND (path ILIKE '%.exe' OR path ILIKE '%.dll' OR path ILIKE '%.ps1' OR path ILIKE '%.bat') ORDER BY modified DESC NULLS LAST LIMIT 50`
	case "suspicious":
		q = `SELECT path, size, modified FROM mft WHERE is_dir=false AND (
			path ILIKE '%/Temp/%.exe' OR path ILIKE '%/AppData/Roaming/%.exe' OR
			path ILIKE '%/Downloads/%.exe' OR path ILIKE '%/Windows/Temp/%.exe' OR
			path ILIKE '%/ProgramData/%.exe' OR path ILIKE '%/Windows/Tasks/%.exe'
		) ORDER BY modified DESC NULLS LAST LIMIT 50`
	default:
		q = `SELECT path, size, modified FROM mft WHERE is_dir=false AND path ILIKE ? ORDER BY modified DESC NULLS LAST LIMIT 50`
		args = append(args, "%"+filter+"%")
	}

	rows, err := db.Query(q, args...)
	if err != nil {
		return err
	}
	defer rows.Close()

	headers := []string{"Path", "Size", "Modified"}
	var data [][]string
	for rows.Next() {
		var path, mod sql.NullString
		var size sql.NullInt64
		rows.Scan(&path, &size, &mod)
		sz := ""
		if size.Valid {
			switch {
			case size.Int64 < 1024:
				sz = fmt.Sprintf("%dB", size.Int64)
			case size.Int64 < 1048576:
				sz = fmt.Sprintf("%.1fKB", float64(size.Int64)/1024)
			default:
				sz = fmt.Sprintf("%.1fMB", float64(size.Int64)/1048576)
			}
		}
		data = append(data, []string{path.String, sz, mod.String})
	}
	if len(data) == 0 {
		fmt.Printf("  (no files for filter: %s)\n\n", filter)
		return nil
	}
	display.Table(headers, data)
	return nil
}

func cmdDefender(db *sql.DB) error {
	rows, err := db.Query(`SELECT timestamp, threat_name, severity, action, path, process_name
	                       FROM defender_events ORDER BY timestamp DESC LIMIT 50`)
	if err != nil {
		return err
	}
	defer rows.Close()

	headers := []string{"Timestamp", "Threat", "Severity", "Action", "Path", "Process"}
	var data [][]string
	for rows.Next() {
		var ts, threat, sev, action, path, proc sql.NullString
		rows.Scan(&ts, &threat, &sev, &action, &path, &proc)
		data = append(data, []string{ts.String, threat.String, sev.String, action.String, path.String, proc.String})
	}
	if len(data) == 0 {
		fmt.Println("  (no Defender events)")
		return nil
	}
	display.Table(headers, data)
	return nil
}

func parseTimelineArgs(args []string) (from, to string) {
	if len(args) >= 1 {
		from = args[0]
	}
	if len(args) >= 2 {
		to = args[1]
	}
	return
}

func printHelp() {
	fmt.Print(`
  ── Artifact Commands ──────────────────────────────────────────────
    summary                     Case statistics
    events [event_id]           EVTX events (latest 50; filter by ID)
    auth [user|ip|logon_type]   Auth events (logon/logoff/fail)
    files [suspicious|exec|deleted|<search>]  MFT files
    defender                    Windows Defender detections
    ioc                         All IOC indicators

  ── Analysis ───────────────────────────────────────────────────────
    timeline [from] [to]        Unified timeline (ISO timestamps)
    correlate <term>            Cross-table search (process/IP/user/file)
    pivot process <pid|name>    All artifacts for a process
    pivot ip <ip>               Network + memory + logs for an IP
    pivot user <username>       All user activity
    pivot file <path>           File artifact chain
    detect                      Run built-in threat detectors
    hunt [rules-dir]            Run SIGMA JSON rules
    yara [rules-dir]            Scan text artifacts (string/regex)

  ── Other ──────────────────────────────────────────────────────────
    sql <query>                 Raw DuckDB SQL
    help                        Show this help
    exit                        Exit REPL

`)
}
