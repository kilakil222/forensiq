package volatility

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"time"

	"forensiq/internal/parsers"
)

// Runner executes Volatility3 as a subprocess and stores results in DuckDB.
type Runner struct {
	dumpPath string
	volBin   string
}

// New returns a Runner for the given memory dump path.
// It searches for vol3 first, then vol in PATH.
func New(dumpPath string) *Runner {
	bin := ""
	if path, err := exec.LookPath("vol3"); err == nil {
		bin = path
	} else if path, err := exec.LookPath("vol"); err == nil {
		bin = path
	}
	return &Runner{dumpPath: dumpPath, volBin: bin}
}

// IsAvailable returns true if a Volatility binary was found in PATH.
func (r *Runner) IsAvailable() bool {
	return r.volBin != ""
}

// Plugins returns the list of Windows plugins to run.
func (r *Runner) Plugins() []string {
	return []string{
		"windows.pslist", "windows.psscan", "windows.cmdline",
		"windows.netscan", "windows.netstat", "windows.filescan",
		"windows.handles", "windows.modules", "windows.driverscan",
		"windows.malfind", "windows.hivelist", "windows.info",
	}
}

// RunPlugin runs a single Volatility plugin, parses JSON output, and inserts rows into DuckDB.
// Progress is sent to ch when the plugin finishes.
func (r *Runner) RunPlugin(plugin string, db *sql.DB, ch chan<- parsers.Progress) error {
	start := time.Now()
	cmd := exec.Command(r.volBin, "-q", "-f", r.dumpPath, "--renderer", "json", plugin)
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("vol %s: %w", plugin, err)
	}

	rows, err := parseVolOutput(out)
	if err != nil {
		return fmt.Errorf("vol %s parse: %w", plugin, err)
	}

	count, err := insertRows(plugin, rows, db)
	if err != nil {
		return err
	}
	select {
	case ch <- parsers.Progress{Parser: "vol/" + plugin, Count: count, Done: true, Elapsed: time.Since(start)}:
	default:
	}
	return nil
}

// parseVolOutput handles three Volatility3 JSON output formats:
//  1. A top-level JSON array: [{"PID": 4, ...}, ...]
//  2. A wrapped object:       {"rows": [...]}
//  3. Newline-delimited JSON: one object per line
func parseVolOutput(data []byte) ([]map[string]interface{}, error) {
	// Try array JSON first
	var arr []map[string]interface{}
	if json.Unmarshal(data, &arr) == nil {
		return arr, nil
	}
	// Try wrapped {"rows": [...]}
	var wrapped struct {
		Rows []map[string]interface{} `json:"rows"`
	}
	if json.Unmarshal(data, &wrapped) == nil && wrapped.Rows != nil {
		return wrapped.Rows, nil
	}
	// Try NDJSON (newline-delimited JSON)
	var rows []map[string]interface{}
	dec := json.NewDecoder(bytes.NewReader(data))
	for {
		var row map[string]interface{}
		if err := dec.Decode(&row); err == io.EOF {
			break
		} else if err != nil {
			continue
		}
		rows = append(rows, row)
	}
	return rows, nil
}

func insertRows(plugin string, rows []map[string]interface{}, db *sql.DB) (int64, error) {
	inserter := pluginInserter(plugin)
	if inserter == nil {
		return 0, nil
	}
	var count int64
	for _, row := range rows {
		if err := inserter(db, row); err == nil {
			count++
		}
	}
	return count, nil
}

// pluginInserter returns a row-inserter function for the given plugin name,
// or nil if the plugin has no mapped table.
func pluginInserter(plugin string) func(*sql.DB, map[string]interface{}) error {
	switch plugin {
	case "windows.pslist":
		return func(db *sql.DB, r map[string]interface{}) error {
			_, err := db.Exec(
				`INSERT INTO mem_pslist (pid, ppid, name, threads, handles, wow64, create_time) VALUES (?, ?, ?, ?, ?, ?, ?)`,
				intField(r, "PID"), intField(r, "PPID"), strField(r, "ImageFileName"),
				intField(r, "Threads"), intField(r, "Handles"), boolField(r, "Wow64"), strField(r, "CreateTime"),
			)
			return err
		}

	case "windows.psscan":
		return func(db *sql.DB, r map[string]interface{}) error {
			_, err := db.Exec(
				`INSERT INTO mem_psscan (pid, ppid, name) VALUES (?, ?, ?)`,
				intField(r, "PID"), intField(r, "PPID"), strField(r, "ImageFileName"),
			)
			return err
		}

	case "windows.cmdline":
		return func(db *sql.DB, r map[string]interface{}) error {
			_, err := db.Exec(
				`INSERT INTO mem_cmdline (pid, name, cmdline) VALUES (?, ?, ?)`,
				intField(r, "PID"), strField(r, "ImageFileName"), strField(r, "Args"),
			)
			return err
		}

	case "windows.netscan", "windows.netstat":
		return func(db *sql.DB, r map[string]interface{}) error {
			_, err := db.Exec(
				`INSERT INTO mem_netscan (proto, local_addr, local_port, remote_addr, remote_port, "state", pid, name, created) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				strField(r, "Proto"), strField(r, "LocalAddr"), intField(r, "LocalPort"),
				strField(r, "ForeignAddr"), intField(r, "ForeignPort"),
				strField(r, "State"), intField(r, "PID"), strField(r, "Owner"),
				nullableStr(strField(r, "Created")),
			)
			return err
		}

	case "windows.filescan":
		return func(db *sql.DB, r map[string]interface{}) error {
			_, err := db.Exec(
				`INSERT INTO mem_filescan (name, path) VALUES (?, ?)`,
				strField(r, "Name"), strField(r, "Name"),
			)
			return err
		}

	case "windows.handles":
		return func(db *sql.DB, r map[string]interface{}) error {
			_, err := db.Exec(
				`INSERT INTO mem_handles (pid, name, handle_type, handle_value, object_name) VALUES (?, ?, ?, ?, ?)`,
				intField(r, "PID"), strField(r, "ImageFileName"), strField(r, "Type"),
				strField(r, "HandleValue"), strField(r, "Name"),
			)
			return err
		}

	case "windows.modules":
		return func(db *sql.DB, r map[string]interface{}) error {
			_, err := db.Exec(
				`INSERT INTO mem_modules (pid, name, base, size, path) VALUES (?, ?, ?, ?, ?)`,
				intField(r, "PID"), strField(r, "Name"), strField(r, "Base"),
				intField(r, "Size"), strField(r, "File"),
			)
			return err
		}

	case "windows.driverscan":
		return func(db *sql.DB, r map[string]interface{}) error {
			_, err := db.Exec(
				`INSERT INTO mem_driverscan (mem_offset, name, size, path) VALUES (?, ?, ?, ?)`,
				strField(r, "Offset"), strField(r, "Name"),
				intField(r, "Size"), strField(r, "Driver"),
			)
			return err
		}

	case "windows.malfind":
		return func(db *sql.DB, r map[string]interface{}) error {
			_, err := db.Exec(
				`INSERT INTO mem_malfind (pid, name, address, size, hexdump, disasm) VALUES (?, ?, ?, ?, ?, ?)`,
				intField(r, "PID"), strField(r, "Process"), strField(r, "Start"),
				intField(r, "Size"), strField(r, "Hexdump"), strField(r, "Disasm"),
			)
			return err
		}

	case "windows.hivelist":
		return func(db *sql.DB, r map[string]interface{}) error {
			_, err := db.Exec(
				`INSERT INTO mem_hivelist (hive_name, path) VALUES (?, ?)`,
				strField(r, "Name"), strField(r, "FileFullPath"),
			)
			return err
		}

	case "windows.info":
		return func(db *sql.DB, r map[string]interface{}) error {
			_, err := db.Exec(
				`INSERT INTO mem_sysinfo (key, value) VALUES (?, ?)`,
				strField(r, "Variable"), strField(r, "Value"),
			)
			return err
		}

	default:
		return nil
	}
}

// strField returns the string representation of field k in r, or "" if absent.
func strField(r map[string]interface{}, k string) string {
	if v, ok := r[k]; ok {
		return fmt.Sprintf("%v", v)
	}
	return ""
}

// intField returns an int64 value for field k in r, or 0 if absent or not numeric.
func intField(r map[string]interface{}, k string) int64 {
	if v, ok := r[k]; ok {
		switch t := v.(type) {
		case float64:
			return int64(t)
		case int64:
			return t
		case int:
			return int64(t)
		case uint64:
			return int64(t)
		}
	}
	return 0
}

// boolField returns a bool value for field k in r, or false if absent.
func boolField(r map[string]interface{}, k string) bool {
	if v, ok := r[k]; ok {
		b, _ := v.(bool)
		return b
	}
	return false
}

// nullableStr returns nil when s is empty so DuckDB stores NULL instead of "".
func nullableStr(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}
