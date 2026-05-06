// Package triage opens a ZIP archive produced by a forensic collection tool,
// identifies each file by path pattern, and dispatches it to the appropriate parser.
package triage

import (
	"archive/zip"
	"bytes"
	"database/sql"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"forensiq/internal/parsers"
	"forensiq/internal/parsers/amcache"
	"forensiq/internal/parsers/browser"
	"forensiq/internal/parsers/evtx"
	linux "forensiq/internal/parsers/linux"
	"forensiq/internal/parsers/jumplists"
	"forensiq/internal/parsers/lnk"
	"forensiq/internal/parsers/recyclebin"
	"forensiq/internal/parsers/shellbags"
	"forensiq/internal/parsers/usnjrnl"
	"forensiq/internal/parsers/mft"
	"forensiq/internal/parsers/prefetch"
	"forensiq/internal/parsers/registry"
	"forensiq/internal/parsers/shimcache"
)

// RouteAll maps a file path inside the ZIP to the list of parsers that handle it.
// Returns nil if the file should be skipped. SYSTEM hive returns two parsers
// (shimcache + registry) since both read from the same file.
func RouteAll(path string) []parsers.Parser {
	lower := strings.ToLower(filepath.ToSlash(path))
	base := strings.ToLower(filepath.Base(path))

	switch {
	case strings.HasSuffix(lower, ".evtx"):
		ch := channelFromPath(path)
		return []parsers.Parser{evtx.New(ch)}

	case strings.HasSuffix(lower, ".pf"):
		return []parsers.Parser{prefetch.New()}

	case base == "$mft" || base == "mft":
		return []parsers.Parser{mft.New()}

	case base == "amcache.hve":
		return []parsers.Parser{amcache.New()}

	// SYSTEM hive: parse both Shimcache and general registry values from same file.
	// Restrict to actual hive locations — many unrelated files are also named "system".
	case base == "system" && strings.Contains(lower, "/system32/config/"):
		return []parsers.Parser{shimcache.New(), registry.New("SYSTEM")}

	case base == "ntuser.dat":
		user := userFromPath(path)
		return []parsers.Parser{registry.New("NTUSER"), shellbags.New("NTUSER", user)}

	case base == "usrclass.dat":
		user := userFromPath(path)
		return []parsers.Parser{shellbags.New("UsrClass", user)}

	case base == "software" && strings.Contains(lower, "/system32/config/"):
		return []parsers.Parser{registry.New("SOFTWARE")}

	case strings.HasPrefix(base, "$i") && strings.Contains(lower, "recycle"):
		return []parsers.Parser{recyclebin.New(path)}

	case strings.HasSuffix(lower, ".automaticdestinations-ms"):
		return []parsers.Parser{jumplists.New(path)}

	case strings.HasSuffix(lower, ".customdestinations-ms"):
		return []parsers.Parser{jumplists.New(path)}

	case strings.HasSuffix(lower, ".lnk"):
		return []parsers.Parser{lnk.New(path)}

	case base == "history" && strings.Contains(lower, "chrome"):
		return []parsers.Parser{browser.New(path)}

	case base == "history" && strings.Contains(lower, "edge"):
		return []parsers.Parser{browser.New(path)}

	case base == "history" && (strings.Contains(lower, "brave") || strings.Contains(lower, "opera")):
		return []parsers.Parser{browser.New(path)}

	case base == "places.sqlite":
		return []parsers.Parser{browser.New(path)}

	case base == "history" && (strings.Contains(lower, "user data") || strings.Contains(lower, "appdata")):
		return []parsers.Parser{browser.New(path)}

	case base == "$j" || base == "usnjrnl_j" || base == "$usnjrnl_j" || base == "j":
		return []parsers.Parser{usnjrnl.New()}

	case base == "auth.log" || base == "secure" || base == "auth.log.1":
		return []parsers.Parser{linux.NewAuthLog()}

	case base == ".bash_history" || base == "bash_history":
		return []parsers.Parser{linux.NewShellHistory(userFromPath(path), "bash")}

	case base == ".zsh_history" || base == "zsh_history":
		return []parsers.Parser{linux.NewShellHistory(userFromPath(path), "zsh")}

	case base == "wtmp" || base == "wtmp.1":
		return []parsers.Parser{linux.NewWtmp("wtmp")}

	case base == "btmp" || base == "btmp.1":
		return []parsers.Parser{linux.NewWtmp("btmp")}

	case base == "authorized_keys":
		return []parsers.Parser{linux.NewPersistence("authorized_keys", path, userFromPath(path))}

	case base == "passwd" && strings.Contains(lower, "etc"):
		return []parsers.Parser{linux.NewPersistence("passwd", path, "")}

	case base == "sudoers":
		return []parsers.Parser{linux.NewPersistence("sudoers", path, "")}

	case base == "crontab" || strings.HasPrefix(base, "cron.") ||
		strings.Contains(lower, "/cron.d/") || strings.Contains(lower, "/crontabs/"):
		return []parsers.Parser{linux.NewPersistence("crontab", path, userFromPath(path))}

	default:
		return nil
	}
}

// Route maps a file path to a single parser (first match). Kept for compatibility.
func Route(path string) parsers.Parser {
	ps := RouteAll(path)
	if len(ps) == 0 {
		return nil
	}
	return ps[0]
}

// userFromPath tries to extract a username from a path like "home/alice/.bash_history".
func userFromPath(path string) string {
	parts := strings.Split(filepath.ToSlash(path), "/")
	for i, p := range parts {
		if (p == "home" || p == "Users") && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return filepath.Base(filepath.Dir(path))
}

// channelFromPath derives a short channel name from the EVTX filename.
// Examples:
//
//	"Security.evtx"                                    → "Security"
//	"Microsoft-Windows-Sysmon%4Operational.evtx"       → "Operational"
func channelFromPath(path string) string {
	base := filepath.Base(path)
	name := strings.TrimSuffix(base, filepath.Ext(base))
	if idx := strings.LastIndex(name, "%4"); idx >= 0 {
		return name[idx+2:]
	}
	return name
}

// walInjector is implemented by parsers that can consume a WAL file alongside the main DB.
type walInjector interface {
	SetWAL([]byte)
}

// ParseZIP opens zipPath and dispatches each recognized file to its parser(s).
// All parsed rows are inserted into db via each parser's Parse method.
// Progress events are forwarded to ch; a failure for one file does not abort others.
func ParseZIP(zipPath string, db *sql.DB, ch chan<- parsers.Progress) error {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("open zip: %w", err)
	}
	defer zr.Close()

	// Pass 1: collect SQLite WAL files (e.g. "History-wal") keyed by lowercase path.
	walMap := make(map[string][]byte)
	for _, f := range zr.File {
		if !strings.HasSuffix(strings.ToLower(f.Name), "-wal") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		data, _ := io.ReadAll(rc)
		rc.Close()
		walMap[strings.ToLower(f.Name)] = data
	}

	// Pass 2: parse main files, injecting WAL data where available.
	for _, f := range zr.File {
		ps := RouteAll(f.Name)
		if len(ps) == 0 {
			continue
		}

		if wal, ok := walMap[strings.ToLower(f.Name)+"-wal"]; ok {
			for _, p := range ps {
				if inj, ok := p.(walInjector); ok {
					inj.SetWAL(wal)
				}
			}
		}

		rc, err := f.Open()
		if err != nil {
			for _, p := range ps {
				ch <- parsers.Progress{Parser: p.Name(), Err: err, Done: true}
			}
			continue
		}

		if len(ps) == 1 {
			if parseErr := ps[0].Parse(rc, db, ch); parseErr != nil {
				ch <- parsers.Progress{Parser: ps[0].Name(), Err: parseErr, Done: true}
			}
		} else {
			// Multiple parsers need the same data: buffer it once, fan out.
			data, readErr := io.ReadAll(rc)
			if readErr != nil {
				for _, p := range ps {
					ch <- parsers.Progress{Parser: p.Name(), Err: readErr, Done: true}
				}
			} else {
				for _, p := range ps {
					if parseErr := p.Parse(bytes.NewReader(data), db, ch); parseErr != nil {
						ch <- parsers.Progress{Parser: p.Name(), Err: parseErr, Done: true}
					}
				}
			}
		}
		rc.Close()
	}
	return nil
}
