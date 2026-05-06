package browser

import (
	"database/sql"
	"io"
	"path/filepath"
	"strings"
	"time"

	"forensiq/internal/parsers"
)

type BrowserParser struct {
	filePath string
	walData  []byte
}

func New(filePath string) *BrowserParser { return &BrowserParser{filePath: filePath} }

func (p *BrowserParser) SetWAL(data []byte) { p.walData = data }
func (p *BrowserParser) Name() string    { return "Browser/History" }

var chromeEpoch = time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC)

func chromeMicrosToTime(v int64) time.Time {
	if v <= 0 {
		return time.Time{}
	}
	return chromeEpoch.Add(time.Duration(v) * time.Microsecond)
}

func (p *BrowserParser) detectBrowser() string {
	lower := strings.ToLower(filepath.ToSlash(p.filePath))
	switch {
	case strings.Contains(lower, "edge"):
		return "Edge"
	case strings.Contains(lower, "brave"):
		return "Brave"
	case strings.Contains(lower, "opera"):
		return "Opera"
	case strings.Contains(lower, "chrome"):
		return "Chrome"
	case strings.Contains(lower, "firefox") || strings.Contains(lower, "mozilla"):
		return "Firefox"
	default:
		return "Chrome"
	}
}

func (p *BrowserParser) detectProfile() string {
	slashed := filepath.ToSlash(p.filePath)
	return filepath.Base(filepath.Dir(slashed))
}

func downloadState(n int64) string {
	switch n {
	case 0:
		return "IN_PROGRESS"
	case 1:
		return "COMPLETE"
	case 2:
		return "CANCELLED"
	case 3:
		return "INTERRUPTED"
	case 4:
		return "MIXED"
	default:
		return "UNKNOWN"
	}
}

func (p *BrowserParser) Parse(r io.Reader, db *sql.DB, ch chan<- parsers.Progress) error {
	start := time.Now()

	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}

	sdb, err := openSQLiteBytes(data)
	if err != nil {
		return err
	}
	if len(p.walData) > 0 {
		sdb.applyWAL(p.walData)
	}

	browser := p.detectBrowser()
	profile := p.detectProfile()

	histStmt, err := db.Prepare(`INSERT INTO browser_history (browser, url, title, visit_time, visit_count, profile) VALUES (?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer histStmt.Close()

	dlStmt, err := db.Prepare(`INSERT INTO browser_downloads (browser, url, local_path, start_time, end_time, state) VALUES (?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer dlStmt.Close()

	var count int64

	if browser == "Firefox" {
		sdb.scanTable("moz_places", func(cols []sqliteValue) error {
			if len(cols) < 5 {
				return nil
			}
			url := colText(cols, 1)
			title := colText(cols, 2)
			visitCount := colInt(cols, 3)
			lastVisitRaw := colInt(cols, 4)
			var visitTime time.Time
			if lastVisitRaw > 0 {
				visitTime = time.Unix(lastVisitRaw/1000000, (lastVisitRaw%1000000)*1000).UTC()
			}
			histStmt.Exec(browser, url, title, nullableTime(visitTime), visitCount, profile)
			count++
			if count%1000 == 0 {
				ch <- parsers.Progress{Parser: p.Name(), Count: count}
			}
			return nil
		})
	} else {
		sdb.scanTable("urls", func(cols []sqliteValue) error {
			if len(cols) < 5 {
				return nil
			}
			url := colText(cols, 1)
			title := colText(cols, 2)
			visitCount := colInt(cols, 3)
			lastVisitRaw := colInt(cols, 4)
			visitTime := chromeMicrosToTime(lastVisitRaw)
			histStmt.Exec(browser, url, title, nullableTime(visitTime), visitCount, profile)
			count++
			if count%1000 == 0 {
				ch <- parsers.Progress{Parser: p.Name(), Count: count}
			}
			return nil
		})

		sdb.scanTable("downloads", func(cols []sqliteValue) error {
			if len(cols) < 8 {
				return nil
			}
			targetPath := colText(cols, 2)
			tabURL := colText(cols, 4)
			startRaw := colInt(cols, 5)
			endRaw := colInt(cols, 6)
			stateRaw := colInt(cols, 7)
			startTime := chromeMicrosToTime(startRaw)
			endTime := chromeMicrosToTime(endRaw)
			dlStmt.Exec(browser, tabURL, targetPath, nullableTime(startTime), nullableTime(endTime), downloadState(stateRaw))
			return nil
		})
	}

	ch <- parsers.Progress{Parser: p.Name(), Count: count, Done: true, Elapsed: time.Since(start)}
	return nil
}

func colText(cols []sqliteValue, i int) string {
	if i >= len(cols) {
		return ""
	}
	if cols[i].Kind == kindText {
		return cols[i].Text
	}
	return ""
}

func colInt(cols []sqliteValue, i int) int64 {
	if i >= len(cols) {
		return 0
	}
	if cols[i].Kind == kindInt {
		return cols[i].Int
	}
	return 0
}

func nullableTime(t time.Time) interface{} {
	if t.IsZero() {
		return nil
	}
	return t
}
