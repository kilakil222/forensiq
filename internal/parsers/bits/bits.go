// Package bits parses BITS (Background Intelligent Transfer Service) queue database (qmgr.db).
// qmgr.db is a JET Blue / ESE database. This parser reuses the ESE B-tree walking
// logic patterns established in the srum package.
package bits

import (
	"bytes"
	"database/sql"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"time"

	"forensiq/internal/parsers"
)

// ---- public API -------------------------------------------------------

// Parser implements parsers.Parser for qmgr.db.
type Parser struct{}

func New() *Parser { return &Parser{} }

func (p *Parser) Name() string { return "BITS/QmgrDB" }

func (p *Parser) Parse(r io.Reader, db *sql.DB, ch chan<- parsers.Progress) error {
	start := time.Now()

	data, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("bits: read: %w", err)
	}

	count, err := parseBITS(data, db)
	if err != nil {
		ch <- parsers.Progress{Parser: "BITS/QmgrDB", Err: err, Done: true, Elapsed: time.Since(start)}
		return err
	}
	ch <- parsers.Progress{Parser: "BITS/QmgrDB", Count: count, Done: true, Elapsed: time.Since(start)}
	return nil
}

// ---- ESE constants & types -------------------------------------------

const (
	pageHeaderSize = 40

	flagRoot   = 0x01
	flagLeaf   = 0x02
	flagParent = 0x04
)

// stateNames maps BITS job state integer to string.
var stateNames = []string{
	"Queued", "Connecting", "Transferring", "Suspended",
	"Error", "TransientError", "Transferred", "Acknowledged", "Cancelled",
}

func stateName(s int32) string {
	if s >= 0 && int(s) < len(stateNames) {
		return stateNames[s]
	}
	return fmt.Sprintf("State(%d)", s)
}

// formatGUID converts 16 raw ESE bytes (mixed-endian) to GUID string.
func formatGUID(b []byte) string {
	if len(b) < 16 {
		return ""
	}
	return fmt.Sprintf("{%08X-%04X-%04X-%04X-%012X}",
		binary.LittleEndian.Uint32(b[0:4]),
		binary.LittleEndian.Uint16(b[4:6]),
		binary.LittleEndian.Uint16(b[6:8]),
		b[8:10],
		b[10:16],
	)
}

// filetimeToTime converts a Windows FILETIME (100-ns ticks since 1601-01-01) to UTC time.Time.
func filetimeToTime(ft uint64) time.Time {
	if ft == 0 {
		return time.Time{}
	}
	const epochDiff = 116444736000000000
	if ft < epochDiff {
		return time.Time{}
	}
	nanos := int64(ft-epochDiff) * 100
	return time.Unix(0, nanos).UTC()
}

// ---- page reading helpers --------------------------------------------

type page struct {
	data     []byte
	size     int
	flags    uint32
	prevPage uint32
	nextPage uint32
	cpTag    uint16
}

func readPage(data []byte, pageSize int, pageNum uint32) (*page, error) {
	offset := int64(pageNum+1) * int64(pageSize)
	end := offset + int64(pageSize)
	if end > int64(len(data)) {
		return nil, fmt.Errorf("page %d out of bounds (file size %d)", pageNum, len(data))
	}
	pg := &page{
		data: data[offset:end],
		size: pageSize,
	}
	pg.flags = binary.LittleEndian.Uint32(pg.data[32:36])
	pg.prevPage = binary.LittleEndian.Uint32(pg.data[12:16])
	pg.nextPage = binary.LittleEndian.Uint32(pg.data[16:20])
	pg.cpTag = binary.LittleEndian.Uint16(pg.data[30:32])
	return pg, nil
}

type tag struct {
	size    uint16
	offset  uint16
	deleted bool
}

func pageTags(pg *page) []tag {
	if pg.cpTag == 0 {
		return nil
	}
	result := make([]tag, 0, pg.cpTag)
	pageEnd := len(pg.data)

	for i := 0; i < int(pg.cpTag); i++ {
		tagOff := pageEnd - (i+1)*4
		if tagOff < pageHeaderSize {
			break
		}
		word0 := binary.LittleEndian.Uint16(pg.data[tagOff:])
		word1 := binary.LittleEndian.Uint16(pg.data[tagOff+2:])

		cb := word0 & 0x1FFF
		flags := (word0 >> 13) & 0x3
		ib := word1 & 0x7FFF

		deleted := (flags & 0x2) != 0

		result = append(result, tag{
			size:    cb,
			offset:  ib,
			deleted: deleted,
		})
	}
	return result
}

func tagRecord(pg *page, idx int) []byte {
	tags := pageTags(pg)
	if idx >= len(tags) {
		return nil
	}
	t := tags[idx]
	if t.size == 0 {
		return nil
	}
	start := pageHeaderSize + int(t.offset)
	end := start + int(t.size)
	if end > len(pg.data)-int(pg.cpTag)*4 {
		return nil
	}
	if start < pageHeaderSize || end > len(pg.data) {
		return nil
	}
	return pg.data[start:end]
}

// ---- B-tree walker ---------------------------------------------------

func collectLeafRecords(data []byte, pageSize int, rootPageNum uint32) ([][]byte, error) {
	visited := make(map[uint32]bool)
	var records [][]byte

	var walk func(pn uint32) error
	walk = func(pn uint32) error {
		if pn == 0 || pn == 0xFFFFFFFF || visited[pn] {
			return nil
		}
		visited[pn] = true

		pg, err := readPage(data, pageSize, pn)
		if err != nil {
			return nil
		}

		isLeaf := (pg.flags & flagLeaf) != 0
		isParent := (pg.flags & flagParent) != 0

		if isLeaf {
			tags := pageTags(pg)
			for i := 1; i < len(tags); i++ {
				if tags[i].deleted {
					continue
				}
				rec := tagRecord(pg, i)
				if rec != nil && len(rec) > 0 {
					cp := make([]byte, len(rec))
					copy(cp, rec)
					records = append(records, cp)
				}
			}
			if pg.nextPage != 0 && pg.nextPage != 0xFFFFFFFF {
				_ = walk(pg.nextPage)
			}
			return nil
		}

		if isParent {
			tags := pageTags(pg)
			for i := 1; i < len(tags); i++ {
				if tags[i].deleted {
					continue
				}
				rec := tagRecord(pg, i)
				if rec == nil || len(rec) < 4 {
					continue
				}
				childPage := binary.LittleEndian.Uint32(rec[len(rec)-4:])
				if childPage != 0 && childPage != 0xFFFFFFFF {
					_ = walk(childPage)
				}
			}
			if len(tags) > 0 {
				rec := tagRecord(pg, 0)
				if rec != nil && len(rec) >= 4 {
					childPage := binary.LittleEndian.Uint32(rec[len(rec)-4:])
					if childPage != 0 && childPage != 0xFFFFFFFF {
						_ = walk(childPage)
					}
				}
			}
			return nil
		}

		if (pg.flags & flagRoot) != 0 {
			tags := pageTags(pg)
			for i := 1; i < len(tags); i++ {
				if tags[i].deleted {
					continue
				}
				rec := tagRecord(pg, i)
				if rec != nil && len(rec) > 0 {
					cp := make([]byte, len(rec))
					copy(cp, rec)
					records = append(records, cp)
				}
			}
		}
		return nil
	}

	if err := walk(rootPageNum); err != nil {
		return nil, err
	}
	return records, nil
}

// ---- ESE record decoder ----------------------------------------------

type recordHeader struct {
	lastFixed    uint16
	lastVariable uint16
	varDataStart uint16
}

func decodeRecordHeader(rec []byte) (recordHeader, error) {
	if len(rec) < 6 {
		return recordHeader{}, fmt.Errorf("record too short: %d", len(rec))
	}
	return recordHeader{
		lastFixed:    binary.LittleEndian.Uint16(rec[0:2]),
		lastVariable: binary.LittleEndian.Uint16(rec[2:4]),
		varDataStart: binary.LittleEndian.Uint16(rec[4:6]),
	}, nil
}

func extractFixedCols(rec []byte, colSizes []int) [][]byte {
	hdr, err := decodeRecordHeader(rec)
	if err != nil {
		return nil
	}
	lastFixed := int(hdr.lastFixed)
	if lastFixed > len(colSizes) {
		lastFixed = len(colSizes)
	}

	out := make([][]byte, lastFixed)
	pos := 6
	for i := 0; i < lastFixed; i++ {
		sz := colSizes[i]
		if pos+sz > len(rec) {
			break
		}
		cp := make([]byte, sz)
		copy(cp, rec[pos:pos+sz])
		out[i] = cp
		pos += sz
	}
	return out
}

func extractVariableCol(rec []byte, fixedColSizes []int, varColIdx int) []byte {
	hdr, err := decodeRecordHeader(rec)
	if err != nil {
		return nil
	}
	if hdr.lastVariable == 0x7f || hdr.lastVariable == 0 {
		return nil
	}

	lastFixed := int(hdr.lastFixed)
	if lastFixed > len(fixedColSizes) {
		lastFixed = len(fixedColSizes)
	}

	fixedEnd := 6
	for i := 0; i < lastFixed; i++ {
		fixedEnd += fixedColSizes[i]
	}

	lastVar := int(hdr.lastVariable)
	numVarCols := lastVar
	if numVarCols <= 0 || numVarCols > 64 {
		return nil
	}

	offTableStart := fixedEnd
	offTableEnd := offTableStart + numVarCols*2
	if offTableEnd > len(rec) {
		return nil
	}

	varDataBase := int(hdr.varDataStart)
	if varDataBase < offTableEnd || varDataBase > len(rec) {
		varDataBase = offTableEnd
	}

	if varColIdx < 1 || varColIdx > numVarCols {
		return nil
	}

	endOff := int(binary.LittleEndian.Uint16(rec[offTableStart+(varColIdx-1)*2:])) & 0x7FFF
	var startOff int
	if varColIdx == 1 {
		startOff = 0
	} else {
		startOff = int(binary.LittleEndian.Uint16(rec[offTableStart+(varColIdx-2)*2:])) & 0x7FFF
	}

	absStart := varDataBase + startOff
	absEnd := varDataBase + endOff

	if absStart < 0 || absEnd > len(rec) || absStart >= absEnd {
		return nil
	}
	cp := make([]byte, absEnd-absStart)
	copy(cp, rec[absStart:absEnd])
	return cp
}

// ---- Catalog parsing -------------------------------------------------

func parseCatalog(data []byte, pageSize int) map[string]uint32 {
	const catalogPage = 4
	tables := make(map[string]uint32)

	records, err := collectLeafRecords(data, pageSize, catalogPage)
	if err != nil {
		return tables
	}

	// Catalog fixed column layout (same as srum):
	// 1: ObjidTable (Long 4), 2: Type (Short 2), 3: Id (Long 4),
	// 4: ColtypOrPgnoFDP (Long 4), 5: SpaceUsage (Long 4), 6: Flags (Long 4),
	// 7: PagesOrLocale (Long 4), 8: RootFlag (Bit 1), 9: RecordOffset (Short 2),
	// 10: LCMapFlags (Long 4), 11: KeyMost (UShort 2), 12: LVChunkMax (Long 4)
	catFixedSizes := []int{4, 2, 4, 4, 4, 4, 4, 1, 2, 4, 2, 4}

	for _, rec := range records {
		func() {
			defer func() { recover() }() //nolint

			cols := extractFixedCols(rec, catFixedSizes)
			if len(cols) < 4 || cols[1] == nil || cols[3] == nil {
				return
			}

			recType := binary.LittleEndian.Uint16(cols[1])
			if recType != 1 {
				return
			}

			rootPage := binary.LittleEndian.Uint32(cols[3])

			nameBytes := extractVariableCol(rec, catFixedSizes, 1)
			if nameBytes == nil {
				return
			}

			name := strings.TrimRight(string(nameBytes), "\x00")
			if name == "" {
				return
			}

			tables[name] = rootPage
		}()
	}
	return tables
}

func findTablePage(tables map[string]uint32, targetName string) (uint32, bool) {
	lower := strings.ToLower(targetName)
	for name, page := range tables {
		if strings.ToLower(name) == lower {
			return page, true
		}
	}
	return 0, false
}

// ---- BITS fixed column layouts ---------------------------------------

// bitsJobFixedSizes: Id(16), JobType(4), State(4), Priority(4),
// CreationTime(8), ModificationTime(8), CompletionTime(8)
// Text columns (Name, Description, Owner) are variable.
var bitsJobFixedSizes = []int{16, 4, 4, 4, 8, 8, 8}

// bitsFileFixedSizes: Id(16), JobId(16), BytesTotal(8), BytesTransferred(8)
// Text columns (RemoteName, LocalName) are variable.
var bitsFileFixedSizes = []int{16, 16, 8, 8}

// ---- BITS job record decoder -----------------------------------------

type bitsJob struct {
	jobGUID     string
	jobType     int32
	state       int32
	priority    int32
	createdAt   time.Time
	modifiedAt  time.Time
	completedAt time.Time
	name        string
	description string
	owner       string
}

func decodeBITSJob(rec []byte) (bitsJob, bool) {
	defer func() { recover() }() //nolint

	cols := extractFixedCols(rec, bitsJobFixedSizes)

	var j bitsJob

	// Col 1: Id (GUID, 16 bytes)
	if len(cols) > 0 && cols[0] != nil && len(cols[0]) == 16 {
		j.jobGUID = formatGUID(cols[0])
	}
	// Col 2: JobType (4 bytes)
	if len(cols) > 1 && cols[1] != nil && len(cols[1]) == 4 {
		j.jobType = int32(binary.LittleEndian.Uint32(cols[1]))
	}
	// Col 3: State (4 bytes)
	if len(cols) > 2 && cols[2] != nil && len(cols[2]) == 4 {
		j.state = int32(binary.LittleEndian.Uint32(cols[2]))
	}
	// Col 4: Priority (4 bytes)
	if len(cols) > 3 && cols[3] != nil && len(cols[3]) == 4 {
		j.priority = int32(binary.LittleEndian.Uint32(cols[3]))
	}
	// Col 5: CreationTime (FILETIME, 8 bytes)
	if len(cols) > 4 && cols[4] != nil && len(cols[4]) == 8 {
		ft := binary.LittleEndian.Uint64(cols[4])
		j.createdAt = filetimeToTime(ft)
	}
	// Col 6: ModificationTime (FILETIME, 8 bytes)
	if len(cols) > 5 && cols[5] != nil && len(cols[5]) == 8 {
		ft := binary.LittleEndian.Uint64(cols[5])
		j.modifiedAt = filetimeToTime(ft)
	}
	// Col 7: CompletionTime (FILETIME, 8 bytes)
	if len(cols) > 6 && cols[6] != nil && len(cols[6]) == 8 {
		ft := binary.LittleEndian.Uint64(cols[6])
		j.completedAt = filetimeToTime(ft)
	}

	// Variable cols: 1=Name, 2=Description, 3=Owner
	if b := extractVariableCol(rec, bitsJobFixedSizes, 1); b != nil {
		j.name = strings.TrimRight(string(b), "\x00")
	}
	if b := extractVariableCol(rec, bitsJobFixedSizes, 2); b != nil {
		j.description = strings.TrimRight(string(b), "\x00")
	}
	if b := extractVariableCol(rec, bitsJobFixedSizes, 3); b != nil {
		j.owner = strings.TrimRight(string(b), "\x00")
	}

	if j.jobGUID == "" {
		return bitsJob{}, false
	}
	return j, true
}

// ---- BITS file record decoder ----------------------------------------

type bitsFile struct {
	fileGUID   string
	jobGUID    string
	remoteName string
	localName  string
	bytesTotal int64
	bytesXfer  int64
}

func decodeBITSFile(rec []byte) (bitsFile, bool) {
	defer func() { recover() }() //nolint

	cols := extractFixedCols(rec, bitsFileFixedSizes)

	var f bitsFile

	// Col 1: Id (GUID, 16 bytes)
	if len(cols) > 0 && cols[0] != nil && len(cols[0]) == 16 {
		f.fileGUID = formatGUID(cols[0])
	}
	// Col 2: JobId (GUID, 16 bytes)
	if len(cols) > 1 && cols[1] != nil && len(cols[1]) == 16 {
		f.jobGUID = formatGUID(cols[1])
	}
	// Col 3: BytesTotal (8 bytes) — NOTE: in some schemas this comes after variable cols
	// We try fixed first; fallback is handled in fallback scanner
	if len(cols) > 2 && cols[2] != nil && len(cols[2]) == 8 {
		f.bytesTotal = int64(binary.LittleEndian.Uint64(cols[2]))
	}
	// Col 4: BytesTransferred (8 bytes)
	if len(cols) > 3 && cols[3] != nil && len(cols[3]) == 8 {
		f.bytesXfer = int64(binary.LittleEndian.Uint64(cols[3]))
	}

	// Variable cols: 1=RemoteName, 2=LocalName
	if b := extractVariableCol(rec, bitsFileFixedSizes, 1); b != nil {
		f.remoteName = strings.TrimRight(string(b), "\x00")
	}
	if b := extractVariableCol(rec, bitsFileFixedSizes, 2); b != nil {
		f.localName = strings.TrimRight(string(b), "\x00")
	}

	// If no fixed GUIDs but variable cols look like URLs, do a URL-scan fallback
	if f.fileGUID == "" && f.remoteName == "" {
		return bitsFile{}, false
	}
	return f, true
}

// ---- Fallback: scan all leaf pages for URL-like records ---------------

// isHTTPURL returns true if the byte slice starts with http:// or https://
func isHTTPURL(b []byte) bool {
	s := strings.ToLower(string(b))
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
}

// scanAllLeafPagesForURLs walks every page in the file looking for leaf pages
// that contain readable http/https strings — used as fallback when catalog fails.
func scanAllLeafPagesForURLs(data []byte, pageSize int) []bitsFile {
	totalPages := len(data)/pageSize - 1
	if totalPages <= 0 {
		return nil
	}

	var results []bitsFile
	seen := make(map[string]bool)

	for pn := uint32(0); pn < uint32(totalPages); pn++ {
		pg, err := readPage(data, pageSize, pn)
		if err != nil {
			continue
		}
		if (pg.flags&flagLeaf) == 0 {
			continue
		}

		tags := pageTags(pg)
		for i := 1; i < len(tags); i++ {
			if tags[i].deleted {
				continue
			}
			rec := tagRecord(pg, i)
			if rec == nil || len(rec) < 20 {
				continue
			}

			// Scan for http:// or https:// within the record bytes
			idx := bytes.Index(rec, []byte("http"))
			if idx < 0 {
				continue
			}

			urlBytes := rec[idx:]
			// Find end of URL (null terminator or control char)
			end := 0
			for end < len(urlBytes) {
				c := urlBytes[end]
				if c == 0 || c < 0x20 {
					break
				}
				end++
			}
			if end < 8 {
				continue
			}

			url := string(urlBytes[:end])
			if !isHTTPURL(urlBytes[:end]) {
				continue
			}
			if seen[url] {
				continue
			}
			seen[url] = true

			// Try to extract a local path following the URL (after null)
			var localPath string
			if idx+end+1 < len(rec) {
				rest := rec[idx+end+1:]
				for j := 0; j < len(rest); j++ {
					if rest[j] < 0x20 || rest[j] > 0x7e {
						if j > 4 {
							localPath = string(rest[:j])
						}
						break
					}
				}
			}

			results = append(results, bitsFile{
				remoteName: url,
				localName:  localPath,
			})
		}
	}
	return results
}

// ---- Main BITS parser ------------------------------------------------

func parseBITS(data []byte, db *sql.DB) (int64, error) {
	if len(data) < 240 {
		return 0, fmt.Errorf("bits: file too short")
	}

	pageSize := int(binary.LittleEndian.Uint32(data[236:240]))
	if pageSize == 0 || pageSize&(pageSize-1) != 0 || pageSize < 4096 {
		pageSize = 8192
	}

	catalog := parseCatalog(data, pageSize)

	// Try known table names for different Windows versions
	jobTableNames := []string{"BITS_JOB", "Jobs", "BITSJob", "Job"}
	fileTableNames := []string{"BITS_FILE", "Files", "BITSFile", "File"}

	var jobPage, filePage uint32
	for _, name := range jobTableNames {
		if pg, ok := findTablePage(catalog, name); ok && pg > 0 {
			jobPage = pg
			break
		}
	}
	for _, name := range fileTableNames {
		if pg, ok := findTablePage(catalog, name); ok && pg > 0 {
			filePage = pg
			break
		}
	}

	var totalCount int64

	// ---- Insert jobs ----
	if jobPage > 0 {
		count, err := insertBITSJobs(data, pageSize, jobPage, db)
		if err == nil {
			totalCount += count
		}
	}

	// ---- Insert files ----
	if filePage > 0 {
		count, err := insertBITSFiles(data, pageSize, filePage, db)
		if err == nil {
			totalCount += count
		}
	}

	// ---- Fallback: scan all leaf pages when catalog-based approach found nothing ----
	if filePage == 0 || totalCount == 0 {
		fallbackFiles := scanAllLeafPagesForURLs(data, pageSize)
		if len(fallbackFiles) > 0 {
			count, err := insertBITSFilesDirect(fallbackFiles, db)
			if err == nil {
				totalCount += count
			}
		}
	}

	return totalCount, nil
}

func insertBITSJobs(data []byte, pageSize int, rootPage uint32, db *sql.DB) (int64, error) {
	records, err := collectLeafRecords(data, pageSize, rootPage)
	if err != nil {
		return 0, err
	}

	tx, err := db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback() //nolint

	stmt, err := tx.Prepare(`INSERT INTO bits_jobs
		(job_guid, job_name, job_type, state, state_name, priority, owner, created_at, modified_at, completed_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	var count int64
	for _, rec := range records {
		func() {
			defer func() { recover() }() //nolint

			job, ok := decodeBITSJob(rec)
			if !ok {
				return
			}

			sn := stateName(job.state)

			var createdAt, modifiedAt, completedAt interface{}
			if !job.createdAt.IsZero() {
				createdAt = job.createdAt
			}
			if !job.modifiedAt.IsZero() {
				modifiedAt = job.modifiedAt
			}
			if !job.completedAt.IsZero() {
				completedAt = job.completedAt
			}

			_, err := stmt.Exec(
				job.jobGUID, job.name, job.jobType, job.state, sn,
				job.priority, job.owner, createdAt, modifiedAt, completedAt,
			)
			if err == nil {
				count++
			}
		}()
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return count, nil
}

func insertBITSFiles(data []byte, pageSize int, rootPage uint32, db *sql.DB) (int64, error) {
	records, err := collectLeafRecords(data, pageSize, rootPage)
	if err != nil {
		return 0, err
	}

	tx, err := db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback() //nolint

	stmt, err := tx.Prepare(`INSERT INTO bits_files
		(job_guid, file_guid, remote_url, local_path, bytes_total, bytes_xferred, pct_complete)
		VALUES (?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	var count int64
	for _, rec := range records {
		func() {
			defer func() { recover() }() //nolint

			f, ok := decodeBITSFile(rec)
			if !ok {
				return
			}

			var pct float64
			if f.bytesTotal > 0 {
				pct = float64(f.bytesXfer) / float64(f.bytesTotal) * 100.0
			}

			_, err := stmt.Exec(
				f.jobGUID, f.fileGUID, f.remoteName, f.localName,
				f.bytesTotal, f.bytesXfer, pct,
			)
			if err == nil {
				count++
			}
		}()
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return count, nil
}

func insertBITSFilesDirect(files []bitsFile, db *sql.DB) (int64, error) {
	tx, err := db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback() //nolint

	stmt, err := tx.Prepare(`INSERT INTO bits_files
		(job_guid, file_guid, remote_url, local_path, bytes_total, bytes_xferred, pct_complete)
		VALUES (?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	var count int64
	for _, f := range files {
		var pct float64
		if f.bytesTotal > 0 {
			pct = float64(f.bytesXfer) / float64(f.bytesTotal) * 100.0
		}
		_, err := stmt.Exec(
			f.jobGUID, f.fileGUID, f.remoteName, f.localName,
			f.bytesTotal, f.bytesXfer, pct,
		)
		if err == nil {
			count++
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return count, nil
}

// ensure bytes package is used
var _ = bytes.NewReader
