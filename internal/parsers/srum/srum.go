// Package srum parses SRUDB.dat (Windows System Resource Usage Monitor)
// by walking the raw ESE/JET Blue B-tree pages.
package srum

import (
	"bytes"
	"database/sql"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"forensiq/internal/parsers"
)

// ---- public API -------------------------------------------------------

// Parser implements parsers.Parser for SRUDB.dat.
type Parser struct{}

func New() *Parser { return &Parser{} }

func (p *Parser) Name() string { return "SRUM" }

func (p *Parser) Parse(r io.Reader, db *sql.DB, ch chan<- parsers.Progress) error {
	start := time.Now()

	data, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("srum: read: %w", err)
	}

	count, err := parseESE(data, db, ch, start)
	if err != nil {
		ch <- parsers.Progress{Parser: "SRUM", Err: err, Done: true, Elapsed: time.Since(start)}
		return err
	}
	ch <- parsers.Progress{Parser: "SRUM", Count: count, Done: true, Elapsed: time.Since(start)}
	return nil
}

// ---- ESE constants & types -------------------------------------------

const (
	pageHeaderSize = 40

	flagRoot   = 0x01
	flagLeaf   = 0x02
	flagParent = 0x04

	guidNetworkUsage = "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}"
	guidAppUsage     = "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA86}"
	tableIDMap       = "SruDbIdMapTable"
)

// filetimeToTime converts a Windows FILETIME (100-ns ticks since 1601-01-01)
// to a UTC time.Time.
func filetimeToTime(ft uint64) time.Time {
	if ft == 0 {
		return time.Time{}
	}
	const epochDiff = 116444736000000000 // 100-ns intervals from 1601 to 1970
	if ft < epochDiff {
		return time.Time{}
	}
	nanos := int64(ft-epochDiff) * 100
	return time.Unix(0, nanos).UTC()
}

// utf16leToString decodes a UTF-16LE byte slice to a Go string.
func utf16leToString(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	u16 := make([]uint16, len(b)/2)
	for i := range u16 {
		u16[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	runes := utf16.Decode(u16)
	var sb strings.Builder
	for _, r := range runes {
		if r == 0 {
			break
		}
		sb.WriteRune(r)
	}
	return sb.String()
}

// sidToString converts a binary SID blob to S-1-x-... notation.
func sidToString(b []byte) string {
	if len(b) < 8 {
		return ""
	}
	// revision
	revision := int(b[0])
	subAuthorityCount := int(b[1])
	if len(b) < 8+subAuthorityCount*4 {
		return ""
	}
	// identifier authority (6 bytes big-endian)
	var identAuth uint64
	for i := 2; i < 8; i++ {
		identAuth = identAuth<<8 | uint64(b[i])
	}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("S-%d-%d", revision, identAuth))
	for i := 0; i < subAuthorityCount; i++ {
		sa := binary.LittleEndian.Uint32(b[8+i*4:])
		sb.WriteString(fmt.Sprintf("-%d", sa))
	}
	return sb.String()
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
	// logical page N is at file offset (N+1)*pageSize
	offset := int64(pageNum+1) * int64(pageSize)
	end := offset + int64(pageSize)
	if end > int64(len(data)) {
		return nil, fmt.Errorf("page %d out of bounds (file size %d)", pageNum, len(data))
	}
	pg := &page{
		data: data[offset:end],
		size: pageSize,
	}
	// flags at header offset 32
	pg.flags = binary.LittleEndian.Uint32(pg.data[32:36])
	// previous page link at offset 12, next page link at offset 16
	pg.prevPage = binary.LittleEndian.Uint32(pg.data[12:16])
	pg.nextPage = binary.LittleEndian.Uint32(pg.data[16:20])
	// cpTag (tag count) at header offset 30
	pg.cpTag = binary.LittleEndian.Uint16(pg.data[30:32])
	return pg, nil
}

// tag holds the size and offset of a record within a page.
type tag struct {
	size    uint16
	offset  uint16 // relative to end of page header (page_start + pageHeaderSize)
	deleted bool
}

// pageTags returns the list of tags for a page (excluding tag 0 which is the header tag).
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

// tagRecord returns the raw record bytes for tag i (0-based, after tag 0).
// Tag 0 is always the page header tag; actual records start at tag index 1.
func tagRecord(pg *page, idx int) []byte {
	tags := pageTags(pg)
	// idx 0 → tags[0] (page header tag, caller skips it)
	// we return tags[idx]
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

// collectLeafRecords gathers all non-deleted records from the leaf pages
// reachable from rootPageNum via the B-tree.
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
			return nil // skip bad pages
		}

		isLeaf := (pg.flags & flagLeaf) != 0
		isParent := (pg.flags & flagParent) != 0

		if isLeaf {
			// Collect records from this leaf page
			tags := pageTags(pg)
			// Skip tag[0] (page header tag), start from index 1
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
			// Follow the leaf page chain
			if pg.nextPage != 0 && pg.nextPage != 0xFFFFFFFF {
				_ = walk(pg.nextPage)
			}
			return nil
		}

		if isParent {
			// Internal/parent page: each tag is a branch node whose last 4 bytes are the child page number
			tags := pageTags(pg)
			// Tag[0] on parent page is special — it's the "left-most" child pointer stored
			// in the page header tag; skip it or treat first real tag as tag[1].
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
			// Also check tag[0] for the left-most pointer
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

		// Root page that is also a leaf (small table)
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

// recordHeader holds the decoded 6-byte ESE record header.
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

// fixedColSizes returns the byte widths of fixed columns 1..N given the
// hardcoded layout for a specific table type.
// Returns nil for unknown types.
func fixedColSizesNetwork() []int {
	// Col 1..11: AutoIncId(4), TimeStamp(8), AppId(4), UserId(4),
	//            InterfaceLuid(8), L2ProfileId(4), L2ProfileFlags(4),
	//            BytesSent(8), BytesRecvd(8), PacketsSent(4), PacketsRecvd(4)
	return []int{4, 8, 4, 4, 8, 4, 4, 8, 8, 4, 4}
}

func fixedColSizesApp() []int {
	// Col 1..19: AutoIncId(4), TimeStamp(8), AppId(4), UserId(4),
	//            FgCycles(8), BgCycles(8), FaceTime(4),
	//            FgCtxSw(4), BgCtxSw(4),
	//            FgBytesRead(8), FgBytesWritten(8),
	//            FgNumRead(4), FgNumWrite(4), FgFlushes(4),
	//            BgBytesRead(8), BgBytesWritten(8),
	//            BgNumRead(4), BgNumWrite(4), BgFlushes(4)
	return []int{4, 8, 4, 4, 8, 8, 4, 4, 4, 8, 8, 4, 4, 4, 8, 8, 4, 4, 4}
}

func fixedColSizesIDMap() []int {
	// Col 1..2: IdIndex(4), IdType(1)
	return []int{4, 1}
}

// extractFixedCols reads fixed column values from a record.
// Returns a slice of raw byte slices, one per column (1-indexed by position).
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
	pos := 6 // after 6-byte record header
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

// extractVariableCol returns the bytes of variable column number varColIdx (1-based)
// from a record. Returns nil if not present.
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

	// Calculate where fixed data ends
	fixedEnd := 6
	for i := 0; i < lastFixed; i++ {
		fixedEnd += fixedColSizes[i]
	}

	// Variable column offset table starts right after fixed data
	lastVar := int(hdr.lastVariable)
	numVarCols := lastVar // variable columns are numbered from 128, but we index relative

	// Actually ESE variable columns start at column number 128 typically,
	// but SRUM uses them differently — the offset table is right after fixed columns.
	// Number of variable columns = lastVariable (their count)
	if numVarCols <= 0 || numVarCols > 64 {
		return nil
	}

	// Variable offset table: numVarCols uint16 entries
	offTableStart := fixedEnd
	offTableEnd := offTableStart + numVarCols*2
	if offTableEnd > len(rec) {
		return nil
	}

	// varDataStart from header indicates where var data actually begins in record
	varDataBase := int(hdr.varDataStart)
	if varDataBase < offTableEnd || varDataBase > len(rec) {
		// fall back to right after offset table
		varDataBase = offTableEnd
	}

	// Each entry is cumulative size up to and including that variable column
	if varColIdx < 1 || varColIdx > numVarCols {
		return nil
	}

	// Cumulative end of varColIdx column
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

// tableInfo records what we found in the ESE catalog for a table.
type tableInfo struct {
	name     string
	rootPage uint32
}

// parseCatalog reads the MSysObjects catalog (always at logical page 4)
// and returns a map of table-name → root page number.
func parseCatalog(data []byte, pageSize int) map[string]uint32 {
	const catalogPage = 4
	tables := make(map[string]uint32)

	records, err := collectLeafRecords(data, pageSize, catalogPage)
	if err != nil {
		return tables
	}

	// Catalog fixed column layout (hardcoded):
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

			// Type == 1 means table
			recType := binary.LittleEndian.Uint16(cols[1])
			if recType != 1 {
				return
			}

			// ColtypOrPgnoFDP is the root page number for tables
			rootPage := binary.LittleEndian.Uint32(cols[3])

			// Variable column 1 is the name
			nameBytes := extractVariableCol(rec, catFixedSizes, 1)
			if nameBytes == nil {
				return
			}

			// Name is stored as ASCII or UTF-8
			name := strings.TrimRight(string(nameBytes), "\x00")
			if name == "" {
				return
			}

			// Normalize GUID to uppercase for comparison
			upper := strings.ToUpper(name)
			_ = upper

			tables[name] = rootPage
		}()
	}
	return tables
}

// findTablePage scans the catalog for a table by name (case-insensitive).
func findTablePage(tables map[string]uint32, targetName string) (uint32, bool) {
	lower := strings.ToLower(targetName)
	for name, page := range tables {
		if strings.ToLower(name) == lower {
			return page, true
		}
	}
	return 0, false
}

// ---- ID Map ----------------------------------------------------------

type idMap struct {
	apps  map[int32]string
	users map[int32]string
}

func buildIDMap(data []byte, pageSize int, rootPage uint32) idMap {
	m := idMap{
		apps:  make(map[int32]string),
		users: make(map[int32]string),
	}

	records, err := collectLeafRecords(data, pageSize, rootPage)
	if err != nil {
		return m
	}

	idmapFixedSizes := fixedColSizesIDMap()

	for _, rec := range records {
		func() {
			defer func() { recover() }() //nolint

			cols := extractFixedCols(rec, idmapFixedSizes)
			if len(cols) < 2 || cols[0] == nil || cols[1] == nil {
				return
			}

			idIndex := int32(binary.LittleEndian.Uint32(cols[0]))
			idType := cols[1][0]

			// Variable column 1 (IdBlob) — 3rd overall column but 1st variable
			blob := extractVariableCol(rec, idmapFixedSizes, 1)
			if blob == nil {
				return
			}

			var name string
			if idType == 0 {
				// UTF-16LE app path
				name = utf16leToString(blob)
			} else {
				// Binary SID
				name = sidToString(blob)
				if name == "" {
					name = fmt.Sprintf("SID(%d)", idIndex)
				}
			}

			if idType == 1 {
				m.users[idIndex] = name
			} else {
				m.apps[idIndex] = name
			}
		}()
	}
	return m
}

// ---- Network Usage records ------------------------------------------

type networkRow struct {
	timestamp   time.Time
	appID       int32
	userID      int32
	ifaceLuid   int64
	l2ProfileID int32
	bytesSent   int64
	bytesRecvd  int64
}

func decodeNetworkRecord(rec []byte) (networkRow, bool) {
	cols := extractFixedCols(rec, fixedColSizesNetwork())
	if len(cols) < 9 {
		return networkRow{}, false
	}

	var row networkRow

	// Col 2: TimeStamp (FILETIME, 8 bytes) — index 1
	if cols[1] != nil && len(cols[1]) == 8 {
		ft := binary.LittleEndian.Uint64(cols[1])
		row.timestamp = filetimeToTime(ft)
	}
	// Col 3: AppId (4 bytes) — index 2
	if cols[2] != nil && len(cols[2]) == 4 {
		row.appID = int32(binary.LittleEndian.Uint32(cols[2]))
	}
	// Col 4: UserId (4 bytes) — index 3
	if cols[3] != nil && len(cols[3]) == 4 {
		row.userID = int32(binary.LittleEndian.Uint32(cols[3]))
	}
	// Col 5: InterfaceLuid (8 bytes) — index 4
	if cols[4] != nil && len(cols[4]) == 8 {
		row.ifaceLuid = int64(binary.LittleEndian.Uint64(cols[4]))
	}
	// Col 6: L2ProfileId (4 bytes) — index 5
	if cols[5] != nil && len(cols[5]) == 4 {
		row.l2ProfileID = int32(binary.LittleEndian.Uint32(cols[5]))
	}
	// Col 8: BytesSent (8 bytes) — index 7
	if len(cols) > 7 && cols[7] != nil && len(cols[7]) == 8 {
		row.bytesSent = int64(binary.LittleEndian.Uint64(cols[7]))
	}
	// Col 9: BytesRecvd (8 bytes) — index 8
	if len(cols) > 8 && cols[8] != nil && len(cols[8]) == 8 {
		row.bytesRecvd = int64(binary.LittleEndian.Uint64(cols[8]))
	}

	return row, true
}

// ---- App Usage records -----------------------------------------------

type appRow struct {
	timestamp          time.Time
	appID              int32
	userID             int32
	fgCycles           int64
	bgCycles           int64
	fgContextSwitches  int32
	bgContextSwitches  int32
	fgBytesRead        int64
	fgBytesWritten     int64
}

func decodeAppRecord(rec []byte) (appRow, bool) {
	cols := extractFixedCols(rec, fixedColSizesApp())
	if len(cols) < 4 {
		return appRow{}, false
	}

	var row appRow

	// Col 2: TimeStamp (index 1)
	if cols[1] != nil && len(cols[1]) == 8 {
		ft := binary.LittleEndian.Uint64(cols[1])
		row.timestamp = filetimeToTime(ft)
	}
	// Col 3: AppId (index 2)
	if cols[2] != nil && len(cols[2]) == 4 {
		row.appID = int32(binary.LittleEndian.Uint32(cols[2]))
	}
	// Col 4: UserId (index 3)
	if cols[3] != nil && len(cols[3]) == 4 {
		row.userID = int32(binary.LittleEndian.Uint32(cols[3]))
	}
	// Col 5: FgCycles (index 4)
	if len(cols) > 4 && cols[4] != nil && len(cols[4]) == 8 {
		row.fgCycles = int64(binary.LittleEndian.Uint64(cols[4]))
	}
	// Col 6: BgCycles (index 5)
	if len(cols) > 5 && cols[5] != nil && len(cols[5]) == 8 {
		row.bgCycles = int64(binary.LittleEndian.Uint64(cols[5]))
	}
	// Col 8: FgContextSwitches (index 7)
	if len(cols) > 7 && cols[7] != nil && len(cols[7]) == 4 {
		row.fgContextSwitches = int32(binary.LittleEndian.Uint32(cols[7]))
	}
	// Col 9: BgContextSwitches (index 8)
	if len(cols) > 8 && cols[8] != nil && len(cols[8]) == 4 {
		row.bgContextSwitches = int32(binary.LittleEndian.Uint32(cols[8]))
	}
	// Col 10: FgBytesRead (index 9)
	if len(cols) > 9 && cols[9] != nil && len(cols[9]) == 8 {
		row.fgBytesRead = int64(binary.LittleEndian.Uint64(cols[9]))
	}
	// Col 11: FgBytesWritten (index 10)
	if len(cols) > 10 && cols[10] != nil && len(cols[10]) == 8 {
		row.fgBytesWritten = int64(binary.LittleEndian.Uint64(cols[10]))
	}

	return row, true
}

// ---- Main ESE parser -------------------------------------------------

func parseESE(data []byte, db *sql.DB, ch chan<- parsers.Progress, start time.Time) (int64, error) {
	if len(data) < 240 {
		return 0, fmt.Errorf("srum: file too short")
	}

	// Page size at offset 236
	pageSize := int(binary.LittleEndian.Uint32(data[236:240]))
	if pageSize == 0 || pageSize&(pageSize-1) != 0 || pageSize < 4096 {
		pageSize = 8192 // default
	}

	// Parse catalog at logical page 4
	catalogTables := parseCatalog(data, pageSize)

	// Build ID map
	var ids idMap
	if idMapPage, ok := findTablePage(catalogTables, tableIDMap); ok && idMapPage > 0 {
		ids = buildIDMap(data, pageSize, idMapPage)
	} else {
		ids = idMap{
			apps:  make(map[int32]string),
			users: make(map[int32]string),
		}
	}

	var totalCount int64

	// ---- Network Usage ----
	if netPage, ok := findTablePage(catalogTables, guidNetworkUsage); ok && netPage > 0 {
		count, err := insertNetworkUsage(data, pageSize, netPage, ids, db)
		if err == nil {
			totalCount += count
			ch <- parsers.Progress{Parser: "SRUM/Network", Count: count, Elapsed: time.Since(start)}
		}
	} else {
		// Try case-insensitive GUID match
		for name, page := range catalogTables {
			upper := strings.ToUpper(name)
			if upper == strings.ToUpper(guidNetworkUsage) {
				count, err := insertNetworkUsage(data, pageSize, page, ids, db)
				if err == nil {
					totalCount += count
					ch <- parsers.Progress{Parser: "SRUM/Network", Count: count, Elapsed: time.Since(start)}
				}
				break
			}
		}
	}

	// ---- App Resource Usage ----
	if appPage, ok := findTablePage(catalogTables, guidAppUsage); ok && appPage > 0 {
		count, err := insertAppUsage(data, pageSize, appPage, ids, db)
		if err == nil {
			totalCount += count
			ch <- parsers.Progress{Parser: "SRUM/AppUsage", Count: count, Elapsed: time.Since(start)}
		}
	} else {
		for name, page := range catalogTables {
			upper := strings.ToUpper(name)
			if upper == strings.ToUpper(guidAppUsage) {
				count, err := insertAppUsage(data, pageSize, page, ids, db)
				if err == nil {
					totalCount += count
					ch <- parsers.Progress{Parser: "SRUM/AppUsage", Count: count, Elapsed: time.Since(start)}
				}
				break
			}
		}
	}

	return totalCount, nil
}

func insertNetworkUsage(data []byte, pageSize int, rootPage uint32, ids idMap, db *sql.DB) (int64, error) {
	records, err := collectLeafRecords(data, pageSize, rootPage)
	if err != nil {
		return 0, err
	}

	tx, err := db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback() //nolint

	stmt, err := tx.Prepare(`INSERT INTO srum_network_usage
		(timestamp, app_id, user_id, app_name, user_name, bytes_sent, bytes_recvd, iface_luid, l2_profile_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	var count int64
	for _, rec := range records {
		func() {
			defer func() { recover() }() //nolint

			row, ok := decodeNetworkRecord(rec)
			if !ok {
				return
			}

			appName := ids.apps[row.appID]
			userName := ids.users[row.userID]

			var ts interface{}
			if !row.timestamp.IsZero() {
				ts = row.timestamp
			}

			_, err := stmt.Exec(ts, row.appID, row.userID, appName, userName,
				row.bytesSent, row.bytesRecvd, row.ifaceLuid, row.l2ProfileID)
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

func insertAppUsage(data []byte, pageSize int, rootPage uint32, ids idMap, db *sql.DB) (int64, error) {
	records, err := collectLeafRecords(data, pageSize, rootPage)
	if err != nil {
		return 0, err
	}

	tx, err := db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback() //nolint

	stmt, err := tx.Prepare(`INSERT INTO srum_app_usage
		(timestamp, app_id, user_id, app_name, user_name,
		 fg_cycles, bg_cycles, fg_context_switches, bg_context_switches,
		 fg_bytes_read, fg_bytes_written)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	var count int64
	for _, rec := range records {
		func() {
			defer func() { recover() }() //nolint

			row, ok := decodeAppRecord(rec)
			if !ok {
				return
			}

			appName := ids.apps[row.appID]
			userName := ids.users[row.userID]

			var ts interface{}
			if !row.timestamp.IsZero() {
				ts = row.timestamp
			}

			_, err := stmt.Exec(ts, row.appID, row.userID, appName, userName,
				row.fgCycles, row.bgCycles, row.fgContextSwitches, row.bgContextSwitches,
				row.fgBytesRead, row.fgBytesWritten)
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

// ---- ensure utf8 package is used (utf16leToString uses it indirectly) --
var _ = utf8.RuneError
var _ = bytes.NewReader
