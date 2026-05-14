// Package ntds parses NTDS.dit (Active Directory database, ESE format)
// and enumerates domain user accounts. Hash extraction is NOT implemented
// (requires SYSKEY from SYSTEM hive). This parser focuses on account metadata.
package ntds

import (
	"database/sql"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf16"

	"forensiq/internal/parsers"
)

// Parser implements parsers.Parser for NTDS.dit.
type Parser struct{}

func New() *Parser { return &Parser{} }

func (p *Parser) Name() string { return "NTDS.dit" }

// ---- ESE constants -------------------------------------------------------

const (
	esePageHeaderSize = 40
	eseFlagRoot       = 0x01
	eseFlagLeaf       = 0x02
	eseFlagParent     = 0x04
)

// Known ATTribute column name prefixes in NTDS.dit datatable.
// These are the ESE column names (stored as ASCII in the catalog).
const (
	colSAMAccountName  = "ATTm590045" // sAMAccountName
	colObjectSid       = "ATTk589970" // objectSid (binary)
	colLastLogon       = "ATTq589876" // lastLogon (FILETIME)
	colBadPwdTime      = "ATTq590480" // badPasswordTime (FILETIME)
	colBadPwdCount     = "ATTl590197" // badPwdCount (integer)
	colUAC             = "ATTl589832" // userAccountControl (integer)
	colDescription     = "ATTm13"     // description
	colDisplayName     = "ATTm590478" // displayName
	colPwdLastSet      = "ATTq590468" // pwdLastSet (FILETIME)
	colAccountExpires  = "ATTq591520" // accountExpires (FILETIME)
	colIsDeleted       = "ATTb590126" // isDeleted (boolean)
)

// userAccountControl flags.
const (
	uacDisabled      = 0x0002
	uacPwdNotReqd    = 0x0020
	uacNormalAccount = 0x0200
	uacDontExpirePwd = 0x10000
	uacPwdExpired    = 0x800000
)

// ---- ESE page/tag helpers (mirrors srum.go) -----------------------------

type esePage struct {
	data     []byte
	size     int
	flags    uint32
	prevPage uint32
	nextPage uint32
	cpTag    uint16
}

func readESEPage(data []byte, pageSize int, pageNum uint32) (*esePage, error) {
	offset := int64(pageNum+1) * int64(pageSize)
	end := offset + int64(pageSize)
	if end > int64(len(data)) {
		return nil, fmt.Errorf("page %d out of bounds", pageNum)
	}
	pg := &esePage{
		data: data[offset:end],
		size: pageSize,
	}
	pg.flags = binary.LittleEndian.Uint32(pg.data[32:36])
	pg.prevPage = binary.LittleEndian.Uint32(pg.data[12:16])
	pg.nextPage = binary.LittleEndian.Uint32(pg.data[16:20])
	pg.cpTag = binary.LittleEndian.Uint16(pg.data[30:32])
	return pg, nil
}

type eseTag struct {
	size    uint16
	offset  uint16
	deleted bool
}

func esePageTags(pg *esePage) []eseTag {
	if pg.cpTag == 0 {
		return nil
	}
	result := make([]eseTag, 0, pg.cpTag)
	pageEnd := len(pg.data)
	for i := 0; i < int(pg.cpTag); i++ {
		tagOff := pageEnd - (i+1)*4
		if tagOff < esePageHeaderSize {
			break
		}
		word0 := binary.LittleEndian.Uint16(pg.data[tagOff:])
		word1 := binary.LittleEndian.Uint16(pg.data[tagOff+2:])
		cb := word0 & 0x1FFF
		flags := (word0 >> 13) & 0x3
		ib := word1 & 0x7FFF
		deleted := (flags & 0x2) != 0
		result = append(result, eseTag{size: cb, offset: ib, deleted: deleted})
	}
	return result
}

func eseTagRecord(pg *esePage, idx int) []byte {
	tags := esePageTags(pg)
	if idx >= len(tags) {
		return nil
	}
	t := tags[idx]
	if t.size == 0 {
		return nil
	}
	start := esePageHeaderSize + int(t.offset)
	end := start + int(t.size)
	if start < esePageHeaderSize || end > len(pg.data) {
		return nil
	}
	return pg.data[start:end]
}

// collectLeafRecords walks the B-tree from rootPageNum collecting leaf records.
func collectLeafRecords(data []byte, pageSize int, rootPageNum uint32) [][]byte {
	visited := make(map[uint32]bool)
	var records [][]byte

	var walk func(pn uint32)
	walk = func(pn uint32) {
		if pn == 0 || pn == 0xFFFFFFFF || visited[pn] {
			return
		}
		visited[pn] = true

		pg, err := readESEPage(data, pageSize, pn)
		if err != nil {
			return
		}

		isLeaf := (pg.flags & eseFlagLeaf) != 0
		isParent := (pg.flags & eseFlagParent) != 0

		if isLeaf {
			tags := esePageTags(pg)
			for i := 1; i < len(tags); i++ {
				if tags[i].deleted {
					continue
				}
				rec := eseTagRecord(pg, i)
				if rec != nil && len(rec) > 0 {
					cp := make([]byte, len(rec))
					copy(cp, rec)
					records = append(records, cp)
				}
			}
			if pg.nextPage != 0 && pg.nextPage != 0xFFFFFFFF {
				walk(pg.nextPage)
			}
			return
		}

		if isParent {
			tags := esePageTags(pg)
			for i := 1; i < len(tags); i++ {
				if tags[i].deleted {
					continue
				}
				rec := eseTagRecord(pg, i)
				if rec == nil || len(rec) < 4 {
					continue
				}
				childPage := binary.LittleEndian.Uint32(rec[len(rec)-4:])
				if childPage != 0 && childPage != 0xFFFFFFFF {
					walk(childPage)
				}
			}
			if len(tags) > 0 {
				rec := eseTagRecord(pg, 0)
				if rec != nil && len(rec) >= 4 {
					childPage := binary.LittleEndian.Uint32(rec[len(rec)-4:])
					if childPage != 0 && childPage != 0xFFFFFFFF {
						walk(childPage)
					}
				}
			}
			return
		}

		// Root-that-is-also-leaf (small table).
		if (pg.flags & eseFlagRoot) != 0 {
			tags := esePageTags(pg)
			for i := 1; i < len(tags); i++ {
				if tags[i].deleted {
					continue
				}
				rec := eseTagRecord(pg, i)
				if rec != nil && len(rec) > 0 {
					cp := make([]byte, len(rec))
					copy(cp, rec)
					records = append(records, cp)
				}
			}
		}
	}

	walk(rootPageNum)
	return records
}

// ---- Catalog parsing ----------------------------------------------------

// columnInfo holds what we need from a catalog column entry for datatable.
type columnInfo struct {
	colID   uint32
	colType uint16
	colIdx  int // 0-based position among fixed/variable columns
}

// catalogEntry represents one row from MSysObjects.
type catalogEntry struct {
	objidTable uint32
	recType    uint16 // 1=table, 2=column, 3=index
	colID      uint32 // for columns: the column ID (FDPgno for tables)
	colType    uint16 // for columns: ESE column type
	rootPage   uint32 // for tables: root page
	name       string
}

// ESE fixed column sizes in MSysObjects (catalog).
// 1:ObjidTable(4), 2:Type(2), 3:Id(4), 4:ColtypOrPgnoFDP(4),
// 5:SpaceUsage(4), 6:Flags(4), 7:PagesOrLocale(4), 8:RootFlag(1),
// 9:RecordOffset(2), 10:LCMapFlags(4), 11:KeyMost(2), 12:LVChunkMax(4)
var catFixedSizes = []int{4, 2, 4, 4, 4, 4, 4, 1, 2, 4, 2, 4}

func parseCatalog(data []byte, pageSize int) (tableRootPages map[string]uint32, tableColumns map[string][]catalogEntry) {
	tableRootPages = make(map[string]uint32)
	tableColumns = make(map[string][]catalogEntry)

	const catalogPage = 4
	records := collectLeafRecords(data, pageSize, catalogPage)

	// Track table ObjidTable → name mapping.
	tableObjid := make(map[uint32]string) // objid → table name

	// Pass 1: find tables.
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
			objidTable := binary.LittleEndian.Uint32(cols[0])
			rootPage := binary.LittleEndian.Uint32(cols[3])

			nameBytes := extractVariableCol(rec, catFixedSizes, 1)
			if nameBytes == nil {
				return
			}
			name := strings.TrimRight(string(nameBytes), "\x00")
			if name == "" {
				return
			}
			tableRootPages[name] = rootPage
			tableObjid[objidTable] = name
		}()
	}

	// Pass 2: find columns and associate them with tables.
	for _, rec := range records {
		func() {
			defer func() { recover() }() //nolint

			cols := extractFixedCols(rec, catFixedSizes)
			if len(cols) < 4 || cols[1] == nil {
				return
			}
			recType := binary.LittleEndian.Uint16(cols[1])
			if recType != 2 { // 2 = column
				return
			}

			objidTable := binary.LittleEndian.Uint32(cols[0])
			tableName, ok := tableObjid[objidTable]
			if !ok {
				return
			}

			colID := uint32(0)
			if cols[2] != nil && len(cols[2]) == 4 {
				colID = binary.LittleEndian.Uint32(cols[2])
			}
			colType := uint16(0)
			if cols[3] != nil && len(cols[3]) == 4 {
				// ColtypOrPgnoFDP stores the column type as a 4-byte value.
				colType = uint16(binary.LittleEndian.Uint32(cols[3]))
			}

			nameBytes := extractVariableCol(rec, catFixedSizes, 1)
			if nameBytes == nil {
				return
			}
			name := strings.TrimRight(string(nameBytes), "\x00")
			if name == "" {
				return
			}

			tableColumns[tableName] = append(tableColumns[tableName], catalogEntry{
				objidTable: objidTable,
				recType:    recType,
				colID:      colID,
				colType:    colType,
				name:       name,
			})
		}()
	}
	return
}

// ---- ESE record decoding ------------------------------------------------

// ESE record header: lastFixed(2), lastVariable(2), varDataStart(2).
func extractFixedCols(rec []byte, colSizes []int) [][]byte {
	if len(rec) < 6 {
		return nil
	}
	lastFixed := int(binary.LittleEndian.Uint16(rec[0:2]))
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
	if len(rec) < 6 {
		return nil
	}
	lastFixed := int(binary.LittleEndian.Uint16(rec[0:2]))
	lastVariable := int(binary.LittleEndian.Uint16(rec[2:4]))
	varDataStart := int(binary.LittleEndian.Uint16(rec[4:6]))

	if lastVariable == 0x7f || lastVariable == 0 {
		return nil
	}
	if lastFixed > len(fixedColSizes) {
		lastFixed = len(fixedColSizes)
	}

	fixedEnd := 6
	for i := 0; i < lastFixed; i++ {
		fixedEnd += fixedColSizes[i]
	}

	numVarCols := lastVariable
	if numVarCols <= 0 || numVarCols > 128 {
		return nil
	}

	offTableStart := fixedEnd
	offTableEnd := offTableStart + numVarCols*2
	if offTableEnd > len(rec) {
		return nil
	}

	varDataBase := varDataStart
	if varDataBase < offTableEnd || varDataBase > len(rec) {
		varDataBase = offTableEnd
	}

	if varColIdx < 1 || varColIdx > numVarCols {
		return nil
	}

	endOff := int(binary.LittleEndian.Uint16(rec[offTableStart+(varColIdx-1)*2:])) & 0x7FFF
	startOff := 0
	if varColIdx > 1 {
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

// ---- NTDS-specific helpers ----------------------------------------------

// filetimeToTime converts Windows FILETIME to UTC time.Time.
func filetimeToTime(ft uint64) time.Time {
	if ft == 0 || ft == 0x7FFFFFFFFFFFFFFF {
		return time.Time{}
	}
	const epochDiff = 116444736000000000
	if ft < epochDiff {
		return time.Time{}
	}
	nanos := int64(ft-epochDiff) * 100
	t := time.Unix(0, nanos).UTC()
	// Sanity check: must be in realistic range.
	if t.Year() < 1970 || t.Year() > 2100 {
		return time.Time{}
	}
	return t
}

// sidToString converts a binary SID to S-1-x-... notation.
func sidToString(b []byte) string {
	if len(b) < 8 {
		return ""
	}
	revision := b[0]
	subCount := int(b[1])
	authority := uint64(b[2])<<40 | uint64(b[3])<<32 | uint64(b[4])<<24 |
		uint64(b[5])<<16 | uint64(b[6])<<8 | uint64(b[7])
	s := fmt.Sprintf("S-%d-%d", revision, authority)
	if len(b) < 8+subCount*4 {
		return s
	}
	for i := 0; i < subCount; i++ {
		sub := binary.LittleEndian.Uint32(b[8+i*4:])
		s += fmt.Sprintf("-%d", sub)
	}
	return s
}

// utf16leToString decodes UTF-16LE bytes to a Go string.
func utf16leToString(b []byte) string {
	if len(b) < 2 {
		return ""
	}
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

// ---- Column layout for datatable ----------------------------------------

// We use a simplified approach: build a fixed-size column layout from the catalog,
// then use offsets to decode each record. Since NTDS.dit column types are well-known,
// we map ATT* column names to their ESE column type and decode accordingly.

// ESE column types relevant to us.
const (
	eseColTypeBit       = 1  // boolean
	eseColTypeLong      = 7  // int32
	eseColTypeLongLong  = 8  // int64
	eseColTypeText      = 10 // variable length text (UTF-16LE for Unicode columns)
	eseColTypeBinary    = 11 // variable length binary
	eseColTypeUnicode   = 12 // variable length unicode (UTF-16LE)
)

// knownColumns is our target set of column names and their ESE types.
var knownColumns = map[string]int{
	colSAMAccountName: eseColTypeUnicode,
	colObjectSid:      eseColTypeBinary,
	colLastLogon:      eseColTypeLongLong,
	colBadPwdTime:     eseColTypeLongLong,
	colBadPwdCount:    eseColTypeLong,
	colUAC:            eseColTypeLong,
	colDescription:    eseColTypeUnicode,
	colDisplayName:    eseColTypeUnicode,
	colPwdLastSet:     eseColTypeLongLong,
	colAccountExpires: eseColTypeLongLong,
	colIsDeleted:      eseColTypeBit,
}

// ---- Simplified datatable record decoder --------------------------------

// We use a pragmatic scan approach: instead of reconstructing the full ESE
// column layout (which requires tracking fixed/variable/tagged columns),
// we scan datatable records for readable UTF-16LE strings that look like
// usernames (for sAMAccountName) and binary SID blobs.

type accountRow struct {
	samAccountName string
	displayName    string
	description    string
	objectSid      string
	lastLogon      time.Time
	pwdLastSet     time.Time
	badPwdCount    int32
	accountFlags   int32
	isDisabled     bool
	isDeleted      bool
	pwdNeverExpires bool
	noPwdRequired  bool
}

// scanRecordForAccount performs a pragmatic scan of an ESE datatable record.
// It looks for UTF-16LE strings and SID blobs by pattern matching.
func scanRecordForAccount(rec []byte) (accountRow, bool) {
	var row accountRow

	// Scan for SID blob: starts with 0x01 (revision), then sub-authority count,
	// then 6-byte authority, then sub-authorities (4 bytes each).
	// Domain user SIDs are typically 28 bytes: S-1-5-21-X-X-X-RID.
	sidFound := false
	for i := 0; i+8 <= len(rec); i++ {
		if rec[i] == 0x01 && rec[i+1] >= 1 && rec[i+1] <= 15 {
			subCount := int(rec[i+1])
			sidLen := 8 + subCount*4
			if i+sidLen <= len(rec) {
				// Check identifier authority == 5 (NT Authority).
				auth := uint64(rec[i+2])<<40 | uint64(rec[i+3])<<32 | uint64(rec[i+4])<<24 |
					uint64(rec[i+5])<<16 | uint64(rec[i+6])<<8 | uint64(rec[i+7])
				if auth == 5 && subCount >= 2 {
					sid := sidToString(rec[i : i+sidLen])
					if sid != "" {
						row.objectSid = sid
						sidFound = true
						break
					}
				}
			}
		}
	}

	// Scan for UTF-16LE strings.
	var strings16 []string
	i := 0
	for i+3 < len(rec) {
		lo := rec[i]
		hi := rec[i+1]
		if hi == 0x00 && lo >= 0x20 && lo <= 0x7E {
			// Start of a potential UTF-16LE string.
			j := i
			var chars []uint16
			for j+1 < len(rec) {
				c := binary.LittleEndian.Uint16(rec[j:])
				if c == 0 {
					break
				}
				// Allow printable BMP characters.
				if c < 0x0020 || (c > 0x007E && c < 0x00A0 && c != 0x00B7) {
					if len(chars) >= 2 {
						break
					}
					// Reset.
					chars = nil
					j += 2
					continue
				}
				chars = append(chars, c)
				j += 2
			}
			if len(chars) >= 2 {
				runes := utf16.Decode(chars)
				var sb strings.Builder
				for _, r := range runes {
					sb.WriteRune(r)
				}
				s := sb.String()
				if len(s) >= 2 && len(s) <= 256 {
					strings16 = append(strings16, s)
				}
				i = j
				continue
			}
		}
		i++
	}

	// Heuristically assign strings to fields.
	// sAMAccountName: short alphanumeric string (1-20 chars), often first.
	// displayName: can be longer, may contain spaces.
	// description: usually longer free-text.
	for _, s := range strings16 {
		trimmed := strings.TrimSpace(s)
		if trimmed == "" {
			continue
		}
		if row.samAccountName == "" && isSAMAccountName(trimmed) {
			row.samAccountName = trimmed
		} else if row.displayName == "" && len(trimmed) <= 128 {
			row.displayName = trimmed
		} else if row.description == "" {
			row.description = trimmed
		}
	}

	// Scan for FILETIME values (8-byte, reasonable range: 2000-2100).
	const ftMin = uint64(125911584000000000) // 2000-01-01
	const ftMax = uint64(159548832000000000) // 2106-01-01
	ftimes := []uint64{}
	for i := 0; i+8 <= len(rec); i += 4 {
		ft := binary.LittleEndian.Uint64(rec[i:])
		if ft >= ftMin && ft <= ftMax {
			ftimes = append(ftimes, ft)
		}
	}
	if len(ftimes) > 0 {
		row.lastLogon = filetimeToTime(ftimes[0])
	}
	if len(ftimes) > 1 {
		row.pwdLastSet = filetimeToTime(ftimes[1])
	}

	// Scan for UAC (userAccountControl) value.
	// It's a 4-byte integer; NORMAL_ACCOUNT (0x0200) is almost always set for users.
	for i := 0; i+4 <= len(rec); i += 2 {
		v := int32(binary.LittleEndian.Uint32(rec[i:]))
		if v&uacNormalAccount != 0 && v >= 0x0200 && v <= 0x1000000 {
			row.accountFlags = v
			row.isDisabled = (v & uacDisabled) != 0
			row.pwdNeverExpires = (v & uacDontExpirePwd) != 0
			row.noPwdRequired = (v & uacPwdNotReqd) != 0
			break
		}
	}

	// Require at least a SID or a sAMAccountName to produce a useful row.
	if row.samAccountName == "" && !sidFound {
		return accountRow{}, false
	}
	if row.samAccountName == "" {
		return accountRow{}, false
	}

	return row, true
}

// isSAMAccountName returns true if s looks like a SAM account name.
func isSAMAccountName(s string) bool {
	if len(s) < 1 || len(s) > 20 {
		return false
	}
	// Must contain at least one letter or digit.
	alphanum := 0
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			alphanum++
		} else if r == '_' || r == '-' || r == '.' || r == '$' || r == ' ' {
			continue
		} else {
			return false
		}
	}
	return alphanum >= 1
}

// ---- Main parser --------------------------------------------------------

// Parse reads the NTDS.dit stream and inserts accounts into ntds_accounts.
func (p *Parser) Parse(r io.Reader, db *sql.DB, ch chan<- parsers.Progress) error {
	start := time.Now()

	data, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("ntds: read: %w", err)
	}

	count, err := parseNTDS(data, db, ch, start)
	if err != nil {
		ch <- parsers.Progress{Parser: p.Name(), Err: err, Done: true, Elapsed: time.Since(start)}
		return err
	}
	ch <- parsers.Progress{Parser: p.Name(), Count: count, Done: true, Elapsed: time.Since(start)}
	return nil
}

func parseNTDS(data []byte, db *sql.DB, ch chan<- parsers.Progress, start time.Time) (int64, error) {
	if len(data) < 240 {
		return 0, fmt.Errorf("ntds: file too short")
	}

	// Page size at offset 236 (same as SRUDB.dat — standard ESE header).
	pageSize := int(binary.LittleEndian.Uint32(data[236:240]))
	if pageSize == 0 || pageSize&(pageSize-1) != 0 || pageSize < 4096 {
		pageSize = 8192 // standard ESE page size
	}

	// Parse catalog to find datatable root page.
	tableRootPages, _ := parseCatalog(data, pageSize)

	// Find datatable (case-insensitive).
	var datatableRoot uint32
	for name, root := range tableRootPages {
		if strings.EqualFold(name, "datatable") {
			datatableRoot = root
			break
		}
	}
	if datatableRoot == 0 {
		return 0, fmt.Errorf("ntds: datatable not found in catalog")
	}

	records := collectLeafRecords(data, pageSize, datatableRoot)
	if len(records) == 0 {
		return 0, fmt.Errorf("ntds: no records in datatable")
	}

	tx, err := db.Begin()
	if err != nil {
		return 0, fmt.Errorf("ntds: begin tx: %w", err)
	}
	defer tx.Rollback() //nolint

	stmt, err := tx.Prepare(`INSERT INTO ntds_accounts
		(sam_account_name, display_name, description, object_sid,
		 last_logon, pwd_last_set, bad_pwd_count, account_flags,
		 is_disabled, is_deleted, pwd_never_expires, no_pwd_required)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return 0, fmt.Errorf("ntds: prepare: %w", err)
	}
	defer stmt.Close()

	var count int64
	seen := make(map[string]bool) // deduplicate by sAMAccountName

	for _, rec := range records {
		func() {
			defer func() { recover() }() //nolint

			row, ok := scanRecordForAccount(rec)
			if !ok {
				return
			}
			if row.samAccountName == "" {
				return
			}
			// Deduplicate.
			key := strings.ToLower(row.samAccountName)
			if seen[key] {
				return
			}
			seen[key] = true

			var lastLogon, pwdLastSet interface{}
			if !row.lastLogon.IsZero() {
				lastLogon = row.lastLogon
			}
			if !row.pwdLastSet.IsZero() {
				pwdLastSet = row.pwdLastSet
			}

			_, execErr := stmt.Exec(
				row.samAccountName,
				nullStr(row.displayName),
				nullStr(row.description),
				nullStr(row.objectSid),
				lastLogon,
				pwdLastSet,
				row.badPwdCount,
				row.accountFlags,
				row.isDisabled,
				row.isDeleted,
				row.pwdNeverExpires,
				row.noPwdRequired,
			)
			if execErr == nil {
				count++
			}
		}()
	}

	if count == 0 {
		// Fallback: broad string scan across all pages looking for SAM-like names
		// alongside SID blobs. This handles heavily fragmented or unusual layouts.
		count = broadScanFallback(data, pageSize, stmt, seen)
	}

	if err := tx.Commit(); err != nil {
		return count, fmt.Errorf("ntds: commit: %w", err)
	}
	return count, nil
}

// broadScanFallback scans every page of the file for UTF-16LE username strings
// paired with SID blobs. Used when the B-tree walk yields nothing.
func broadScanFallback(data []byte, pageSize int, stmt *sql.Stmt, seen map[string]bool) int64 {
	var count int64
	numPages := len(data) / pageSize

	for pi := 4; pi < numPages; pi++ {
		func() {
			defer func() { recover() }() //nolint

			page := data[pi*pageSize : (pi+1)*pageSize]
			row, ok := scanRecordForAccount(page)
			if !ok || row.samAccountName == "" {
				return
			}
			key := strings.ToLower(row.samAccountName)
			if seen[key] {
				return
			}
			seen[key] = true

			_, execErr := stmt.Exec(
				row.samAccountName,
				nullStr(row.displayName),
				nullStr(row.description),
				nullStr(row.objectSid),
				nil, nil, // timestamps unknown in fallback
				int32(0),
				int32(0),
				false, false, false, false,
			)
			if execErr == nil {
				count++
			}
		}()
	}
	return count
}

func nullStr(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}
