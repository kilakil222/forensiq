package browser

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"
)

type sqliteKind int

const (
	kindNull sqliteKind = iota
	kindInt
	kindFloat
	kindText
	kindBlob
)

type sqliteValue struct {
	Kind  sqliteKind
	Int   int64
	Float float64
	Text  string
	Blob  []byte
}

type sqliteDB struct {
	data     []byte
	pageSize int
	wal      map[int][]byte // WAL overlay: pageNum → page data
}

func openSQLite(r io.Reader) (*sqliteDB, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return openSQLiteBytes(data)
}

func openSQLiteBytes(data []byte) (*sqliteDB, error) {
	if len(data) < 100 {
		return nil, fmt.Errorf("sqlite: file too short")
	}
	if !bytes.HasPrefix(data, []byte("SQLite format 3")) {
		return nil, fmt.Errorf("sqlite: bad magic")
	}
	ps := int(binary.BigEndian.Uint16(data[16:18]))
	if ps == 1 {
		ps = 65536
	}
	if ps < 512 {
		return nil, fmt.Errorf("sqlite: invalid page size %d", ps)
	}
	return &sqliteDB{data: data, pageSize: ps}, nil
}

func (db *sqliteDB) page(n int) ([]byte, error) {
	if n < 1 {
		return nil, fmt.Errorf("sqlite: invalid page number %d", n)
	}
	if pg, ok := db.wal[n]; ok {
		return pg, nil
	}
	start := (n - 1) * db.pageSize
	end := start + db.pageSize
	if end > len(db.data) {
		return nil, fmt.Errorf("sqlite: page %d out of range", n)
	}
	return db.data[start:end], nil
}

// applyWAL overlays committed WAL frames onto the database page cache.
// Only frames whose salt matches the WAL header are applied; the last frame per page wins.
func (db *sqliteDB) applyWAL(walData []byte) {
	if len(walData) < 32 {
		return
	}
	magic := binary.BigEndian.Uint32(walData[0:4])
	if magic != 0x377f0682 && magic != 0x377f0683 {
		return
	}
	walPageSize := int(binary.BigEndian.Uint32(walData[8:12]))
	if walPageSize < 512 {
		walPageSize = db.pageSize
	}
	salt1 := binary.BigEndian.Uint32(walData[16:20])
	salt2 := binary.BigEndian.Uint32(walData[20:24])

	if db.wal == nil {
		db.wal = make(map[int][]byte)
	}
	pos := 32
	for pos+24+walPageSize <= len(walData) {
		frame := walData[pos:]
		pageNum := int(binary.BigEndian.Uint32(frame[0:4]))
		fSalt1 := binary.BigEndian.Uint32(frame[8:12])
		fSalt2 := binary.BigEndian.Uint32(frame[12:16])
		if fSalt1 == salt1 && fSalt2 == salt2 && pageNum > 0 {
			pg := make([]byte, walPageSize)
			copy(pg, frame[24:24+walPageSize])
			db.wal[pageNum] = pg
		}
		pos += 24 + walPageSize
	}
}

func readVarint(b []byte, pos int) (int64, int) {
	var v uint64
	for i := 0; i < 9; i++ {
		if pos+i >= len(b) {
			return 0, 0
		}
		c := b[pos+i]
		if i == 8 {
			v = (v << 8) | uint64(c)
			return int64(v), 9
		}
		v = (v << 7) | uint64(c&0x7f)
		if c&0x80 == 0 {
			return int64(v), i + 1
		}
	}
	return int64(v), 9
}

func (db *sqliteDB) maxLocal() int {
	return ((db.pageSize - 12) * 64 / 255) - 23
}

func (db *sqliteDB) minLocal() int {
	return ((db.pageSize - 12) * 32 / 255) - 23
}

func (db *sqliteDB) readOverflow(firstOverflowPage int, need int) ([]byte, error) {
	result := make([]byte, 0, need)
	pageNum := firstOverflowPage
	for pageNum != 0 && len(result) < need {
		pg, err := db.page(pageNum)
		if err != nil {
			return result, err
		}
		nextPage := int(binary.BigEndian.Uint32(pg[0:4]))
		chunk := pg[4:]
		remaining := need - len(result)
		if len(chunk) > remaining {
			chunk = chunk[:remaining]
		}
		result = append(result, chunk...)
		pageNum = nextPage
	}
	return result, nil
}

func (db *sqliteDB) readRecord(payload []byte) ([]sqliteValue, error) {
	if len(payload) == 0 {
		return nil, nil
	}
	headerLen, n := readVarint(payload, 0)
	if n == 0 || int(headerLen) > len(payload) {
		return nil, fmt.Errorf("sqlite: bad record header")
	}
	pos := n
	end := int(headerLen)

	var types []int64
	for pos < end {
		t, tn := readVarint(payload, pos)
		if tn == 0 {
			break
		}
		types = append(types, t)
		pos += tn
	}

	dataPos := end
	vals := make([]sqliteValue, len(types))
	for i, t := range types {
		switch {
		case t == 0:
			vals[i] = sqliteValue{Kind: kindNull}
		case t == 1:
			if dataPos+1 > len(payload) {
				return vals, nil
			}
			vals[i] = sqliteValue{Kind: kindInt, Int: int64(int8(payload[dataPos]))}
			dataPos++
		case t == 2:
			if dataPos+2 > len(payload) {
				return vals, nil
			}
			vals[i] = sqliteValue{Kind: kindInt, Int: int64(int16(binary.BigEndian.Uint16(payload[dataPos : dataPos+2])))}
			dataPos += 2
		case t == 3:
			if dataPos+3 > len(payload) {
				return vals, nil
			}
			v := int64(payload[dataPos])<<16 | int64(payload[dataPos+1])<<8 | int64(payload[dataPos+2])
			if v&0x800000 != 0 {
				v |= ^int64(0xffffff)
			}
			vals[i] = sqliteValue{Kind: kindInt, Int: v}
			dataPos += 3
		case t == 4:
			if dataPos+4 > len(payload) {
				return vals, nil
			}
			vals[i] = sqliteValue{Kind: kindInt, Int: int64(int32(binary.BigEndian.Uint32(payload[dataPos : dataPos+4])))}
			dataPos += 4
		case t == 5:
			if dataPos+6 > len(payload) {
				return vals, nil
			}
			var v int64
			for j := 0; j < 6; j++ {
				v = v<<8 | int64(payload[dataPos+j])
			}
			if v&(1<<47) != 0 {
				v |= ^int64((1 << 48) - 1)
			}
			vals[i] = sqliteValue{Kind: kindInt, Int: v}
			dataPos += 6
		case t == 6:
			if dataPos+8 > len(payload) {
				return vals, nil
			}
			vals[i] = sqliteValue{Kind: kindInt, Int: int64(binary.BigEndian.Uint64(payload[dataPos : dataPos+8]))}
			dataPos += 8
		case t == 7:
			if dataPos+8 > len(payload) {
				return vals, nil
			}
			bits := binary.BigEndian.Uint64(payload[dataPos : dataPos+8])
			vals[i] = sqliteValue{Kind: kindFloat, Float: math.Float64frombits(bits)}
			dataPos += 8
		case t == 8:
			vals[i] = sqliteValue{Kind: kindInt, Int: 0}
		case t == 9:
			vals[i] = sqliteValue{Kind: kindInt, Int: 1}
		case t >= 12 && t%2 == 0:
			sz := int((t - 12) / 2)
			if dataPos+sz > len(payload) {
				sz = len(payload) - dataPos
			}
			b := make([]byte, sz)
			copy(b, payload[dataPos:dataPos+sz])
			vals[i] = sqliteValue{Kind: kindBlob, Blob: b}
			dataPos += sz
		case t >= 13 && t%2 == 1:
			sz := int((t - 13) / 2)
			if dataPos+sz > len(payload) {
				sz = len(payload) - dataPos
			}
			vals[i] = sqliteValue{Kind: kindText, Text: string(payload[dataPos : dataPos+sz])}
			dataPos += sz
		}
	}
	return vals, nil
}

func (db *sqliteDB) scanLeafPage(pageNum int, isPage1 bool, fn func([]sqliteValue) error) error {
	pg, err := db.page(pageNum)
	if err != nil {
		return err
	}

	headerOffset := 0
	if isPage1 {
		headerOffset = 100
	}

	if headerOffset >= len(pg) || pg[headerOffset] != 0x0d {
		return nil
	}

	cellCount := int(binary.BigEndian.Uint16(pg[headerOffset+3 : headerOffset+5]))
	ptrOffset := headerOffset + 8
	maxLocal := db.maxLocal()
	minLocal := db.minLocal()

	for i := 0; i < cellCount; i++ {
		ptrPos := ptrOffset + i*2
		if ptrPos+2 > len(pg) {
			break
		}
		cellOff := int(binary.BigEndian.Uint16(pg[ptrPos : ptrPos+2]))
		if cellOff >= len(pg) {
			continue
		}

		pos := cellOff
		payloadLen, n := readVarint(pg, pos)
		if n == 0 {
			continue
		}
		pos += n

		_, n = readVarint(pg, pos)
		if n == 0 {
			continue
		}
		pos += n

		pLen := int(payloadLen)
		var payload []byte

		if pLen <= maxLocal {
			if pos+pLen > len(pg) {
				pLen = len(pg) - pos
			}
			payload = pg[pos : pos+pLen]
		} else {
			localPayload := minLocal + (pLen-minLocal)%(db.pageSize-4)
			if localPayload > maxLocal {
				localPayload = maxLocal
			}
			if pos+localPayload > len(pg) {
				localPayload = len(pg) - pos
			}
			overflowPtrPos := pos + localPayload
			payload = make([]byte, localPayload)
			copy(payload, pg[pos:pos+localPayload])

			if overflowPtrPos+4 <= len(pg) {
				overflowPage := int(binary.BigEndian.Uint32(pg[overflowPtrPos : overflowPtrPos+4]))
				if overflowPage > 0 {
					extra, err2 := db.readOverflow(overflowPage, pLen-localPayload)
					if err2 == nil {
						payload = append(payload, extra...)
					}
				}
			}
		}

		cols, err2 := db.readRecord(payload)
		if err2 != nil {
			continue
		}
		if err2 = fn(cols); err2 != nil {
			return err2
		}
	}
	return nil
}

func (db *sqliteDB) scanInteriorPage(pageNum int, isPage1 bool, fn func([]sqliteValue) error) error {
	pg, err := db.page(pageNum)
	if err != nil {
		return err
	}

	headerOffset := 0
	if isPage1 {
		headerOffset = 100
	}

	if headerOffset >= len(pg) || pg[headerOffset] != 0x05 {
		return nil
	}

	cellCount := int(binary.BigEndian.Uint16(pg[headerOffset+3 : headerOffset+5]))
	rightmostChild := int(binary.BigEndian.Uint32(pg[headerOffset+8 : headerOffset+12]))
	ptrOffset := headerOffset + 12

	for i := 0; i < cellCount; i++ {
		ptrPos := ptrOffset + i*2
		if ptrPos+2 > len(pg) {
			break
		}
		cellOff := int(binary.BigEndian.Uint16(pg[ptrPos : ptrPos+2]))
		if cellOff+4 > len(pg) {
			continue
		}
		leftChild := int(binary.BigEndian.Uint32(pg[cellOff : cellOff+4]))
		if err2 := db.scanTablePage(leftChild, false, fn); err2 != nil {
			return err2
		}
	}

	return db.scanTablePage(rightmostChild, false, fn)
}

func (db *sqliteDB) scanTablePage(pageNum int, isPage1 bool, fn func([]sqliteValue) error) error {
	if pageNum <= 0 {
		return nil
	}
	pg, err := db.page(pageNum)
	if err != nil {
		return err
	}

	headerOffset := 0
	if isPage1 {
		headerOffset = 100
	}

	if headerOffset >= len(pg) {
		return nil
	}

	switch pg[headerOffset] {
	case 0x0d:
		return db.scanLeafPage(pageNum, isPage1, fn)
	case 0x05:
		return db.scanInteriorPage(pageNum, isPage1, fn)
	}
	return nil
}

func (db *sqliteDB) scanTable(tableName string, fn func(cols []sqliteValue) error) error {
	rootPage, err := db.findTableRoot(tableName)
	if err != nil {
		return err
	}
	return db.scanTablePage(rootPage, rootPage == 1, fn)
}

func (db *sqliteDB) findTableRoot(name string) (int, error) {
	var result int
	err := db.scanTablePage(1, true, func(cols []sqliteValue) error {
		if len(cols) < 5 {
			return nil
		}
		if cols[0].Kind != kindText || cols[0].Text != "table" {
			return nil
		}
		tblName := ""
		if cols[2].Kind == kindText {
			tblName = cols[2].Text
		} else if cols[1].Kind == kindText {
			tblName = cols[1].Text
		}
		if tblName != name {
			return nil
		}
		if cols[3].Kind == kindInt {
			result = int(cols[3].Int)
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	if result == 0 {
		return 0, fmt.Errorf("sqlite: table %q not found", name)
	}
	return result, nil
}
