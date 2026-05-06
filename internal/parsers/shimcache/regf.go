// Package shimcache contains a minimal REGF (Windows registry hive) parser.
// It implements just enough of the NK/VK cell format to walk keys and read
// values — no external library required.
package shimcache

import (
	"encoding/binary"
	"fmt"
	"unicode/utf16"
)

// regf is a parsed Windows registry hive loaded entirely into memory.
type regf struct {
	data []byte
	root *nkCell
}

// openRegf parses a REGF hive from raw bytes.
func openRegf(data []byte) (*regf, error) {
	if len(data) < 4096 {
		return nil, fmt.Errorf("regf: hive too small (%d bytes)", len(data))
	}
	if string(data[0:4]) != "regf" {
		return nil, fmt.Errorf("regf: bad signature %q", string(data[0:4]))
	}
	rootOff := binary.LittleEndian.Uint32(data[36:40])
	r := &regf{data: data}
	root, err := r.parseNK(int(rootOff) + 0x1000)
	if err != nil {
		return nil, fmt.Errorf("regf: root NK: %w", err)
	}
	r.root = root
	return r, nil
}

// nkCell represents a registry key (NK record).
type nkCell struct {
	name          string
	subkeyCount   uint32
	subkeyListOff int
	valueCount    uint32
	valueListOff  int
	r             *regf
}

// parseNK parses an NK cell at the given absolute offset.
func (r *regf) parseNK(off int) (*nkCell, error) {
	if off < 0x1000 || off+80 > len(r.data) {
		return nil, fmt.Errorf("regf: NK offset 0x%x out of range", off)
	}
	if string(r.data[off+4:off+6]) != "nk" {
		return nil, fmt.Errorf("regf: expected NK at 0x%x, got %q", off, string(r.data[off+4:off+6]))
	}

	subkeyCount := binary.LittleEndian.Uint32(r.data[off+24 : off+28])
	subkeyListRaw := binary.LittleEndian.Uint32(r.data[off+32 : off+36])
	valueCount := binary.LittleEndian.Uint32(r.data[off+40 : off+44])
	valueListRaw := binary.LittleEndian.Uint32(r.data[off+44 : off+48])
	nameLen := binary.LittleEndian.Uint16(r.data[off+76 : off+78])
	flags := binary.LittleEndian.Uint16(r.data[off+6 : off+8])

	nameStart := off + 80
	if nameStart+int(nameLen) > len(r.data) {
		return nil, fmt.Errorf("regf: NK name out of range at 0x%x", off)
	}
	nameBytes := r.data[nameStart : nameStart+int(nameLen)]
	var name string
	if flags&0x20 != 0 {
		name = string(nameBytes)
	} else {
		name = decodeUTF16LE(nameBytes)
	}

	subkeyListOff := -1
	if subkeyCount > 0 && subkeyListRaw != 0xFFFFFFFF && subkeyListRaw != 0 {
		subkeyListOff = int(subkeyListRaw) + 0x1000
	}
	valueListOff := -1
	if valueCount > 0 && valueListRaw != 0xFFFFFFFF && valueListRaw != 0 {
		valueListOff = int(valueListRaw) + 0x1000
	}

	return &nkCell{
		name:          name,
		subkeyCount:   subkeyCount,
		subkeyListOff: subkeyListOff,
		valueCount:    valueCount,
		valueListOff:  valueListOff,
		r:             r,
	}, nil
}

// subkeys returns all direct child NK cells.
func (nk *nkCell) subkeys() ([]*nkCell, error) {
	if nk.subkeyCount == 0 || nk.subkeyListOff < 0 {
		return nil, nil
	}
	return nk.r.parseSubkeyList(nk.subkeyListOff, int(nk.subkeyCount))
}

// parseSubkeyList parses an lf/lh/li/ri list and returns NK cells.
func (r *regf) parseSubkeyList(off int, expected int) ([]*nkCell, error) {
	if off+8 > len(r.data) {
		return nil, fmt.Errorf("regf: subkey list offset 0x%x out of range", off)
	}
	sig := string(r.data[off+4 : off+6])
	count := int(binary.LittleEndian.Uint16(r.data[off+6 : off+8]))

	switch sig {
	case "lf", "lh":
		if off+8+count*8 > len(r.data) {
			return nil, fmt.Errorf("regf: %s list truncated at 0x%x", sig, off)
		}
		var keys []*nkCell
		for i := 0; i < count; i++ {
			entryOff := off + 8 + i*8
			nkOff := int(binary.LittleEndian.Uint32(r.data[entryOff:entryOff+4])) + 0x1000
			nk, err := r.parseNK(nkOff)
			if err != nil {
				continue
			}
			keys = append(keys, nk)
		}
		return keys, nil

	case "li":
		if off+8+count*4 > len(r.data) {
			return nil, fmt.Errorf("regf: li list truncated at 0x%x", off)
		}
		var keys []*nkCell
		for i := 0; i < count; i++ {
			entryOff := off + 8 + i*4
			nkOff := int(binary.LittleEndian.Uint32(r.data[entryOff:entryOff+4])) + 0x1000
			nk, err := r.parseNK(nkOff)
			if err != nil {
				continue
			}
			keys = append(keys, nk)
		}
		return keys, nil

	case "ri":
		if off+8+count*4 > len(r.data) {
			return nil, fmt.Errorf("regf: ri list truncated at 0x%x", off)
		}
		var keys []*nkCell
		for i := 0; i < count; i++ {
			entryOff := off + 8 + i*4
			listOff := int(binary.LittleEndian.Uint32(r.data[entryOff:entryOff+4])) + 0x1000
			sub, err := r.parseSubkeyList(listOff, 0)
			if err != nil {
				continue
			}
			keys = append(keys, sub...)
		}
		return keys, nil

	default:
		return nil, fmt.Errorf("regf: unknown subkey list sig %q at 0x%x", sig, off)
	}
}

// openSubkey traverses a path like "ControlSet001\Control\Session Manager\AppCompatCache".
func (nk *nkCell) openSubkey(path string) (*nkCell, error) {
	cur := nk
	start := 0
	for i := 0; i <= len(path); i++ {
		if i == len(path) || path[i] == '\\' {
			part := path[start:i]
			if part == "" {
				start = i + 1
				continue
			}
			subs, err := cur.subkeys()
			if err != nil {
				return nil, err
			}
			found := false
			for _, sub := range subs {
				if equalFold(sub.name, part) {
					cur = sub
					found = true
					break
				}
			}
			if !found {
				return nil, fmt.Errorf("regf: key %q not found", part)
			}
			start = i + 1
		}
	}
	return cur, nil
}

// vkCell represents a registry value (VK record).
type vkCell struct {
	name     string
	dataType uint32
	data     []byte
}

// values returns all VK cells for this key.
func (nk *nkCell) values() ([]*vkCell, error) {
	if nk.valueCount == 0 || nk.valueListOff < 0 {
		return nil, nil
	}
	r := nk.r
	off := nk.valueListOff
	count := int(nk.valueCount)
	if off+count*4 > len(r.data) {
		return nil, fmt.Errorf("regf: value list truncated at 0x%x", off)
	}
	var vals []*vkCell
	for i := 0; i < count; i++ {
		vkOffRaw := binary.LittleEndian.Uint32(r.data[off+i*4 : off+i*4+4])
		vkOff := int(vkOffRaw) + 0x1000
		vk, err := r.parseVK(vkOff)
		if err != nil {
			continue
		}
		vals = append(vals, vk)
	}
	return vals, nil
}

// parseVK parses a VK cell at the given absolute offset.
func (r *regf) parseVK(off int) (*vkCell, error) {
	if off+24 > len(r.data) {
		return nil, fmt.Errorf("regf: VK offset 0x%x out of range", off)
	}
	if string(r.data[off+4:off+6]) != "vk" {
		return nil, fmt.Errorf("regf: expected VK at 0x%x, got %q", off, string(r.data[off+4:off+6]))
	}
	nameLen := int(binary.LittleEndian.Uint16(r.data[off+6 : off+8]))
	dataLen := binary.LittleEndian.Uint32(r.data[off+8 : off+12])
	dataOff := binary.LittleEndian.Uint32(r.data[off+12 : off+16])
	dataType := binary.LittleEndian.Uint32(r.data[off+16 : off+20])
	flags := binary.LittleEndian.Uint16(r.data[off+20 : off+22])

	var name string
	if nameLen > 0 {
		if off+24+nameLen > len(r.data) {
			return nil, fmt.Errorf("regf: VK name out of range at 0x%x", off)
		}
		nb := r.data[off+24 : off+24+nameLen]
		if flags&0x01 != 0 {
			name = string(nb)
		} else {
			name = decodeUTF16LE(nb)
		}
	}

	var rawData []byte
	inlineFlag := dataLen & 0x80000000
	realLen := dataLen & 0x7FFFFFFF
	if inlineFlag != 0 {
		tmp := make([]byte, 4)
		binary.LittleEndian.PutUint32(tmp, dataOff)
		rawData = tmp[:realLen]
	} else if realLen > 0 {
		absData := int(dataOff) + 0x1000 + 4
		if absData+2 > len(r.data) {
			return nil, fmt.Errorf("regf: VK data out of range at 0x%x", absData)
		}
		// Big Data ("db") cell: used when data exceeds ~16 KB.
		if r.data[absData] == 'd' && r.data[absData+1] == 'b' {
			var err error
			rawData, err = r.readBigData(absData, int(realLen))
			if err != nil {
				return nil, fmt.Errorf("regf: VK big data at 0x%x: %w", absData, err)
			}
		} else {
			if absData+int(realLen) > len(r.data) {
				return nil, fmt.Errorf("regf: VK data out of range at 0x%x len=%d", absData, realLen)
			}
			rawData = r.data[absData : absData+int(realLen)]
		}
	}

	return &vkCell{
		name:     name,
		dataType: dataType,
		data:     rawData,
	}, nil
}

// valueByName finds a VK by name (case-insensitive).
func (nk *nkCell) valueByName(name string) (*vkCell, error) {
	vals, err := nk.values()
	if err != nil {
		return nil, err
	}
	for _, v := range vals {
		if equalFold(v.name, name) {
			return v, nil
		}
	}
	return nil, fmt.Errorf("regf: value %q not found", name)
}

// readBigData reassembles a REGF "Big Data" ("db") value from its segments.
// dbOff is the file offset of the db cell content (cell size already skipped).
// The db cell layout: "db"(2) + segCount(2) + segListOff(4, hive-relative).
// The segment list cell holds segCount uint32 hive-relative offsets.
// Each segment cell contains up to 16344 bytes of raw data.
func (r *regf) readBigData(dbOff int, realLen int) ([]byte, error) {
	if dbOff+8 > len(r.data) {
		return nil, fmt.Errorf("db cell truncated at 0x%x", dbOff)
	}
	segCount := int(binary.LittleEndian.Uint16(r.data[dbOff+2 : dbOff+4]))
	segListRaw := binary.LittleEndian.Uint32(r.data[dbOff+4 : dbOff+8])
	segListOff := int(segListRaw) + 0x1000 + 4 // skip segment-list cell size

	if segCount <= 0 || segCount > 65535 {
		return nil, fmt.Errorf("db: invalid segment count %d", segCount)
	}
	if segListOff+segCount*4 > len(r.data) {
		return nil, fmt.Errorf("db: segment list out of range at 0x%x", segListOff)
	}

	result := make([]byte, 0, realLen)
	for i := 0; i < segCount; i++ {
		remaining := realLen - len(result)
		if remaining <= 0 {
			break
		}
		segRaw := binary.LittleEndian.Uint32(r.data[segListOff+i*4 : segListOff+i*4+4])
		segOff := int(segRaw) + 0x1000 + 4 // skip segment cell size
		segLen := remaining
		if segLen > 16344 {
			segLen = 16344
		}
		if segOff+segLen > len(r.data) {
			return nil, fmt.Errorf("db: segment %d out of range at 0x%x len=%d", i, segOff, segLen)
		}
		result = append(result, r.data[segOff:segOff+segLen]...)
	}
	return result, nil
}

// --- helpers ---

func decodeUTF16LE(b []byte) string {
	if len(b) < 2 {
		return string(b)
	}
	u16 := make([]uint16, len(b)/2)
	for i := range u16 {
		u16[i] = binary.LittleEndian.Uint16(b[i*2 : i*2+2])
	}
	for len(u16) > 0 && u16[len(u16)-1] == 0 {
		u16 = u16[:len(u16)-1]
	}
	return string(utf16.Decode(u16))
}

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 32
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 32
		}
		if ca != cb {
			return false
		}
	}
	return true
}
