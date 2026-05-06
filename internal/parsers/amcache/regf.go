// Package amcache contains a minimal REGF (Windows registry hive) parser.
// It implements just enough of the NK/VK cell format to walk keys and read
// values — no external library required.
package amcache

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
	// Root cell offset is at bytes 36-39 in the base block (relative to hive bins area at 0x1000).
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
	name       string
	subkeyCount uint32
	subkeyListOff int // offset of subkey list in data; -1 if none
	valueCount  uint32
	valueListOff int // offset of value list in data; -1 if none
	r          *regf
}

// parseNK parses an NK cell at the given absolute offset.
func (r *regf) parseNK(off int) (*nkCell, error) {
	if off < 0x1000 || off+80 > len(r.data) {
		return nil, fmt.Errorf("regf: NK offset 0x%x out of range", off)
	}
	// Cell header: 4-byte signed size (negative = allocated).
	// NK signature at offset+4: "nk"
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
		// ASCII (compressed) name
		name = string(nameBytes)
	} else {
		// UTF-16LE name
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
		name:         name,
		subkeyCount:  subkeyCount,
		subkeyListOff: subkeyListOff,
		valueCount:   valueCount,
		valueListOff: valueListOff,
		r:            r,
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
		// Each entry: 4-byte offset + 4-byte hash = 8 bytes.
		if off+8+count*8 > len(r.data) {
			return nil, fmt.Errorf("regf: %s list truncated at 0x%x", sig, off)
		}
		var keys []*nkCell
		for i := 0; i < count; i++ {
			entryOff := off + 8 + i*8
			nkOff := int(binary.LittleEndian.Uint32(r.data[entryOff:entryOff+4])) + 0x1000
			nk, err := r.parseNK(nkOff)
			if err != nil {
				continue // skip bad entries
			}
			keys = append(keys, nk)
		}
		return keys, nil

	case "li":
		// Each entry: 4-byte offset only.
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
		// ri = list of list offsets (indirect).
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

// openSubkey traverses a path like "Root\InventoryApplicationFile" from this key.
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
			name = string(nb) // ASCII
		} else {
			name = decodeUTF16LE(nb)
		}
	}

	// Inline data: MSB of dataLen set means data is stored in dataOff itself (up to 4 bytes).
	var rawData []byte
	inlineFlag := dataLen & 0x80000000
	realLen := dataLen & 0x7FFFFFFF
	if inlineFlag != 0 {
		// Data is inline in the dataOff field (little-endian, up to 4 bytes).
		tmp := make([]byte, 4)
		binary.LittleEndian.PutUint32(tmp, dataOff)
		rawData = tmp[:realLen]
	} else if realLen > 0 {
		absData := int(dataOff) + 0x1000
		// Cell: 4-byte size header then data.
		absData += 4
		if absData+int(realLen) > len(r.data) {
			return nil, fmt.Errorf("regf: VK data out of range at 0x%x len=%d", absData, realLen)
		}
		rawData = r.data[absData : absData+int(realLen)]
	}

	return &vkCell{
		name:     name,
		dataType: dataType,
		data:     rawData,
	}, nil
}

// getString returns the value as a UTF-16LE string (REG_SZ / REG_EXPAND_SZ).
func (v *vkCell) getString() string {
	if len(v.data) == 0 {
		return ""
	}
	// REG_SZ (1) and REG_EXPAND_SZ (2)
	if v.dataType == 1 || v.dataType == 2 {
		s := decodeUTF16LE(v.data)
		// Trim NUL terminator
		for len(s) > 0 && s[len(s)-1] == 0 {
			s = s[:len(s)-1]
		}
		return s
	}
	return string(v.data)
}

// getUint64 returns the value as a uint64 (REG_QWORD).
func (v *vkCell) getUint64() uint64 {
	if len(v.data) < 8 {
		return 0
	}
	return binary.LittleEndian.Uint64(v.data[:8])
}

// getBinary returns raw bytes (REG_BINARY).
func (v *vkCell) getBinary() []byte {
	return v.data
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

// scanNKByName linearly scans all hive bins for NK cells whose name matches
// any of the given target names (case-insensitive). Used as a fallback when
// the hive is dirty and normal subkey-list navigation fails.
func (r *regf) scanNKByName(targets ...string) []*nkCell {
	var found []*nkCell
	data := r.data
	// Hive bins start at 0x1000. Each bin has a 32-byte header starting with
	// "hbin"; cells follow immediately after. Cells use a signed 4-byte size:
	// negative = allocated, positive = free.
	off := 0x1000
	for off+8 < len(data) {
		// Skip hive bin header ("hbin" signature).
		if off+4 <= len(data) && data[off] == 'h' && data[off+1] == 'b' && data[off+2] == 'i' && data[off+3] == 'n' {
			off += 32 // hbin header is 32 bytes
			continue
		}
		rawSize := int32(binary.LittleEndian.Uint32(data[off : off+4]))
		cellSize := int(rawSize)
		if cellSize < 0 {
			cellSize = -cellSize
		} else {
			// Free cell — size is positive. Advance by at least 8.
			if cellSize < 8 {
				cellSize = 8
			}
			off += cellSize
			continue
		}
		if cellSize < 8 || off+cellSize > len(data) {
			off += 8
			continue
		}
		// Allocated cell — check for NK signature at cell+4.
		if data[off+4] == 'n' && data[off+5] == 'k' {
			nk, err := r.parseNK(off)
			if err == nil {
				for _, t := range targets {
					if equalFold(nk.name, t) {
						found = append(found, nk)
						break
					}
				}
			}
		}
		off += cellSize
	}
	return found
}

// MergeWithLogs applies REGF transaction log dirty pages to hive data and
// returns the patched hive bytes. Supports Windows 8+ new-format HvLE entries.
// Pass nil for unused log slots.
func MergeWithLogs(hive, log1, log2 []byte) []byte {
	result := make([]byte, len(hive))
	copy(result, hive)
	result = applyLog(result, log1)
	result = applyLog(result, log2)
	return result
}

// applyLog patches hive with all dirty pages found in one REGF transaction log.
// LOG format: 512-byte REGF base block, then HvLE entries (Windows 8+ format).
// HvLE fixed header layout (92 bytes):
//
//	sig(4) + size(4) + flags(4) + seqno(4) + hashAlgo(4) + unknown(4) +
//	dirtyCount(4) + hash1[32] + hash2[32]
//
// Followed by dirtyCount × 8-byte descriptors {hiveOffset(4), pageSize(4)},
// then the actual dirty page data (at the tail of the entry).
func applyLog(hive, logData []byte) []byte {
	if len(logData) == 0 {
		return hive
	}
	if len(logData) < 512 || string(logData[0:4]) != "regf" {
		return hive
	}

	// HvLE entry layout (Windows 10): sig(4)+size(4)+flags(4)+seqno(4)+unk(4)+
	//   dirty_pages_count(4)+md5_hash(16) = 40 bytes fixed header,
	//   followed by count×8-byte descriptors {hiveOffset(4),pageSize(4)},
	//   then dirty page data starting immediately after descriptors.
	const fixedHdr = 40
	off := 512
	for off+fixedHdr <= len(logData) {
		if string(logData[off:off+4]) != "HvLE" {
			break
		}
		entrySize := int(binary.LittleEndian.Uint32(logData[off+4 : off+8]))
		if entrySize < fixedHdr || off+entrySize > len(logData) {
			break
		}
		count := int(binary.LittleEndian.Uint32(logData[off+20 : off+24]))
		descEnd := off + fixedHdr + count*8
		if count < 0 || descEnd > off+entrySize {
			off += entrySize
			continue
		}
		// Dirty page data starts immediately after the descriptor table.
		dataOff := descEnd
		for i := 0; i < count; i++ {
			dOff := off + fixedHdr + i*8
			hiveOff := int(binary.LittleEndian.Uint32(logData[dOff:dOff+4])) + 0x1000
			sz := int(binary.LittleEndian.Uint32(logData[dOff+4 : dOff+8]))
			if sz <= 0 || sz > 1<<22 || dataOff+sz > off+entrySize || dataOff+sz > len(logData) {
				break
			}
			if hiveOff+sz > len(hive) {
				ext := make([]byte, hiveOff+sz)
				copy(ext, hive)
				hive = ext
			}
			copy(hive[hiveOff:hiveOff+sz], logData[dataOff:dataOff+sz])
			dataOff += sz
		}
		off += entrySize
	}
	return hive
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
	// Strip trailing NUL
	for len(u16) > 0 && u16[len(u16)-1] == 0 {
		u16 = u16[:len(u16)-1]
	}
	return string(utf16.Decode(u16))
}

// equalFold is ASCII-only case-insensitive comparison.
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
