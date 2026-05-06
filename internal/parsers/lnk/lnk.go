package lnk

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

type LNKParser struct {
	filePath string
}

func New(filePath string) *LNKParser { return &LNKParser{filePath: filePath} }
func (p *LNKParser) Name() string    { return "LNK" }

func (p *LNKParser) Parse(r io.Reader, db *sql.DB, ch chan<- parsers.Progress) error {
	start := time.Now()
	data, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("read lnk: %w", err)
	}

	created, accessed, modified, targetPath, machineID, driveSerial, volumeLabel, args, workingDir :=
		parseLNK(data)

	stmt, err := db.Prepare(`INSERT INTO lnk_files
		(path, target_path, created, modified, accessed, machine_id, drive_serial, volume_label, args, working_dir)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare lnk insert: %w", err)
	}
	defer stmt.Close()

	if _, err := stmt.Exec(strings.ToValidUTF8(p.filePath, "?"), nullS(targetPath), nullT(created), nullT(modified), nullT(accessed),
		nullS(machineID), nullS(driveSerial), nullS(volumeLabel), nullS(args), nullS(workingDir)); err != nil {
		return fmt.Errorf("insert lnk: %w", err)
	}

	ch <- parsers.Progress{Parser: p.Name(), Count: 1, Done: true, Elapsed: time.Since(start)}
	return nil
}

func parseLNK(data []byte) (created, accessed, modified time.Time, targetPath, machineID, driveSerial, volumeLabel, args, workingDir string) {
	if len(data) < 76 {
		return
	}
	if data[4] != 0x01 || data[5] != 0x14 {
		return
	}

	linkFlags := binary.LittleEndian.Uint32(data[20:24])
	created = filetimeAt(data, 28)
	accessed = filetimeAt(data, 36)
	modified = filetimeAt(data, 44)

	pos := 76

	// Skip LinkTargetIDList (bit 0)
	if linkFlags&0x01 != 0 {
		if pos+2 > len(data) {
			return
		}
		idListSize := int(binary.LittleEndian.Uint16(data[pos : pos+2]))
		pos += 2 + idListSize
	}

	// Parse LinkInfo (bit 1)
	if linkFlags&0x02 != 0 && pos+28 <= len(data) {
		liBase := pos
		liSize := int(binary.LittleEndian.Uint32(data[pos : pos+4]))
		if liSize >= 28 && liBase+liSize <= len(data) {
			liHdrSize := int(binary.LittleEndian.Uint32(data[liBase+4 : liBase+8]))
			liFlags := binary.LittleEndian.Uint32(data[liBase+8 : liBase+12])
			volIDOffset := int(binary.LittleEndian.Uint32(data[liBase+12 : liBase+16]))
			localBaseOffset := int(binary.LittleEndian.Uint32(data[liBase+16 : liBase+20]))

			// VolumeID (bit 0 of LinkInfoFlags)
			if liFlags&0x01 != 0 && volIDOffset > 0 {
				vidBase := liBase + volIDOffset
				if vidBase+16 <= len(data) {
					vidSize := int(binary.LittleEndian.Uint32(data[vidBase : vidBase+4]))
					serialRaw := binary.LittleEndian.Uint32(data[vidBase+8 : vidBase+12])
					driveSerial = fmt.Sprintf("%08X", serialRaw)
					lblOff := int(binary.LittleEndian.Uint32(data[vidBase+12 : vidBase+16]))
					// Unicode label (VolumeIDSize >= 20, offset at +16)
					if vidSize >= 20 && vidBase+20 <= len(data) {
						lblOffU := int(binary.LittleEndian.Uint32(data[vidBase+16 : vidBase+20]))
						end := lnkMin(vidBase+vidSize, len(data))
						if lblOffU > 0x10 && vidBase+lblOffU < end {
							volumeLabel = readUTF16LE(data[vidBase+lblOffU : end])
						}
					}
					if volumeLabel == "" && lblOff > 0 {
						end := lnkMin(vidBase+vidSize, len(data))
						if vidBase+lblOff < end {
							volumeLabel = readAnsi(data[vidBase+lblOff : end])
						}
					}
				}
			}

			// LocalBasePath ANSI
			if liFlags&0x01 != 0 && localBaseOffset > 0 {
				off := liBase + localBaseOffset
				end := lnkMin(liBase+liSize, len(data))
				if off < end {
					targetPath = readAnsi(data[off:end])
				}
			}

			// LocalBasePath Unicode (HeaderSize >= 36)
			if targetPath == "" && liHdrSize >= 36 && liBase+32 <= len(data) {
				localBaseOffU := int(binary.LittleEndian.Uint32(data[liBase+28 : liBase+32]))
				if localBaseOffU > 0 {
					off := liBase + localBaseOffU
					end := lnkMin(liBase+liSize, len(data))
					if off < end {
						targetPath = readUTF16LE(data[off:end])
					}
				}
			}
		}
		pos = liBase + liSize
	}

	// StringData
	isUnicode := linkFlags&0x80 != 0
	readStr := func() string {
		if pos+2 > len(data) {
			return ""
		}
		count := int(binary.LittleEndian.Uint16(data[pos : pos+2]))
		pos += 2
		if isUnicode {
			end := pos + count*2
			if end > len(data) {
				return ""
			}
			s := readUTF16LE(data[pos:end])
			pos = end
			return s
		}
		end := pos + count
		if end > len(data) {
			return ""
		}
		s := string(data[pos:end])
		pos = end
		return s
	}

	if linkFlags&0x04 != 0 { // HasName
		readStr()
	}
	if linkFlags&0x08 != 0 { // HasRelativePath
		rel := readStr()
		if targetPath == "" {
			targetPath = rel
		}
	}
	if linkFlags&0x10 != 0 { // HasWorkingDir
		workingDir = readStr()
	}
	if linkFlags&0x20 != 0 { // HasArguments
		args = readStr()
	}

	// ExtraData: TrackerDataBlock (sig 0xA0000003) for machine_id
	if pos < len(data) {
		machineID = extractTrackerMachineID(data[pos:])
	}
	return
}

// extractTrackerMachineID finds the TrackerDataBlock extra data and returns the machine NetBIOS name.
func extractTrackerMachineID(data []byte) string {
	pos := 0
	for pos+8 <= len(data) {
		blockSize := int(binary.LittleEndian.Uint32(data[pos : pos+4]))
		if blockSize < 4 {
			break
		}
		if pos+blockSize > len(data) {
			break
		}
		sig := binary.LittleEndian.Uint32(data[pos+4 : pos+8])
		// TrackerDataBlock signature = 0xA0000003, size >= 96
		if sig == 0xA0000003 && blockSize >= 96 {
			nameOff := pos + 16
			if nameOff+16 <= len(data) {
				return readAnsi(data[nameOff : nameOff+16])
			}
		}
		pos += blockSize
	}
	return ""
}

func filetimeAt(data []byte, offset int) time.Time {
	if offset+8 > len(data) {
		return time.Time{}
	}
	const epoch = uint64(116444736000000000)
	ft := binary.LittleEndian.Uint64(data[offset : offset+8])
	if ft == 0 || ft < epoch {
		return time.Time{}
	}
	return time.Unix(0, int64((ft-epoch)*100)).UTC()
}

func readAnsi(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func readUTF16LE(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	n := len(b) / 2
	u := make([]uint16, n)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	for i, c := range u {
		if c == 0 {
			u = u[:i]
			break
		}
	}
	if len(u) == 0 {
		return ""
	}
	return string(utf16.Decode(u))
}

func nullS(s string) interface{} {
	s = strings.ToValidUTF8(s, "�")
	if s == "" {
		return nil
	}
	return s
}

func nullT(t time.Time) interface{} {
	if t.IsZero() {
		return nil
	}
	return t
}

func lnkMin(a, b int) int {
	if a < b {
		return a
	}
	return b
}
