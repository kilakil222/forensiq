// Package disk provides the top-level dispatcher for disk-image-based
// analysis. It opens a forensic disk image (raw .dd, EnCase .E01, or VMware
// .vmdk), locates NTFS partitions via the MBR/GPT, walks each NTFS volume's
// MFT for known forensic targets, and routes the matching files through the
// existing triage parsers.
package disk

import (
	"bytes"
	"database/sql"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"forensiq/internal/parsers"
	"forensiq/internal/parsers/amcache"
	"forensiq/internal/parsers/ewf"
	"forensiq/internal/parsers/ntfs"
	"forensiq/internal/parsers/triage"
	"forensiq/internal/parsers/vmdk"
)

// targetPatterns enumerates filenames the NTFS walker should surface. Order
// is not significant; matching is case-insensitive and uses simple wildcard
// rules implemented in the ntfs package.
var targetPatterns = []string{
	"*.pf",
	"*.evtx",
	"SYSTEM",
	"SOFTWARE",
	"NTUSER.DAT",
	"UsrClass.dat",
	"Amcache.hve",
	"Amcache.hve.LOG1",
	"Amcache.hve.LOG2",
	"$MFT",
	"$UsnJrnl", // the $J named stream is extracted explicitly in the callback
	"*.automaticdestinations-ms",
	"*.customdestinations-ms",
	"*.lnk",
	"$I*",
	"History",       // Chrome/Edge/Brave browser history (SQLite)
	"places.sqlite", // Firefox browser history (SQLite)
}

// Analyze opens imagePath, locates NTFS partitions, extracts forensic
// artifacts and dispatches them through triage.RouteAll.
//
// Errors for individual files are reported via ch as parsers.Progress{Err:..}
// rather than aborting the whole scan; only fatal setup failures (image not
// readable, no NTFS partition found) bubble up as the function's return value.
func Analyze(imagePath string, db *sql.DB, ch chan<- parsers.Progress) error {
	disk, totalSize, closer, err := openImage(imagePath)
	if err != nil {
		return fmt.Errorf("open image: %w", err)
	}
	defer closer()

	parts, err := findNTFSPartitions(disk, totalSize)
	if err != nil || len(parts) == 0 {
		// fall back to treating the whole image as a single NTFS volume
		parts = []int64{0}
	}

	var anyOK bool
	for _, off := range parts {
		vol, err := ntfs.OpenVolume(disk, off)
		if err != nil {
			continue
		}
		anyOK = true

		// Amcache.hve and its transaction logs are buffered here and parsed
		// together after the walk so LOG dirty pages can be applied to the hive.
		var amcacheHive, amcacheLog1, amcacheLog2 []byte

		err = vol.WalkTargetFiles(targetPatterns, func(entry ntfs.FileEntry, data io.Reader) error {
			path := entry.Path
			if path == "" {
				path = entry.Name
			}

			// $UsnJrnl has no unnamed $DATA — the journal is in the named $J stream.
			// Extract it explicitly and route as "$J" so the triage router picks it up.
			if strings.EqualFold(entry.Name, "$UsnJrnl") {
				jData, jSize, err := vol.ReadNamedStream(entry.MFTRecNo, "J")
				if err != nil || jData == nil || jSize == 0 {
					return nil
				}
				ps := triage.RouteAll("$J")
				for _, p := range ps {
					if perr := p.Parse(bytes.NewReader(jData), db, ch); perr != nil {
						ch <- parsers.Progress{Parser: p.Name(), Err: perr, Done: true}
					}
				}
				return nil
			}

			// Buffer Amcache hive and its transaction logs for combined parsing.
			base := strings.ToLower(filepath.Base(entry.Name))
			switch base {
			case "amcache.hve":
				amcacheHive, _ = io.ReadAll(data)
				log.Printf("disk: amcache hive buffered: %d bytes (path=%s)", len(amcacheHive), path)
				return nil
			case "amcache.hve.log1":
				amcacheLog1, _ = io.ReadAll(data)
				log.Printf("disk: amcache LOG1 buffered: %d bytes (path=%s)", len(amcacheLog1), path)
				return nil
			case "amcache.hve.log2":
				amcacheLog2, _ = io.ReadAll(data)
				log.Printf("disk: amcache LOG2 buffered: %d bytes (path=%s)", len(amcacheLog2), path)
				return nil
			}

			ps := triage.RouteAll(path)
			if len(ps) == 0 {
				return nil
			}

			if len(ps) == 1 {
				if perr := ps[0].Parse(data, db, ch); perr != nil {
					log.Printf("disk: parse error [%s] %s: %v", ps[0].Name(), path, perr)
					ch <- parsers.Progress{Parser: ps[0].Name(), Err: perr, Done: true}
				}
				return nil
			}

			// Multiple parsers need the same data: buffer once, fan out.
			buf, rerr := io.ReadAll(data)
			if rerr != nil {
				log.Printf("disk: buffer error %s (size=%d): %v", path, entry.Size, rerr)
				for _, p := range ps {
					ch <- parsers.Progress{Parser: p.Name(), Err: rerr, Done: true}
				}
				return nil
			}
			for _, p := range ps {
				if perr := p.Parse(bytes.NewReader(buf), db, ch); perr != nil {
					log.Printf("disk: parse error [%s] %s (buffered=%d): %v", p.Name(), path, len(buf), perr)
					ch <- parsers.Progress{Parser: p.Name(), Err: perr, Done: true}
				}
			}
			return nil
		})
		if err != nil {
			ch <- parsers.Progress{Parser: "disk", Err: err, Done: true}
		}

		// Parse Amcache with transaction log replay after the walk.
		if len(amcacheHive) > 0 {
			ap := amcache.New()
			if perr := ap.ParseWithLogs(bytes.NewReader(amcacheHive), amcacheLog1, amcacheLog2, db, ch); perr != nil {
				ch <- parsers.Progress{Parser: ap.Name(), Err: perr, Done: true}
			}
		}
	}
	if !anyOK {
		return fmt.Errorf("no usable NTFS volume found in %s", imagePath)
	}
	return nil
}

// openImage opens imagePath either as an EWF segmented image (when the
// extension is .E01) or as a raw file. It returns an io.ReaderAt over the
// virtual disk content, the disk size, and a deferred closer.
func openImage(imagePath string) (io.ReaderAt, int64, func(), error) {
	ext := strings.ToLower(filepath.Ext(imagePath))
	switch ext {
	case ".e01":
		d, err := ewf.Open(imagePath)
		if err != nil {
			return nil, 0, func() {}, err
		}
		return d, d.Size(), func() { d.Close() }, nil
	case ".vmdk":
		d, err := vmdk.Open(imagePath)
		if err != nil {
			return nil, 0, func() {}, err
		}
		return d, d.Size(), func() { d.Close() }, nil
	}
	f, err := os.Open(imagePath)
	if err != nil {
		return nil, 0, func() {}, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, 0, func() {}, err
	}
	return f, fi.Size(), func() { f.Close() }, nil
}

// findNTFSPartitions inspects the MBR (sector 0) and falls back to the GPT
// (sector 1) to enumerate likely NTFS partition byte offsets.
func findNTFSPartitions(r io.ReaderAt, total int64) ([]int64, error) {
	var sec [512]byte
	if _, err := r.ReadAt(sec[:], 0); err != nil {
		return nil, err
	}
	if sec[510] != 0x55 || sec[511] != 0xAA {
		return nil, fmt.Errorf("no MBR signature")
	}

	var out []int64
	gptDetected := false
	for i := 0; i < 4; i++ {
		entry := sec[446+i*16 : 446+(i+1)*16]
		ptype := entry[4]
		lba := int64(binary.LittleEndian.Uint32(entry[8:12]))
		size := int64(binary.LittleEndian.Uint32(entry[12:16]))
		if ptype == 0xEE {
			gptDetected = true
			continue
		}
		if ptype == 0 || size == 0 {
			continue
		}
		if ptype == 0x07 || ptype == 0x27 || ptype == 0x17 || ptype == 0x83 {
			out = append(out, lba*512)
		}
	}

	if gptDetected {
		gpt, err := readGPT(r, total)
		if err == nil {
			out = append(out, gpt...)
		}
	}
	return out, nil
}

// readGPT parses a GPT header at LBA 1 and returns offsets of partitions
// that are likely Windows-NTFS (Microsoft Basic Data) or Linux filesystem.
func readGPT(r io.ReaderAt, total int64) ([]int64, error) {
	var hdr [512]byte
	if _, err := r.ReadAt(hdr[:], 512); err != nil {
		return nil, err
	}
	if string(hdr[0:8]) != "EFI PART" {
		return nil, fmt.Errorf("no GPT signature")
	}
	partLBA := int64(binary.LittleEndian.Uint64(hdr[72:80]))
	numEntries := int(binary.LittleEndian.Uint32(hdr[80:84]))
	entrySize := int(binary.LittleEndian.Uint32(hdr[84:88]))
	if numEntries <= 0 || entrySize < 128 || numEntries > 1024 {
		return nil, fmt.Errorf("bad GPT")
	}
	entriesBuf := make([]byte, numEntries*entrySize)
	if _, err := r.ReadAt(entriesBuf, partLBA*512); err != nil {
		return nil, err
	}

	// Microsoft Basic Data: EBD0A0A2-B9E5-4433-87C0-68B6B72699C7
	msftBasic := []byte{
		0xA2, 0xA0, 0xD0, 0xEB, 0xE5, 0xB9, 0x33, 0x44,
		0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7,
	}
	var out []int64
	for i := 0; i < numEntries; i++ {
		e := entriesBuf[i*entrySize : (i+1)*entrySize]
		guid := e[0:16]
		// Skip empty entries (all zero GUID)
		empty := true
		for _, b := range guid {
			if b != 0 {
				empty = false
				break
			}
		}
		if empty {
			continue
		}
		startLBA := int64(binary.LittleEndian.Uint64(e[32:40]))
		if bytes.Equal(guid, msftBasic) {
			out = append(out, startLBA*512)
		}
	}
	return out, nil
}
