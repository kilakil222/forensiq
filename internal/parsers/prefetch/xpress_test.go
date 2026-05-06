package prefetch

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDecompressMAM(t *testing.T) {
	files, err := filepath.Glob("../../../testdata/*.pf")
	if err != nil || len(files) == 0 {
		t.Skip("no testdata/*.pf files")
	}

	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			data, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			if len(data) < 8 || data[0] != 'M' || data[1] != 'A' || data[2] != 'M' {
				t.Skip("not MAM")
			}

			uncomp, err := decompressMAM(data)
			if err != nil {
				t.Fatalf("decompressMAM: %v", err)
			}

			// Must start with version + SCCA
			if len(uncomp) < 108 {
				t.Fatalf("too short: %d", len(uncomp))
			}
			if string(uncomp[4:8]) != "SCCA" {
				t.Fatalf("bad signature: %q (bytes: %x)", string(uncomp[4:8]), uncomp[4:8])
			}
			ver := binary.LittleEndian.Uint32(uncomp[0:4])
			t.Logf("version=%d  len=%d", ver, len(uncomp))
			t.Logf("bytes 0-15: %x", uncomp[:16])

			// Check Section C paths
			fnOff := int(binary.LittleEndian.Uint32(uncomp[100:104]))
			fnSize := int(binary.LittleEndian.Uint32(uncomp[104:108]))
			t.Logf("Section C: offset=%d size=%d", fnOff, fnSize)

			if fnOff > 0 && fnOff+fnSize <= len(uncomp) {
				fnData := uncomp[fnOff : fnOff+fnSize]
				paths := parseSection(fnData)
				t.Logf("paths found: %d", len(paths))
				for i, p := range paths {
					if i >= 3 {
						break
					}
					t.Logf("  [%d] %s", i, p)
				}
				// Count ASCII-valid paths
				good := 0
				for _, p := range paths {
					if isASCIIPath(p) {
						good++
					}
				}
				t.Logf("ASCII-valid paths: %d / %d", good, len(paths))
				if len(paths) > 0 && good == 0 {
					t.Errorf("FAIL: 0/%d paths are ASCII — decompressor likely broken", len(paths))
					t.Logf("first path bytes: %x", []byte(paths[0])[:min(20, len(paths[0]))])
				}
				// Paths should contain backslashes
				if len(paths) > 0 && !strings.ContainsRune(paths[0], '\\') {
					t.Errorf("first path has no backslash: %q", paths[0][:min(len(paths[0]), 40)])
				}
			} else {
				t.Logf("Section C out of bounds (fnOff=%d fnSize=%d len=%d)", fnOff, fnSize, len(uncomp))
				// Print Section C raw bytes region hint
				if len(uncomp) >= 108 {
					t.Logf("uncomp[96:112] = %x", uncomp[96:112])
				}
				fmt.Printf("DEBUG first 160 bytes: %x\n", uncomp[:min(160, len(uncomp))])
			}
		})
	}
}

func parseSection(fnData []byte) []string {
	var out []string
	i := 0
	for i+1 < len(fnData) {
		j := i
		for j+1 < len(fnData) && !(fnData[j] == 0 && fnData[j+1] == 0) {
			j += 2
		}
		if j > i {
			s := parseUTF16(fnData[i:j])
			if s != "" {
				out = append(out, s)
			}
		}
		i = j + 2
	}
	return out
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
