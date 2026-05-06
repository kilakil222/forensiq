package shimcache_test

import (
	"bytes"
	"path/filepath"
	"testing"

	"forensiq/internal/fcase"
	"forensiq/internal/parsers"
	"forensiq/internal/parsers/shimcache"
	"forensiq/internal/schema"
)

func TestName(t *testing.T) {
	p := shimcache.New()
	if p.Name() != "Shimcache" {
		t.Fatalf("Name() = %q, want %q", p.Name(), "Shimcache")
	}
}

func TestParseEmptyReader(t *testing.T) {
	c, err := fcase.Open(filepath.Join(t.TempDir(), "t.fcase"), "t")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := schema.Apply(c); err != nil {
		t.Fatal(err)
	}

	p := shimcache.New()
	ch := make(chan parsers.Progress, 10)
	err = p.Parse(bytes.NewReader(nil), c.DB(), ch)
	if err == nil {
		t.Fatal("expected error for empty reader, got nil")
	}
}

func TestParseInvalidData(t *testing.T) {
	c, err := fcase.Open(filepath.Join(t.TempDir(), "t.fcase"), "t")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := schema.Apply(c); err != nil {
		t.Fatal(err)
	}

	p := shimcache.New()
	ch := make(chan parsers.Progress, 10)
	// Random garbage — not a valid REGF hive.
	garbage := bytes.Repeat([]byte{0xDE, 0xAD, 0xBE, 0xEF}, 2048)
	err = p.Parse(bytes.NewReader(garbage), c.DB(), ch)
	if err == nil {
		t.Fatal("expected error for invalid hive data, got nil")
	}
}

func TestParseWin8BlobDirect(t *testing.T) {
	// Build a minimal Win8+ shimcache blob with two entries and verify
	// the blob parser doesn't panic and returns the expected count.
	blob := buildWin8Blob([]string{`C:\Windows\System32\cmd.exe`, `C:\Windows\notepad.exe`})

	entries, err := exportParseBlob(blob)
	if err != nil {
		t.Fatalf("parseBlob error: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries[0] != `C:\Windows\System32\cmd.exe` {
		t.Errorf("entry[0] path = %q", entries[0])
	}
}

// buildWin8Blob constructs a minimal Win8+ AppCompatCache blob.
func buildWin8Blob(paths []string) []byte {
	var b bytes.Buffer

	// 8-byte header: sig=0x80 + 4 padding bytes
	header := make([]byte, 8)
	header[0] = 0x80
	b.Write(header)

	for _, p := range paths {
		// Encode path as UTF-16LE
		utf16Path := encodeUTF16LE(p)

		// Entry: "10ts" tag + uint32 dataSize + uint64 FILETIME + uint16 pathLen + path
		dataSize := uint32(8 + 2 + len(utf16Path))

		tag := []byte("10ts")
		b.Write(tag)

		ds := make([]byte, 4)
		bytes.NewReader([]byte{}).Read(ds) // zero
		ds[0] = byte(dataSize)
		ds[1] = byte(dataSize >> 8)
		ds[2] = byte(dataSize >> 16)
		ds[3] = byte(dataSize >> 24)
		b.Write(ds)

		// FILETIME: use a valid value (2020-01-01 in FILETIME)
		ft := make([]byte, 8)
		// 132225792000000000 = 2020-01-01 00:00:00 UTC in FILETIME ticks
		ftVal := uint64(132225792000000000)
		ft[0] = byte(ftVal)
		ft[1] = byte(ftVal >> 8)
		ft[2] = byte(ftVal >> 16)
		ft[3] = byte(ftVal >> 24)
		ft[4] = byte(ftVal >> 32)
		ft[5] = byte(ftVal >> 40)
		ft[6] = byte(ftVal >> 48)
		ft[7] = byte(ftVal >> 56)
		b.Write(ft)

		// Path length (uint16)
		pl := make([]byte, 2)
		pl[0] = byte(len(utf16Path))
		pl[1] = byte(len(utf16Path) >> 8)
		b.Write(pl)

		b.Write(utf16Path)
	}

	return b.Bytes()
}

func encodeUTF16LE(s string) []byte {
	out := make([]byte, len(s)*2)
	for i, c := range s {
		out[i*2] = byte(c)
		out[i*2+1] = byte(c >> 8)
	}
	return out
}
