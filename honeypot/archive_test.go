package honeypot

import (
	"archive/zip"
	"bytes"
	"io"
	"testing"
)

func TestDecoyArchiveIsValidAndBounded(t *testing.T) {
	data, err := decoyArchive()
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("zip.NewReader: %v", err)
	}
	var total uint64
	for _, file := range zr.File {
		total += file.UncompressedSize64
		rc, err := file.Open()
		if err != nil {
			t.Fatalf("open %q: %v", file.Name, err)
		}
		contents, err := io.ReadAll(rc)
		closeErr := rc.Close()
		if err != nil || closeErr != nil {
			t.Fatalf("read %q: read=%v close=%v", file.Name, err, closeErr)
		}
		if len(contents) != int(file.UncompressedSize64) {
			t.Fatalf("entry %q size = %d, metadata says %d", file.Name, len(contents), file.UncompressedSize64)
		}
	}
	if total > MaxDecoyUncompressedBytes {
		t.Fatalf("uncompressed size = %d, limit is %d", total, MaxDecoyUncompressedBytes)
	}
}
