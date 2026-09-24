package honeypot

import (
	"archive/zip"
	"bytes"
	"fmt"
	"sync"
)

// MaxDecoyUncompressedBytes is the maximum uncompressed size of the harmless
// archive returned by the middleware.
const MaxDecoyUncompressedBytes = 512

var (
	decoyOnce sync.Once
	decoyData []byte
	decoyErr  error
)

// decoyArchive returns the same small, ordinary ZIP archive for every probe.
// Its total uncompressed content is strictly bounded.
func decoyArchive() ([]byte, error) {
	decoyOnce.Do(func() {
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		entry, err := zw.Create("probe-notice.txt")
		if err != nil {
			decoyErr = err
			return
		}
		if _, err = entry.Write([]byte("Automated probe received. This archive is a harmless honeypot decoy.\n")); err != nil {
			decoyErr = err
			return
		}
		if err = zw.Close(); err != nil {
			decoyErr = err
			return
		}
		decoyData = buf.Bytes()
	})
	if decoyErr != nil {
		return nil, fmt.Errorf("build honeypot decoy archive: %w", decoyErr)
	}
	return decoyData, nil
}
