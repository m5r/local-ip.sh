//go:build unix

package utils

import (
	"bytes"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestNewLoggerRejectsFIFO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatalf("mkfifo %s: %v", path, err)
	}

	result := make(chan error, 1)
	go func() {
		var buf bytes.Buffer
		_, err := NewLogger(&buf, LogOptions{Level: "info", Format: "json", File: path})
		result <- err
	}()

	select {
	case err := <-result:
		if err == nil {
			t.Fatalf("NewLogger accepted the FIFO %s", path)
		}
		if !strings.Contains(err.Error(), path) {
			t.Errorf("error %q does not name %s", err, path)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("NewLogger blocked on the FIFO")
	}
}
