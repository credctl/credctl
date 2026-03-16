package daemon

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteAndReadPIDFile(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "test.pid")

	if err := WritePIDFile(path); err != nil {
		t.Fatalf("WritePIDFile: %v", err)
	}

	pid, err := ReadPIDFile(path)
	if err != nil {
		t.Fatalf("ReadPIDFile: %v", err)
	}
	if pid != os.Getpid() {
		t.Errorf("PID = %d, want %d", pid, os.Getpid())
	}

	// Cleanup.
	RemovePIDFile(path)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("PID file should be removed")
	}
}

func TestWritePIDFile_AlreadyRunning(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "test.pid")

	// Write first PID file (our own PID — we're running).
	if err := WritePIDFile(path); err != nil {
		t.Fatalf("first WritePIDFile: %v", err)
	}

	// Try to write again — should fail because our PID is still alive.
	err := WritePIDFile(path)
	if err == nil {
		t.Fatal("expected error for duplicate daemon")
	}

	RemovePIDFile(path)
}

func TestWritePIDFile_StalePID(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "test.pid")

	// Write a PID that definitely doesn't exist.
	if err := os.WriteFile(path, []byte("99999999"), 0600); err != nil {
		t.Fatalf("write stale PID: %v", err)
	}

	// Should succeed because the old PID is not running.
	if err := WritePIDFile(path); err != nil {
		t.Fatalf("WritePIDFile after stale: %v", err)
	}

	pid, err := ReadPIDFile(path)
	if err != nil {
		t.Fatalf("ReadPIDFile: %v", err)
	}
	if pid != os.Getpid() {
		t.Errorf("PID = %d, want %d", pid, os.Getpid())
	}

	RemovePIDFile(path)
}

func TestReadPIDFile_NotExist(t *testing.T) {
	_, err := ReadPIDFile("/nonexistent/path/test.pid")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestProcessRunning(t *testing.T) {
	// Our own PID should be running.
	if !processRunning(os.Getpid()) {
		t.Error("our own PID should be running")
	}

	// A very high PID should not be running.
	if processRunning(99999999) {
		t.Error("PID 99999999 should not be running")
	}
}
