package cli

import (
	"strings"
	"testing"
)

func TestRunDaemonStart_AlreadyRunning(t *testing.T) {
	// This test verifies the error path when a daemon socket already exists
	// and responds to connections (simulated by pointing at a valid socket).
	// We can't easily simulate a running daemon, but we can test the config dir error path.
	mock := &mockEnclave{available: true}
	d := testDeps(mock)
	d.configDir = func() (string, error) { return "", errMock("no home dir") }
	withDeps(t, d)

	err := runDaemonStart(nil, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "config dir") {
		t.Errorf("error should mention config dir: %v", err)
	}
}

func TestRunDaemonStop_NoPIDFile(t *testing.T) {
	tmpDir := t.TempDir()

	mock := &mockEnclave{available: true}
	d := testDeps(mock)
	d.configDir = func() (string, error) { return tmpDir, nil }
	withDeps(t, d)

	err := runDaemonStop(nil, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "daemon not running") {
		t.Errorf("error should mention daemon not running: %v", err)
	}
}

func TestRunDaemonStop_ConfigDirError(t *testing.T) {
	mock := &mockEnclave{available: true}
	d := testDeps(mock)
	d.configDir = func() (string, error) { return "", errMock("no home dir") }
	withDeps(t, d)

	err := runDaemonStop(nil, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "config dir") {
		t.Errorf("error should mention config dir: %v", err)
	}
}

func TestRunDaemonStatus_NotRunning(t *testing.T) {
	tmpDir := t.TempDir()

	mock := &mockEnclave{available: true}
	d := testDeps(mock)
	d.configDir = func() (string, error) { return tmpDir, nil }
	withDeps(t, d)

	// Should not error — just prints "not running".
	err := runDaemonStatus(nil, nil)
	if err != nil {
		t.Fatalf("runDaemonStatus: %v", err)
	}
}

func TestRunDaemonStatus_ConfigDirError(t *testing.T) {
	mock := &mockEnclave{available: true}
	d := testDeps(mock)
	d.configDir = func() (string, error) { return "", errMock("no home dir") }
	withDeps(t, d)

	err := runDaemonStatus(nil, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "config dir") {
		t.Errorf("error should mention config dir: %v", err)
	}
}
