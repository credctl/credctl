package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/credctl/credctl/internal/config"
)

func TestRunSetupGCPCredFile_Success(t *testing.T) {
	tmpDir := t.TempDir()

	mock := &mockEnclave{available: true}
	d := testDeps(mock)
	cfg := testConfigWithGCP()
	d.loadConfig = func() (*config.Config, error) { return cfg, nil }
	d.configDir = func() (string, error) { return tmpDir, nil }
	d.lookPath = func(name string) (string, error) { return "/usr/local/bin/credctl", nil }
	withDeps(t, d)

	gcpCredFileOutput = filepath.Join(tmpDir, "gcp-credentials.json")
	err := runSetupGCPCredFile(nil, nil)
	if err != nil {
		t.Fatalf("runSetupGCPCredFile: %v", err)
	}

	// Verify the file was created.
	if _, err := os.Stat(gcpCredFileOutput); err != nil {
		t.Errorf("credential config file not created: %v", err)
	}
}

func TestRunSetupGCPCredFile_DefaultOutput(t *testing.T) {
	tmpDir := t.TempDir()

	mock := &mockEnclave{available: true}
	d := testDeps(mock)
	cfg := testConfigWithGCP()
	d.loadConfig = func() (*config.Config, error) { return cfg, nil }
	d.configDir = func() (string, error) { return tmpDir, nil }
	d.lookPath = func(name string) (string, error) { return "/usr/local/bin/credctl", nil }
	withDeps(t, d)

	gcpCredFileOutput = "" // should default to ~/.credctl/gcp-credentials.json
	err := runSetupGCPCredFile(nil, nil)
	if err != nil {
		t.Fatalf("runSetupGCPCredFile: %v", err)
	}

	defaultPath := filepath.Join(tmpDir, "gcp-credentials.json")
	if _, err := os.Stat(defaultPath); err != nil {
		t.Errorf("credential config file not created at default path: %v", err)
	}
}

func TestRunSetupGCPCredFile_NotInitialised(t *testing.T) {
	mock := &mockEnclave{available: true}
	d := testDeps(mock)
	d.loadConfig = func() (*config.Config, error) { return nil, nil }
	withDeps(t, d)

	err := runSetupGCPCredFile(nil, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "device not initialised") {
		t.Errorf("error should mention not initialised: %v", err)
	}
}

func TestRunSetupGCPCredFile_NoGCPConfig(t *testing.T) {
	mock := &mockEnclave{available: true}
	d := testDeps(mock)
	cfg := testConfig() // no GCP config
	d.loadConfig = func() (*config.Config, error) { return cfg, nil }
	withDeps(t, d)

	err := runSetupGCPCredFile(nil, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "GCP not configured") {
		t.Errorf("error should mention GCP not configured: %v", err)
	}
}

func TestRunSetupGCPCredFile_CredctlNotInPath(t *testing.T) {
	mock := &mockEnclave{available: true}
	d := testDeps(mock)
	cfg := testConfigWithGCP()
	d.loadConfig = func() (*config.Config, error) { return cfg, nil }
	d.lookPath = func(name string) (string, error) { return "", errMock("not found") }
	withDeps(t, d)

	err := runSetupGCPCredFile(nil, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "credctl not found") {
		t.Errorf("error should mention credctl not found: %v", err)
	}
}

func TestRunSetupGCPCredFile_ConfigLoadError(t *testing.T) {
	mock := &mockEnclave{available: true}
	d := testDeps(mock)
	d.loadConfig = func() (*config.Config, error) { return nil, errMock("disk error") }
	withDeps(t, d)

	err := runSetupGCPCredFile(nil, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "failed to read config") {
		t.Errorf("error should mention config: %v", err)
	}
}
