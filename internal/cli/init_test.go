package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/credctl/credctl/internal/config"
	"github.com/credctl/credctl/internal/enclave"
)

func TestRunInit_Fresh(t *testing.T) {
	tmpDir := t.TempDir()
	mock := &mockEnclave{available: true}
	d := testDeps(mock)
	d.loadConfig = func() (*config.Config, error) { return nil, nil }
	d.configDir = func() (string, error) { return tmpDir, nil }
	d.publicKeyPath = func() (string, error) { return filepath.Join(tmpDir, "device.pub"), nil }
	d.saveConfig = func(cfg *config.Config) error { return nil }
	withDeps(t, d)

	// Reset flags for test
	initForce = false
	initKeyTag = config.DefaultKeyTag
	initBiometric = "any"

	err := runInit(nil, nil)
	if err != nil {
		t.Fatalf("runInit: %v", err)
	}
}

func TestRunInit_AlreadyExists_NoForce(t *testing.T) {
	mock := &mockEnclave{available: true}
	d := testDeps(mock)
	d.loadConfig = func() (*config.Config, error) { return testConfig(), nil }
	withDeps(t, d)

	initForce = false

	err := runInit(nil, nil)
	if err != nil {
		t.Fatalf("expected nil error (warning printed), got: %v", err)
	}
}

func TestRunInit_AlreadyExists_WithForce(t *testing.T) {
	tmpDir := t.TempDir()
	deleteCalled := false
	mock := &mockEnclave{
		available: true,
		deleteKey: func(tag string) error {
			deleteCalled = true
			return nil
		},
	}
	d := testDeps(mock)
	d.loadConfig = func() (*config.Config, error) { return testConfig(), nil }
	d.configDir = func() (string, error) { return tmpDir, nil }
	d.publicKeyPath = func() (string, error) { return filepath.Join(tmpDir, "device.pub"), nil }
	d.saveConfig = func(cfg *config.Config) error { return nil }
	withDeps(t, d)

	initForce = true
	initKeyTag = config.DefaultKeyTag
	initBiometric = "any"
	defer func() { initForce = false }()

	err := runInit(nil, nil)
	if err != nil {
		t.Fatalf("runInit: %v", err)
	}
	if !deleteCalled {
		t.Error("expected DeleteKey to be called with --force")
	}
}

func TestRunInit_EnclaveNotAvailable(t *testing.T) {
	mock := &mockEnclave{available: false}
	d := testDeps(mock)
	d.loadConfig = func() (*config.Config, error) { return nil, nil }
	withDeps(t, d)

	initForce = false

	err := runInit(nil, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "Secure Enclave") {
		t.Errorf("error should mention Secure Enclave: %v", err)
	}
}

func TestRunInit_KeyGenerationFails(t *testing.T) {
	mock := &mockEnclave{
		available: true,
		generateKey: func(tag string, biometric enclave.BiometricPolicy) (*enclave.DeviceKey, error) {
			return nil, errMock("hardware failure")
		},
	}
	tmpDir := t.TempDir()
	d := testDeps(mock)
	d.loadConfig = func() (*config.Config, error) { return nil, nil }
	d.configDir = func() (string, error) { return tmpDir, nil }
	d.publicKeyPath = func() (string, error) { return filepath.Join(tmpDir, "device.pub"), nil }
	withDeps(t, d)

	initForce = false
	initKeyTag = config.DefaultKeyTag
	initBiometric = "any"

	err := runInit(nil, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "key generation failed") {
		t.Errorf("error should mention key generation: %v", err)
	}
}

func TestRunInit_InvalidBiometric(t *testing.T) {
	mock := &mockEnclave{available: true}
	d := testDeps(mock)
	d.loadConfig = func() (*config.Config, error) { return nil, nil }
	withDeps(t, d)

	initForce = false
	initKeyTag = config.DefaultKeyTag
	initBiometric = "invalid-policy"

	err := runInit(nil, nil)
	if err == nil {
		t.Fatal("expected error for invalid biometric")
	}
	if !strings.Contains(err.Error(), "invalid --biometric") {
		t.Errorf("error should mention biometric: %v", err)
	}
}

func TestRunInit_BiometricFingerprint(t *testing.T) {
	tmpDir := t.TempDir()
	var savedCfg *config.Config
	mock := &mockEnclave{available: true}
	d := testDeps(mock)
	d.loadConfig = func() (*config.Config, error) { return nil, nil }
	d.configDir = func() (string, error) { return tmpDir, nil }
	d.publicKeyPath = func() (string, error) { return filepath.Join(tmpDir, "device.pub"), nil }
	d.saveConfig = func(cfg *config.Config) error {
		savedCfg = cfg
		return nil
	}
	withDeps(t, d)

	initForce = false
	initKeyTag = config.DefaultKeyTag
	initBiometric = "fingerprint"

	err := runInit(nil, nil)
	if err != nil {
		t.Fatalf("runInit: %v", err)
	}
	if savedCfg == nil {
		t.Fatal("config was not saved")
	}
	if savedCfg.Biometric != "fingerprint" {
		t.Errorf("biometric = %q, want fingerprint", savedCfg.Biometric)
	}
}

func TestRunInit_ConfigSaveError(t *testing.T) {
	tmpDir := t.TempDir()
	mock := &mockEnclave{available: true}
	d := testDeps(mock)
	d.loadConfig = func() (*config.Config, error) { return nil, nil }
	d.configDir = func() (string, error) { return tmpDir, nil }
	d.publicKeyPath = func() (string, error) { return filepath.Join(tmpDir, "device.pub"), nil }
	d.saveConfig = func(cfg *config.Config) error { return errMock("disk full") }
	withDeps(t, d)

	initForce = false
	initKeyTag = config.DefaultKeyTag
	initBiometric = "any"

	// Create the dir so MkdirAll doesn't fail
	os.MkdirAll(tmpDir, 0700)

	err := runInit(nil, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "failed to write config") {
		t.Errorf("error should mention config write: %v", err)
	}
}
