package cli

import (
	"strings"
	"testing"

	"github.com/credctl/credctl/internal/config"
	"github.com/credctl/credctl/internal/enclave"
)

func TestRunStatus_NotInitialised(t *testing.T) {
	mock := &mockEnclave{available: true}
	d := testDeps(mock)
	d.loadConfig = func() (*config.Config, error) { return nil, nil }
	withDeps(t, d)

	err := runStatus(nil, nil)
	if err != nil {
		t.Fatalf("runStatus: %v", err)
	}
}

func TestRunStatus_Initialised_KeyAccessible(t *testing.T) {
	mock := &mockEnclave{available: true}
	d := testDeps(mock)
	d.loadConfig = func() (*config.Config, error) { return testConfig(), nil }
	withDeps(t, d)

	err := runStatus(nil, nil)
	if err != nil {
		t.Fatalf("runStatus: %v", err)
	}
}

func TestRunStatus_KeyNotAccessible(t *testing.T) {
	mock := &mockEnclave{
		available: true,
		loadKey: func(tag string) (*enclave.DeviceKey, error) {
			return nil, errMock("key not found in keychain")
		},
	}
	d := testDeps(mock)
	d.loadConfig = func() (*config.Config, error) { return testConfig(), nil }
	withDeps(t, d)

	err := runStatus(nil, nil)
	if err != nil {
		t.Fatalf("runStatus: %v", err)
	}
}

func TestRunStatus_WithAWSConfig(t *testing.T) {
	mock := &mockEnclave{available: true}
	d := testDeps(mock)
	d.loadConfig = func() (*config.Config, error) { return testConfigWithAWS(), nil }
	withDeps(t, d)

	err := runStatus(nil, nil)
	if err != nil {
		t.Fatalf("runStatus: %v", err)
	}
}

func TestRunStatus_ConfigError(t *testing.T) {
	mock := &mockEnclave{available: true}
	d := testDeps(mock)
	d.loadConfig = func() (*config.Config, error) { return nil, errMock("permission denied") }
	withDeps(t, d)

	err := runStatus(nil, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "failed to read config") {
		t.Errorf("error should mention config read: %v", err)
	}
}

func TestRunStatus_WithS3Bucket(t *testing.T) {
	mock := &mockEnclave{available: true}
	d := testDeps(mock)
	cfg := testConfigWithAWS()
	cfg.AWS.S3Bucket = "my-bucket"
	d.loadConfig = func() (*config.Config, error) { return cfg, nil }
	withDeps(t, d)

	err := runStatus(nil, nil)
	if err != nil {
		t.Fatalf("runStatus: %v", err)
	}
}

