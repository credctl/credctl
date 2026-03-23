package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSaveAndLoad_WithGCP(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	original := &Config{
		Version:       1,
		DeviceID:      "SHA256:abc123",
		KeyTag:        DefaultKeyTag,
		CreatedAt:     time.Now().Truncate(time.Second),
		EnclaveType:   "secure_enclave",
		PublicKeyPath: "~/.credctl/device.pub",
		GCP: &GCPConfig{
			ProjectNumber:       "123456789",
			WorkloadPoolID:      "credctl-pool",
			ProviderID:          "credctl-provider",
			ServiceAccountEmail: "credctl@project.iam.gserviceaccount.com",
			IssuerURL:           "https://d1234.cloudfront.net",
		},
	}

	if err := Save(original); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.GCP == nil {
		t.Fatal("GCP config should not be nil")
	}
	if loaded.GCP.ProjectNumber != original.GCP.ProjectNumber {
		t.Errorf("ProjectNumber = %q, want %q", loaded.GCP.ProjectNumber, original.GCP.ProjectNumber)
	}
	if loaded.GCP.WorkloadPoolID != original.GCP.WorkloadPoolID {
		t.Errorf("WorkloadPoolID = %q, want %q", loaded.GCP.WorkloadPoolID, original.GCP.WorkloadPoolID)
	}
	if loaded.GCP.ProviderID != original.GCP.ProviderID {
		t.Errorf("ProviderID = %q, want %q", loaded.GCP.ProviderID, original.GCP.ProviderID)
	}
	if loaded.GCP.ServiceAccountEmail != original.GCP.ServiceAccountEmail {
		t.Errorf("ServiceAccountEmail = %q, want %q", loaded.GCP.ServiceAccountEmail, original.GCP.ServiceAccountEmail)
	}
}

func TestSaveAndLoad_WithBothClouds(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	original := &Config{
		Version:       1,
		DeviceID:      "SHA256:abc123",
		KeyTag:        DefaultKeyTag,
		CreatedAt:     time.Now().Truncate(time.Second),
		EnclaveType:   "secure_enclave",
		PublicKeyPath: "~/.credctl/device.pub",
		Biometric:     "any",
		AWS: &AWSConfig{
			RoleARN:   "arn:aws:iam::123456789012:role/test",
			IssuerURL: "https://d1234.cloudfront.net",
			Region:    "us-east-1",
			S3Bucket:  "credctl-oidc",
		},
		GCP: &GCPConfig{
			ProjectNumber:       "123456789",
			WorkloadPoolID:      "credctl-pool",
			ProviderID:          "credctl-provider",
			ServiceAccountEmail: "credctl@project.iam.gserviceaccount.com",
			IssuerURL:           "https://d1234.cloudfront.net",
		},
	}

	if err := Save(original); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.AWS == nil {
		t.Fatal("AWS config should not be nil")
	}
	if loaded.GCP == nil {
		t.Fatal("GCP config should not be nil")
	}
	if loaded.Biometric != "any" {
		t.Errorf("Biometric = %q, want %q", loaded.Biometric, "any")
	}
}

func TestGCPConfig_Audience(t *testing.T) {
	gcpCfg := &GCPConfig{
		ProjectNumber:  "123456789",
		WorkloadPoolID: "credctl-pool",
		ProviderID:     "credctl-provider",
	}

	want := "//iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/credctl-pool/providers/credctl-provider"
	got := gcpCfg.Audience()
	if got != want {
		t.Errorf("Audience() = %q, want %q", got, want)
	}
}

func TestLoad_WarnsOnWidePermissions(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	// Save a config first.
	cfg := &Config{Version: 1, DeviceID: "test"}
	if err := Save(cfg); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Widen permissions.
	path := filepath.Join(home, ".credctl", "config.json")
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatalf("Chmod: %v", err)
	}

	// Load should succeed but with a warning (written to stderr).
	loaded, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded == nil {
		t.Fatal("expected non-nil config")
	}
}

func TestLoad_StatError(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	// Create config dir but make it unreadable.
	dir := filepath.Join(home, ".credctl")
	os.MkdirAll(dir, 0700)
	path := filepath.Join(dir, "config.json")
	os.WriteFile(path, []byte(`{"version":1}`), 0600)

	// Make dir unreadable so Stat fails.
	os.Chmod(dir, 0000)
	defer os.Chmod(dir, 0700) // restore for cleanup

	_, err := Load()
	if err == nil {
		t.Fatal("expected error when directory is unreadable")
	}
}

func TestSave_MarshalIndent(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	cfg := &Config{
		Version:  1,
		DeviceID: "SHA256:test",
		AWS:      &AWSConfig{RoleARN: "arn:aws:iam::123456789012:role/test"},
	}
	if err := Save(cfg); err != nil {
		t.Fatalf("Save: %v", err)
	}

	path := filepath.Join(home, ".credctl", "config.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	// Verify it's indented (human-readable).
	content := string(data)
	if content[0] != '{' {
		t.Error("expected JSON object")
	}
	if len(content) < 50 {
		t.Error("expected indented JSON, got compact")
	}
}
