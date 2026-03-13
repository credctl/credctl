package gcp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateCredentialConfig(t *testing.T) {
	cfg := GenerateCredentialConfig(
		"/usr/local/bin/credctl",
		"//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/prov",
		"sa@project.iam.gserviceaccount.com",
	)

	if cfg.Type != "external_account" {
		t.Errorf("type = %q, want external_account", cfg.Type)
	}
	if !strings.Contains(cfg.Audience, "projects/123") {
		t.Errorf("audience = %q, should contain projects/123", cfg.Audience)
	}
	if cfg.TokenURL != "https://sts.googleapis.com/v1/token" {
		t.Errorf("token_url = %q", cfg.TokenURL)
	}
	if !strings.Contains(cfg.ServiceAccountImpersonationURL, "sa@project.iam.gserviceaccount.com") {
		t.Errorf("impersonation_url = %q", cfg.ServiceAccountImpersonationURL)
	}
	if !strings.Contains(cfg.CredentialSource.Executable.Command, "credctl auth --provider gcp --format executable") {
		t.Errorf("command = %q", cfg.CredentialSource.Executable.Command)
	}
	if cfg.CredentialSource.Executable.TimeoutMillis != 30000 {
		t.Errorf("timeout = %d, want 30000", cfg.CredentialSource.Executable.TimeoutMillis)
	}
}

func TestWriteCredentialConfig(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "subdir", "creds.json")

	cfg := GenerateCredentialConfig("/usr/local/bin/credctl", "aud", "sa@p.iam.gserviceaccount.com")

	if err := WriteCredentialConfig(path, cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}

	var parsed ExternalCredentialConfig
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if parsed.Type != "external_account" {
		t.Errorf("type = %q", parsed.Type)
	}

	// Check file permissions
	info, _ := os.Stat(path)
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("permissions = %o, want 0600", perm)
	}
}
