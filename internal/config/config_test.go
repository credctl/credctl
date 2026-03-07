package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestConfigDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	dir, err := ConfigDir()
	if err != nil {
		t.Fatalf("ConfigDir: %v", err)
	}
	want := filepath.Join(home, ".credctl")
	if dir != want {
		t.Errorf("got %q, want %q", dir, want)
	}
}

func TestConfigPath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	path, err := ConfigPath()
	if err != nil {
		t.Fatalf("ConfigPath: %v", err)
	}
	want := filepath.Join(home, ".credctl", "config.json")
	if path != want {
		t.Errorf("got %q, want %q", path, want)
	}
}

func TestPublicKeyPath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	path, err := PublicKeyPath()
	if err != nil {
		t.Fatalf("PublicKeyPath: %v", err)
	}
	want := filepath.Join(home, ".credctl", "device.pub")
	if path != want {
		t.Errorf("got %q, want %q", path, want)
	}
}

func TestLoad_NoFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg != nil {
		t.Error("expected nil config when file does not exist")
	}
}

func TestSaveAndLoad(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	now := time.Now().Truncate(time.Second)
	original := &Config{
		Version:       1,
		DeviceID:      "SHA256:abc123",
		KeyTag:        "com.crzy.credctl.device-key",
		CreatedAt:     now,
		EnclaveType:   "secure_enclave",
		PublicKeyPath: "~/.credctl/device.pub",
	}

	if err := Save(original); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded == nil {
		t.Fatal("Load returned nil")
	}

	if loaded.Version != original.Version {
		t.Errorf("Version = %d, want %d", loaded.Version, original.Version)
	}
	if loaded.DeviceID != original.DeviceID {
		t.Errorf("DeviceID = %q, want %q", loaded.DeviceID, original.DeviceID)
	}
	if loaded.KeyTag != original.KeyTag {
		t.Errorf("KeyTag = %q, want %q", loaded.KeyTag, original.KeyTag)
	}
	if !loaded.CreatedAt.Equal(original.CreatedAt) {
		t.Errorf("CreatedAt = %v, want %v", loaded.CreatedAt, original.CreatedAt)
	}
	if loaded.EnclaveType != original.EnclaveType {
		t.Errorf("EnclaveType = %q, want %q", loaded.EnclaveType, original.EnclaveType)
	}
	if loaded.PublicKeyPath != original.PublicKeyPath {
		t.Errorf("PublicKeyPath = %q, want %q", loaded.PublicKeyPath, original.PublicKeyPath)
	}
	if loaded.AWS != nil {
		t.Error("expected nil AWS config")
	}
}

func TestSaveAndLoad_WithAWS(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	original := &Config{
		Version:       1,
		DeviceID:      "SHA256:abc123",
		KeyTag:        DefaultKeyTag,
		CreatedAt:     time.Now().Truncate(time.Second),
		EnclaveType:   "secure_enclave",
		PublicKeyPath: "~/.credctl/device.pub",
		AWS: &AWSConfig{
			RoleARN:   "arn:aws:iam::123456789012:role/test",
			IssuerURL: "https://d1234.cloudfront.net",
			Region:    "us-west-2",
			S3Bucket:  "credctl-oidc-bucket",
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
	if loaded.AWS.RoleARN != original.AWS.RoleARN {
		t.Errorf("RoleARN = %q, want %q", loaded.AWS.RoleARN, original.AWS.RoleARN)
	}
	if loaded.AWS.IssuerURL != original.AWS.IssuerURL {
		t.Errorf("IssuerURL = %q, want %q", loaded.AWS.IssuerURL, original.AWS.IssuerURL)
	}
	if loaded.AWS.Region != original.AWS.Region {
		t.Errorf("Region = %q, want %q", loaded.AWS.Region, original.AWS.Region)
	}
	if loaded.AWS.S3Bucket != original.AWS.S3Bucket {
		t.Errorf("S3Bucket = %q, want %q", loaded.AWS.S3Bucket, original.AWS.S3Bucket)
	}
}

func TestSave_CreatesDirectory(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	cfg := &Config{Version: 1, DeviceID: "test"}
	if err := Save(cfg); err != nil {
		t.Fatalf("Save: %v", err)
	}

	dir := filepath.Join(home, ".credctl")
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("Stat dir: %v", err)
	}
	if !info.IsDir() {
		t.Error("expected directory")
	}
	if perm := info.Mode().Perm(); perm != 0700 {
		t.Errorf("dir permissions = %o, want 0700", perm)
	}
}

func TestSave_FilePermissions(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	cfg := &Config{Version: 1, DeviceID: "test"}
	if err := Save(cfg); err != nil {
		t.Fatalf("Save: %v", err)
	}

	path := filepath.Join(home, ".credctl", "config.json")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("file permissions = %o, want 0600", perm)
	}
}

func TestLoad_InvalidJSON(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	dir := filepath.Join(home, ".credctl")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte("not json at all {{{"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg, err := Load()
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
	if cfg != nil {
		t.Error("expected nil config on error")
	}
}

func TestDefaultKeyTag(t *testing.T) {
	if DefaultKeyTag != "com.crzy.credctl.device-key" {
		t.Errorf("DefaultKeyTag = %q, want %q", DefaultKeyTag, "com.crzy.credctl.device-key")
	}
}
