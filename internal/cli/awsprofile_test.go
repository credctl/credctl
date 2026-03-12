package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/credctl/credctl/internal/config"
)

func TestRunSetupAWSProfile_NotInitialised(t *testing.T) {
	mock := &mockEnclave{available: true}
	d := testDeps(mock)
	d.loadConfig = func() (*config.Config, error) { return nil, nil }
	withDeps(t, d)

	err := runSetupAWSProfile(nil, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "device not initialised") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRunSetupAWSProfile_NoAWSConfig(t *testing.T) {
	mock := &mockEnclave{available: true}
	d := testDeps(mock)
	cfg := testConfig()
	d.loadConfig = func() (*config.Config, error) { return cfg, nil }
	withDeps(t, d)

	err := runSetupAWSProfile(nil, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "AWS not configured") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRunSetupAWSProfile_CreatesNewFile(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, ".aws", "config")
	t.Setenv("AWS_CONFIG_FILE", configPath)

	mock := &mockEnclave{available: true}
	d := testDeps(mock)
	cfg := testConfigWithAWS()
	d.loadConfig = func() (*config.Config, error) { return cfg, nil }
	withDeps(t, d)

	awsProfileName = "credctl"
	awsProfileForce = false
	err := runSetupAWSProfile(nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}

	content := string(data)
	if !strings.Contains(content, "[profile credctl]") {
		t.Error("missing profile header")
	}
	if !strings.Contains(content, "credential_process") {
		t.Error("missing credential_process")
	}
	if !strings.Contains(content, "credctl auth") {
		t.Error("missing 'credctl auth' in credential_process")
	}
	if !strings.Contains(content, "region = us-east-1") {
		t.Error("missing region")
	}
}

func TestRunSetupAWSProfile_DefaultProfile(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, ".aws", "config")
	t.Setenv("AWS_CONFIG_FILE", configPath)

	mock := &mockEnclave{available: true}
	d := testDeps(mock)
	cfg := testConfigWithAWS()
	d.loadConfig = func() (*config.Config, error) { return cfg, nil }
	withDeps(t, d)

	awsProfileName = "default"
	awsProfileForce = false
	err := runSetupAWSProfile(nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}

	content := string(data)
	if !strings.Contains(content, "[default]") {
		t.Error("missing [default] header")
	}
	if strings.Contains(content, "[profile default]") {
		t.Error("should use [default], not [profile default]")
	}
}

func TestRunSetupAWSProfile_ExistingProfileErrors(t *testing.T) {
	tmpDir := t.TempDir()
	awsDir := filepath.Join(tmpDir, ".aws")
	os.MkdirAll(awsDir, 0700)
	configPath := filepath.Join(awsDir, "config")
	os.WriteFile(configPath, []byte("[profile credctl]\nregion = eu-west-1\n"), 0600)
	t.Setenv("AWS_CONFIG_FILE", configPath)

	mock := &mockEnclave{available: true}
	d := testDeps(mock)
	cfg := testConfigWithAWS()
	d.loadConfig = func() (*config.Config, error) { return cfg, nil }
	withDeps(t, d)

	awsProfileName = "credctl"
	awsProfileForce = false
	err := runSetupAWSProfile(nil, nil)
	if err == nil {
		t.Fatal("expected error for existing profile")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRunSetupAWSProfile_ForceOverwrites(t *testing.T) {
	tmpDir := t.TempDir()
	awsDir := filepath.Join(tmpDir, ".aws")
	os.MkdirAll(awsDir, 0700)
	configPath := filepath.Join(awsDir, "config")
	os.WriteFile(configPath, []byte("[profile credctl]\nregion = eu-west-1\n"), 0600)
	t.Setenv("AWS_CONFIG_FILE", configPath)

	mock := &mockEnclave{available: true}
	d := testDeps(mock)
	cfg := testConfigWithAWS()
	d.loadConfig = func() (*config.Config, error) { return cfg, nil }
	withDeps(t, d)

	awsProfileName = "credctl"
	awsProfileForce = true
	err := runSetupAWSProfile(nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}

	content := string(data)
	if !strings.Contains(content, "credential_process") {
		t.Error("missing credential_process after force overwrite")
	}
	if strings.Contains(content, "eu-west-1") {
		t.Error("old region should be replaced")
	}
}

func TestRunSetupAWSProfile_PreservesOtherProfiles(t *testing.T) {
	tmpDir := t.TempDir()
	awsDir := filepath.Join(tmpDir, ".aws")
	os.MkdirAll(awsDir, 0700)
	configPath := filepath.Join(awsDir, "config")
	existing := "[default]\nregion = eu-west-2\noutput = json\n\n[profile other]\nregion = ap-southeast-1\n"
	os.WriteFile(configPath, []byte(existing), 0600)
	t.Setenv("AWS_CONFIG_FILE", configPath)

	mock := &mockEnclave{available: true}
	d := testDeps(mock)
	cfg := testConfigWithAWS()
	d.loadConfig = func() (*config.Config, error) { return cfg, nil }
	withDeps(t, d)

	awsProfileName = "credctl"
	awsProfileForce = false
	err := runSetupAWSProfile(nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}

	content := string(data)
	if !strings.Contains(content, "[default]") {
		t.Error("default profile should be preserved")
	}
	if !strings.Contains(content, "output = json") {
		t.Error("default profile settings should be preserved")
	}
	if !strings.Contains(content, "[profile other]") {
		t.Error("other profile should be preserved")
	}
	if !strings.Contains(content, "ap-southeast-1") {
		t.Error("other profile settings should be preserved")
	}
	if !strings.Contains(content, "[profile credctl]") {
		t.Error("credctl profile should be added")
	}
}

func TestProfileSectionHeader(t *testing.T) {
	tests := []struct {
		name   string
		expect string
	}{
		{"default", "[default]"},
		{"credctl", "[profile credctl]"},
		{"my-project", "[profile my-project]"},
	}
	for _, tt := range tests {
		got := profileSectionHeader(tt.name)
		if got != tt.expect {
			t.Errorf("profileSectionHeader(%q) = %q, want %q", tt.name, got, tt.expect)
		}
	}
}

func TestParseAWSConfig_NonExistentFile(t *testing.T) {
	sections, err := parseAWSConfig("/nonexistent/path/config")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sections) != 0 {
		t.Errorf("expected empty sections, got %d", len(sections))
	}
}

func TestParseAWSConfig_RoundTrip(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config")
	original := "[default]\nregion = us-east-1\noutput = json\n\n[profile staging]\nregion = eu-west-1\n"
	os.WriteFile(configPath, []byte(original), 0600)

	sections, err := parseAWSConfig(configPath)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if len(sections) != 2 {
		t.Fatalf("expected 2 sections, got %d", len(sections))
	}

	defaultKVs := sections["[default]"]
	if len(defaultKVs) != 2 {
		t.Fatalf("expected 2 default keys, got %d", len(defaultKVs))
	}
	if defaultKVs[0].key != "region" || defaultKVs[0].value != "us-east-1" {
		t.Errorf("unexpected default region: %+v", defaultKVs[0])
	}
}
