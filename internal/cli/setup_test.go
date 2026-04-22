package cli

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/credctl/credctl/internal/config"
)

// setupOIDCTestDeps generates a real EC key and sets configDir/publicKeyPath on deps.
// Must be called BEFORE withDeps.
func setupOIDCTestDeps(t *testing.T, d *deps) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	tmpDir := t.TempDir()
	pubKeyPath := filepath.Join(tmpDir, "device.pub")
	if err := os.WriteFile(pubKeyPath, pubPEM, 0600); err != nil {
		t.Fatalf("write pub key: %v", err)
	}
	d.configDir = func() (string, error) { return tmpDir, nil }
	d.publicKeyPath = func() (string, error) { return pubKeyPath, nil }
}

func TestRunSetupAWS_NotInitialised(t *testing.T) {
	mock := &mockEnclave{available: true}
	d := testDeps(mock)
	d.loadConfig = func() (*config.Config, error) { return nil, nil }
	withDeps(t, d)

	err := runSetupAWS(nil, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "device not initialised") {
		t.Errorf("error should mention not initialised: %v", err)
	}
}

func TestRunSetupAWS_ConfigLoadError(t *testing.T) {
	mock := &mockEnclave{available: true}
	d := testDeps(mock)
	d.loadConfig = func() (*config.Config, error) { return nil, errMock("disk error") }
	withDeps(t, d)

	err := runSetupAWS(nil, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "failed to read config") {
		t.Errorf("error should mention config: %v", err)
	}
}

func TestRunSetupAWS_S3PathAccountIDFails(t *testing.T) {
	mock := &mockEnclave{available: true}
	d := testDeps(mock)
	cfg := testConfig()
	d.loadConfig = func() (*config.Config, error) { return cfg, nil }
	d.execCommand = func(name string, args ...string) ([]byte, error) {
		return nil, errMock("sts error")
	}
	d.execCommandRun = func(name string, args ...string) error { return nil }
	withDeps(t, d)

	setupCloudFront = false
	setupIssuerURL = ""
	setupAWSBucket = ""
	err := runSetupAWS(nil, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "could not determine AWS account ID") {
		t.Errorf("error should mention account ID: %v", err)
	}
}

func TestRunSetupAWS_ReusesExistingIssuer(t *testing.T) {
	mock := &mockEnclave{available: true}
	d := testDeps(mock)
	cfg := testConfigWithAWS()
	var savedCfg *config.Config
	d.loadConfig = func() (*config.Config, error) { return cfg, nil }
	d.saveConfig = func(c *config.Config) error {
		savedCfg = c
		return nil
	}
	d.execCommand = func(name string, args ...string) ([]byte, error) {
		return []byte("123456789012\n"), nil
	}
	d.execCommandRun = func(name string, args ...string) error { return nil }
	setupOIDCTestDeps(t, &d)
	withDeps(t, d)

	setupCloudFront = false
	setupIssuerURL = ""
	setupAWSBucket = ""
	setupPolicyARN = "arn:aws:iam::123456789012:policy/Test"
	setupRoleName = "credctl-device-role"
	setupRegion = "us-east-1"

	err := runSetupAWS(nil, nil)
	if err != nil {
		t.Fatalf("runSetupAWS: %v", err)
	}
	if savedCfg == nil {
		t.Fatal("config was not saved")
	}
	if savedCfg.AWS.IssuerURL != "https://d1234.cloudfront.net" {
		t.Errorf("IssuerURL = %q, want original", savedCfg.AWS.IssuerURL)
	}
}

func TestRunSetupAWS_CloudFormationPath(t *testing.T) {
	mock := &mockEnclave{available: true}
	d := testDeps(mock)
	cfg := testConfig()
	d.loadConfig = func() (*config.Config, error) { return cfg, nil }
	d.execCommandRun = func(name string, args ...string) error {
		return errMock("CloudFormation deploy failed")
	}
	withDeps(t, d)

	setupCloudFront = true
	setupIssuerURL = ""
	err := runSetupAWS(nil, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "CloudFormation deploy failed") {
		t.Errorf("error should mention CloudFormation: %v", err)
	}
	setupCloudFront = false
}

func TestRunSetupAWS_CloudFormationStackOutputsFail(t *testing.T) {
	mock := &mockEnclave{available: true}
	d := testDeps(mock)
	cfg := testConfig()
	d.loadConfig = func() (*config.Config, error) { return cfg, nil }
	d.execCommandRun = func(name string, args ...string) error { return nil }
	d.execCommand = func(name string, args ...string) ([]byte, error) {
		return nil, errMock("stack not found")
	}
	withDeps(t, d)

	setupCloudFront = true
	setupIssuerURL = ""
	err := runSetupAWS(nil, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "get stack outputs") {
		t.Errorf("error should mention stack outputs: %v", err)
	}
	setupCloudFront = false
}

func TestRunSetupAWS_CloudFormationMissingOutputs(t *testing.T) {
	mock := &mockEnclave{available: true}
	d := testDeps(mock)
	cfg := testConfig()
	d.loadConfig = func() (*config.Config, error) { return cfg, nil }
	d.execCommandRun = func(name string, args ...string) error { return nil }
	d.execCommand = func(name string, args ...string) ([]byte, error) {
		resp := describeStacksOutput{
			Stacks: []struct {
				Outputs []stackOutput `json:"Outputs"`
			}{{Outputs: []stackOutput{}}},
		}
		data, _ := json.Marshal(resp)
		return data, nil
	}
	withDeps(t, d)

	setupCloudFront = true
	setupIssuerURL = ""
	err := runSetupAWS(nil, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "stack outputs missing") {
		t.Errorf("error should mention missing outputs: %v", err)
	}
	setupCloudFront = false
}

func TestGetStackOutputs_Success(t *testing.T) {
	mock := &mockEnclave{available: true}
	d := testDeps(mock)
	d.execCommand = func(name string, args ...string) ([]byte, error) {
		resp := describeStacksOutput{
			Stacks: []struct {
				Outputs []stackOutput `json:"Outputs"`
			}{{Outputs: []stackOutput{
				{OutputKey: "IssuerURL", OutputValue: "https://d1234.cloudfront.net"},
				{OutputKey: "RoleARN", OutputValue: "arn:aws:iam::123:role/test"},
				{OutputKey: "BucketName", OutputValue: "my-bucket"},
			}}},
		}
		data, _ := json.Marshal(resp)
		return data, nil
	}
	withDeps(t, d)

	outputs, err := getStackOutputs("test-stack", "us-east-1")
	if err != nil {
		t.Fatalf("getStackOutputs: %v", err)
	}
	if outputs["IssuerURL"] != "https://d1234.cloudfront.net" {
		t.Errorf("IssuerURL = %q", outputs["IssuerURL"])
	}
}

func TestGetStackOutputs_NoStacks(t *testing.T) {
	mock := &mockEnclave{available: true}
	d := testDeps(mock)
	d.execCommand = func(name string, args ...string) ([]byte, error) {
		return []byte(`{"Stacks":[]}`), nil
	}
	withDeps(t, d)

	_, err := getStackOutputs("test-stack", "us-east-1")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "stack not found") {
		t.Errorf("error should mention stack not found: %v", err)
	}
}

func TestGetStackOutputs_InvalidJSON(t *testing.T) {
	mock := &mockEnclave{available: true}
	d := testDeps(mock)
	d.execCommand = func(name string, args ...string) ([]byte, error) {
		return []byte("not json"), nil
	}
	withDeps(t, d)

	_, err := getStackOutputs("test-stack", "us-east-1")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestAwsCLIAvailable(t *testing.T) {
	mock := &mockEnclave{available: true}
	d := testDeps(mock)
	d.lookPath = func(name string) (string, error) { return "/usr/local/bin/aws", nil }
	withDeps(t, d)

	if !awsCLIAvailable() {
		t.Error("should be available when lookPath succeeds")
	}
}

func TestAwsCLIAvailable_NotFound(t *testing.T) {
	mock := &mockEnclave{available: true}
	d := testDeps(mock)
	d.lookPath = func(name string) (string, error) { return "", fmt.Errorf("not found") }
	withDeps(t, d)

	if awsCLIAvailable() {
		t.Error("should not be available when lookPath fails")
	}
}

func TestAwsAccountID_Success(t *testing.T) {
	mock := &mockEnclave{available: true}
	d := testDeps(mock)
	d.execCommand = func(name string, args ...string) ([]byte, error) {
		return []byte("123456789012\n"), nil
	}
	withDeps(t, d)

	id, err := awsAccountID("us-east-1")
	if err != nil {
		t.Fatalf("awsAccountID: %v", err)
	}
	if id != "123456789012" {
		t.Errorf("account ID = %q, want 123456789012", id)
	}
}

func TestResolveIssuerURL_Flag(t *testing.T) {
	setupIssuerURL = "https://custom.example.com"
	defer func() { setupIssuerURL = "" }()

	cfg := testConfigWithAWS()
	url := resolveIssuerURL(cfg)
	if url != "https://custom.example.com" {
		t.Errorf("should use flag, got %q", url)
	}
}

func TestResolveIssuerURL_AWSConfig(t *testing.T) {
	setupIssuerURL = ""
	cfg := testConfigWithAWS()
	url := resolveIssuerURL(cfg)
	if url != "https://d1234.cloudfront.net" {
		t.Errorf("should use AWS config, got %q", url)
	}
}

func TestResolveIssuerURL_GCPConfig(t *testing.T) {
	setupIssuerURL = ""
	cfg := testConfig()
	cfg.GCP = &config.GCPConfig{IssuerURL: "https://storage.googleapis.com/credctl-oidc-test"}
	url := resolveIssuerURL(cfg)
	if url != "https://storage.googleapis.com/credctl-oidc-test" {
		t.Errorf("should use GCP config, got %q", url)
	}
}

func TestResolveIssuerURL_Empty(t *testing.T) {
	setupIssuerURL = ""
	cfg := testConfig()
	url := resolveIssuerURL(cfg)
	if url != "" {
		t.Errorf("should be empty, got %q", url)
	}
}

func TestRunSetupGCP_NotInitialised(t *testing.T) {
	mock := &mockEnclave{available: true}
	d := testDeps(mock)
	d.loadConfig = func() (*config.Config, error) { return nil, nil }
	withDeps(t, d)

	err := runSetupGCP(nil, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "device not initialised") {
		t.Errorf("error should mention not initialised: %v", err)
	}
}

func TestRunSetupGCP_ConfigLoadError(t *testing.T) {
	mock := &mockEnclave{available: true}
	d := testDeps(mock)
	d.loadConfig = func() (*config.Config, error) { return nil, errMock("disk error") }
	withDeps(t, d)

	err := runSetupGCP(nil, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "failed to read config") {
		t.Errorf("error should mention config: %v", err)
	}
}

func TestRunSetupGCP_GcloudNotFound(t *testing.T) {
	mock := &mockEnclave{available: true}
	d := testDeps(mock)
	cfg := testConfig()
	d.loadConfig = func() (*config.Config, error) { return cfg, nil }
	d.lookPath = func(name string) (string, error) {
		if name == "gcloud" {
			return "", errMock("not found")
		}
		return "/usr/local/bin/" + name, nil
	}
	withDeps(t, d)

	err := runSetupGCP(nil, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "gcloud CLI not found") {
		t.Errorf("error should mention gcloud: %v", err)
	}
}

func TestRunSetupGCP_CreatesGCSOIDCWhenNoIssuer(t *testing.T) {
	mock := &mockEnclave{available: true}
	d := testDeps(mock)
	cfg := testConfig() // no AWS or GCP config, so no issuer URL
	d.loadConfig = func() (*config.Config, error) { return cfg, nil }
	d.saveConfig = func(c *config.Config) error { return nil }
	d.lookPath = func(name string) (string, error) { return "/usr/local/bin/" + name, nil }

	var commands []string
	d.execCommand = func(name string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "config" {
			return []byte("my-project\n"), nil
		}
		if len(args) > 0 && args[0] == "projects" {
			return []byte(`{"projectNumber":"123456789"}`), nil
		}
		return []byte(""), nil
	}
	d.execCommandRun = func(name string, args ...string) error {
		if len(args) > 0 {
			commands = append(commands, name+" "+args[0])
		}
		return nil
	}
	setupOIDCTestDeps(t, &d)
	withDeps(t, d)

	gcpProject = ""
	gcpPoolID = "credctl-pool"
	gcpProviderID = "credctl-provider"
	gcpServiceAccount = "sa@project.iam.gserviceaccount.com"
	gcpIssuerURL = ""
	gcpBucket = ""

	err := runSetupGCP(nil, nil)
	if err != nil {
		t.Fatalf("runSetupGCP: %v", err)
	}

	// Should have created a GCS bucket
	foundBucketCreate := false
	for _, c := range commands {
		if strings.Contains(c, "storage") {
			foundBucketCreate = true
			break
		}
	}
	if !foundBucketCreate {
		t.Errorf("expected GCS bucket creation command, got: %v", commands)
	}
}

func TestRunSetupGCP_ReusesAWSIssuer(t *testing.T) {
	mock := &mockEnclave{available: true}
	d := testDeps(mock)
	cfg := testConfigWithAWS() // has issuer URL from AWS config
	var savedCfg *config.Config
	d.loadConfig = func() (*config.Config, error) { return cfg, nil }
	d.saveConfig = func(c *config.Config) error {
		savedCfg = c
		return nil
	}
	d.lookPath = func(name string) (string, error) { return "/usr/local/bin/" + name, nil }
	d.execCommand = func(name string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "projects" {
			return []byte(`{"projectNumber":"123456789"}`), nil
		}
		return []byte("my-project\n"), nil
	}
	d.execCommandRun = func(name string, args ...string) error { return nil }
	setupOIDCTestDeps(t, &d)
	withDeps(t, d)

	gcpProject = ""
	gcpPoolID = "credctl-pool"
	gcpProviderID = "credctl-provider"
	gcpServiceAccount = "sa@project.iam.gserviceaccount.com"
	gcpIssuerURL = ""

	err := runSetupGCP(nil, nil)
	if err != nil {
		t.Fatalf("runSetupGCP: %v", err)
	}
	if savedCfg == nil {
		t.Fatal("config was not saved")
	}
	if savedCfg.GCP == nil {
		t.Fatal("GCP config should not be nil")
	}
	if savedCfg.GCP.IssuerURL != "https://d1234.cloudfront.net" {
		t.Errorf("should reuse AWS issuer, got %q", savedCfg.GCP.IssuerURL)
	}
}

func TestGetProjectNumber_Success(t *testing.T) {
	mock := &mockEnclave{available: true}
	d := testDeps(mock)
	d.execCommand = func(name string, args ...string) ([]byte, error) {
		return []byte(`{"projectNumber":"987654321"}`), nil
	}
	withDeps(t, d)

	num, err := getProjectNumber("my-project")
	if err != nil {
		t.Fatalf("getProjectNumber: %v", err)
	}
	if num != "987654321" {
		t.Errorf("project number = %q, want 987654321", num)
	}
}

func TestGetProjectNumber_Error(t *testing.T) {
	mock := &mockEnclave{available: true}
	d := testDeps(mock)
	d.execCommand = func(name string, args ...string) ([]byte, error) {
		return nil, errMock("gcloud error")
	}
	withDeps(t, d)

	_, err := getProjectNumber("my-project")
	if err == nil {
		t.Fatal("expected error")
	}
}
