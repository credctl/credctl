package cli

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/credctl/credctl/internal/config"
)

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

func TestRunSetupAWS_DeployFails(t *testing.T) {
	mock := &mockEnclave{available: true}
	d := testDeps(mock)
	cfg := testConfig()
	d.loadConfig = func() (*config.Config, error) { return cfg, nil }
	d.execCommandRun = func(name string, args ...string) error {
		return errMock("CloudFormation deploy failed")
	}
	withDeps(t, d)

	err := runSetupAWS(nil, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "CloudFormation deploy failed") {
		t.Errorf("error should mention deploy: %v", err)
	}
}

func TestRunSetupAWS_StackOutputsFail(t *testing.T) {
	mock := &mockEnclave{available: true}
	d := testDeps(mock)
	cfg := testConfig()
	d.loadConfig = func() (*config.Config, error) { return cfg, nil }
	d.execCommandRun = func(name string, args ...string) error { return nil }
	d.execCommand = func(name string, args ...string) ([]byte, error) {
		return nil, errMock("stack not found")
	}
	withDeps(t, d)

	err := runSetupAWS(nil, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "get stack outputs") {
		t.Errorf("error should mention stack outputs: %v", err)
	}
}

func TestRunSetupAWS_MissingOutputs(t *testing.T) {
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

	err := runSetupAWS(nil, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "stack outputs missing") {
		t.Errorf("error should mention missing outputs: %v", err)
	}
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

func TestRunSetupGCP_NoIssuerURL(t *testing.T) {
	mock := &mockEnclave{available: true}
	d := testDeps(mock)
	cfg := testConfig() // no AWS config, so no issuer URL
	d.loadConfig = func() (*config.Config, error) { return cfg, nil }
	d.lookPath = func(name string) (string, error) { return "/usr/local/bin/" + name, nil }
	d.execCommand = func(name string, args ...string) ([]byte, error) {
		// For gcloud config get-value project
		if len(args) > 0 && args[0] == "config" {
			return []byte("my-project\n"), nil
		}
		// For gcloud projects describe
		return []byte(`{"projectNumber":"123456789"}`), nil
	}
	withDeps(t, d)

	gcpProject = ""
	gcpIssuerURL = ""
	err := runSetupGCP(nil, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "no issuer URL") {
		t.Errorf("error should mention issuer URL: %v", err)
	}
}

func TestRunSetupGCP_Success(t *testing.T) {
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
	if savedCfg.GCP.ProjectNumber != "123456789" {
		t.Errorf("ProjectNumber = %q", savedCfg.GCP.ProjectNumber)
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
