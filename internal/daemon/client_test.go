package daemon

import (
	"encoding/json"
	"testing"

	"github.com/credctl/credctl/internal/config"
)

func TestClient_DaemonRunning(t *testing.T) {
	// Non-existent socket.
	if DaemonRunning("/nonexistent/socket.sock") {
		t.Error("expected false for nonexistent socket")
	}
}

func TestClient_FetchCredentials(t *testing.T) {
	cfg := &config.Config{
		Version:  1,
		DeviceID: "SHA256:testfp12345678",
		KeyTag:   "com.crzy.credctl.test-key",
		AWS: &config.AWSConfig{
			RoleARN:   "arn:aws:iam::123456789012:role/test",
			IssuerURL: "https://d1234.cloudfront.net",
			Region:    "us-east-1",
		},
	}
	srv, socketPath := setupTestServer(t, cfg)
	startTestServer(t, srv)

	// Test DaemonRunning with real server.
	if !DaemonRunning(socketPath) {
		t.Fatal("expected daemon to be running")
	}

	// Test FetchCredentials.
	data, err := FetchCredentials(socketPath, "aws", "credential_process")
	if err != nil {
		t.Fatalf("FetchCredentials: %v", err)
	}

	var creds credentialProcessOutput
	if err := json.Unmarshal(data, &creds); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if creds.AccessKeyID != "AKIATEST" {
		t.Errorf("AccessKeyID = %s, want AKIATEST", creds.AccessKeyID)
	}
}

func TestClient_FetchStatus(t *testing.T) {
	cfg := &config.Config{
		Version:  1,
		DeviceID: "SHA256:testfp12345678",
		KeyTag:   "com.crzy.credctl.test-key",
	}
	srv, socketPath := setupTestServer(t, cfg)
	startTestServer(t, srv)

	status, err := FetchStatus(socketPath)
	if err != nil {
		t.Fatalf("FetchStatus: %v", err)
	}
	if status.PID == 0 {
		t.Error("expected non-zero PID")
	}
}

func TestClient_ClearCache(t *testing.T) {
	cfg := &config.Config{
		Version:  1,
		DeviceID: "SHA256:testfp12345678",
		KeyTag:   "com.crzy.credctl.test-key",
	}
	srv, socketPath := setupTestServer(t, cfg)
	startTestServer(t, srv)

	if err := ClearCache(socketPath); err != nil {
		t.Fatalf("ClearCache: %v", err)
	}
}

func TestClient_FetchCredentials_DaemonNotRunning(t *testing.T) {
	_, err := FetchCredentials("/nonexistent/socket.sock", "aws", "credential_process")
	if err == nil {
		t.Fatal("expected error for nonexistent socket")
	}
}
