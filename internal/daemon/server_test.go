package daemon

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/credctl/credctl/internal/aws"
	"github.com/credctl/credctl/internal/config"
	"github.com/credctl/credctl/internal/gcp"
)

func testServerDeps(cfg *config.Config) ServerDeps {
	return ServerDeps{
		LoadConfig: func() (*config.Config, error) { return cfg, nil },
		PublicKeyPath: func() (string, error) {
			return "/tmp/credctl-test/device.pub", nil
		},
		NewSignFn: func(keyTag string) func(data []byte) ([]byte, error) {
			return func(data []byte) ([]byte, error) {
				// Return a valid-looking DER signature for testing.
				// This won't verify but is structurally correct for BuildAndSign.
				return []byte{0x30, 0x44, 0x02, 0x20,
					0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
					0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
					0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
					0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
					0x02, 0x20,
					0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
					0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
					0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
					0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
				}, nil
			}
		},
		AssumeRole: func(roleARN, sessionName, token, region string) (*aws.Credentials, error) {
			return &aws.Credentials{
				AccessKeyID:    "AKIATEST",
				SecretAccessKey: "secret-key",
				SessionToken:   "session-token",
				Expiration:     time.Now().Add(1 * time.Hour),
			}, nil
		},
		GCPExchangeToken: func(audience, subjectToken string) (*gcp.FederatedToken, error) {
			return &gcp.FederatedToken{
				AccessToken: "federated-token",
				ExpiresIn:   3600,
				TokenType:   "Bearer",
			}, nil
		},
		GCPGenerateAccessToken: func(sa, token string, scopes []string) (*gcp.AccessToken, error) {
			return &gcp.AccessToken{
				Token:      "ya29.test-access-token",
				ExpireTime: time.Now().Add(1 * time.Hour),
			}, nil
		},
	}
}

// testSeq is used to generate unique short socket paths.
var testSeq int

func setupTestServer(t *testing.T, cfg *config.Config) (*Server, string) {
	t.Helper()

	// Generate a real EC P-256 key pair.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal pub key: %v", err)
	}
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})

	tmpDir := t.TempDir()
	pubKeyPath := filepath.Join(tmpDir, "device.pub")
	if err := os.WriteFile(pubKeyPath, pubKeyPEM, 0600); err != nil {
		t.Fatalf("write pub key: %v", err)
	}

	deps := testServerDeps(cfg)
	deps.PublicKeyPath = func() (string, error) { return pubKeyPath, nil }

	// Use a short socket path to avoid Unix socket path length limits (104 bytes on macOS).
	testSeq++
	sockDir := fmt.Sprintf("/tmp/credctl-test-%d", testSeq)
	if err := os.MkdirAll(sockDir, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(sockDir) })

	socketPath := filepath.Join(sockDir, "d.sock")
	pidPath := filepath.Join(sockDir, "d.pid")

	srv := NewServer(socketPath, pidPath, 0, deps) // 0 = no idle timeout
	return srv, socketPath
}

func startTestServer(t *testing.T, srv *Server) {
	t.Helper()
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Start()
	}()

	// Wait for server to be ready.
	time.Sleep(50 * time.Millisecond)

	t.Cleanup(func() {
		srv.Shutdown(nil)
		if err := <-errCh; err != nil {
			t.Logf("server error: %v", err)
		}
	})
}

func TestServer_Status(t *testing.T) {
	cfg := &config.Config{
		Version:  1,
		DeviceID: "SHA256:testfp12345678",
		KeyTag:   "com.crzy.credctl.test-key",
	}
	srv, socketPath := setupTestServer(t, cfg)
	startTestServer(t, srv)

	client := httpClient(socketPath)
	resp, err := client.Get("http://daemon/v1/status")
	if err != nil {
		t.Fatalf("status request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status code = %d, want 200", resp.StatusCode)
	}

	var status StatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if status.PID == 0 {
		t.Error("expected non-zero PID")
	}
}

func TestServer_Clear(t *testing.T) {
	cfg := &config.Config{
		Version:  1,
		DeviceID: "SHA256:testfp12345678",
		KeyTag:   "com.crzy.credctl.test-key",
	}
	srv, socketPath := setupTestServer(t, cfg)
	startTestServer(t, srv)

	client := httpClient(socketPath)
	resp, err := client.Post("http://daemon/v1/clear", "application/json", nil)
	if err != nil {
		t.Fatalf("clear request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status code = %d, want 200", resp.StatusCode)
	}
}

func TestServer_AWSCredentials(t *testing.T) {
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

	client := httpClient(socketPath)

	// First request — cache miss.
	resp, err := client.Get("http://daemon/v1/credentials/aws?format=credential_process")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %s", resp.StatusCode, string(body))
	}
	if resp.Header.Get("X-Credctl-Cache") != "miss" {
		t.Error("expected cache miss on first request")
	}

	var creds credentialProcessOutput
	if err := json.NewDecoder(resp.Body).Decode(&creds); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if creds.AccessKeyID != "AKIATEST" {
		t.Errorf("AccessKeyID = %s, want AKIATEST", creds.AccessKeyID)
	}

	// Second request — cache hit.
	resp2, err := client.Get("http://daemon/v1/credentials/aws?format=credential_process")
	if err != nil {
		t.Fatalf("second request: %v", err)
	}
	defer resp2.Body.Close()

	if resp2.Header.Get("X-Credctl-Cache") != "hit" {
		t.Error("expected cache hit on second request")
	}
}

func TestServer_GCPCredentials_Executable(t *testing.T) {
	cfg := &config.Config{
		Version:  1,
		DeviceID: "SHA256:testfp12345678",
		KeyTag:   "com.crzy.credctl.test-key",
		GCP: &config.GCPConfig{
			ProjectNumber:       "123456789",
			WorkloadPoolID:      "credctl-pool",
			ProviderID:          "credctl-provider",
			ServiceAccountEmail: "credctl@project.iam.gserviceaccount.com",
			IssuerURL:           "https://d1234.cloudfront.net",
		},
	}
	srv, socketPath := setupTestServer(t, cfg)
	startTestServer(t, srv)

	client := httpClient(socketPath)
	resp, err := client.Get("http://daemon/v1/credentials/gcp?format=executable")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %s", resp.StatusCode, string(body))
	}

	var out executableOutput
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !out.Success {
		t.Error("expected success=true")
	}
}

func TestServer_GCPCredentials_Env(t *testing.T) {
	cfg := &config.Config{
		Version:  1,
		DeviceID: "SHA256:testfp12345678",
		KeyTag:   "com.crzy.credctl.test-key",
		GCP: &config.GCPConfig{
			ProjectNumber:       "123456789",
			WorkloadPoolID:      "credctl-pool",
			ProviderID:          "credctl-provider",
			ServiceAccountEmail: "credctl@project.iam.gserviceaccount.com",
			IssuerURL:           "https://d1234.cloudfront.net",
		},
	}
	srv, socketPath := setupTestServer(t, cfg)
	startTestServer(t, srv)

	client := httpClient(socketPath)
	resp, err := client.Get("http://daemon/v1/credentials/gcp?format=env")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %s", resp.StatusCode, string(body))
	}

	var out gcpEnvOutput
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.AccessToken != "ya29.test-access-token" {
		t.Errorf("access_token = %s, want ya29.test-access-token", out.AccessToken)
	}
}

func TestServer_UnknownProvider(t *testing.T) {
	cfg := &config.Config{
		Version:  1,
		DeviceID: "SHA256:testfp12345678",
		KeyTag:   "com.crzy.credctl.test-key",
	}
	srv, socketPath := setupTestServer(t, cfg)
	startTestServer(t, srv)

	client := httpClient(socketPath)
	resp, err := client.Get("http://daemon/v1/credentials/azure")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestServer_AWSNotConfigured(t *testing.T) {
	cfg := &config.Config{
		Version:  1,
		DeviceID: "SHA256:testfp12345678",
		KeyTag:   "com.crzy.credctl.test-key",
		// No AWS config.
	}
	srv, socketPath := setupTestServer(t, cfg)
	startTestServer(t, srv)

	client := httpClient(socketPath)
	resp, err := client.Get("http://daemon/v1/credentials/aws")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}
