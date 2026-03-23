package cli

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/credctl/credctl/internal/aws"
	"github.com/credctl/credctl/internal/config"
	"github.com/credctl/credctl/internal/gcp"
)

// setupSigningTest creates a real EC key and returns the mock enclave, pub key path, and private key.
func setupSigningTest(t *testing.T) (*mockEnclave, string) {
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

	mock := &mockEnclave{
		available: true,
		sign: func(tag string, data []byte) ([]byte, error) {
			hash := sha256.Sum256(data)
			return ecdsa.SignASN1(rand.Reader, priv, hash[:])
		},
	}

	return mock, pubKeyPath
}

// --- AWS auth tests ---

func TestRunAuth_NotInitialised(t *testing.T) {
	mock := &mockEnclave{available: true}
	d := testDeps(mock)
	d.loadConfig = func() (*config.Config, error) { return nil, nil }
	withDeps(t, d)

	authProvider = "aws"
	authFormat = "credential_process"
	err := runAuth(nil, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "device not initialised") {
		t.Errorf("error should mention not initialised: %v", err)
	}
}

func TestRunAuth_NoAWSConfig(t *testing.T) {
	mock := &mockEnclave{available: true}
	d := testDeps(mock)
	cfg := testConfig()
	d.loadConfig = func() (*config.Config, error) { return cfg, nil }
	withDeps(t, d)

	authProvider = "aws"
	authFormat = "credential_process"
	err := runAuth(nil, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "AWS not configured") {
		t.Errorf("error should mention AWS not configured: %v", err)
	}
}

func TestRunAuth_CredentialProcess(t *testing.T) {
	mock, pubKeyPath := setupSigningTest(t)

	d := testDeps(mock)
	cfg := testConfigWithAWS()
	d.loadConfig = func() (*config.Config, error) { return cfg, nil }
	d.publicKeyPath = func() (string, error) { return pubKeyPath, nil }
	d.assumeRole = func(roleARN, sessionName, token, region string) (*aws.Credentials, error) {
		return &aws.Credentials{
			AccessKeyID:    "AKIATEST",
			SecretAccessKey: "secret",
			SessionToken:   "token",
			Expiration:     time.Now().Add(1 * time.Hour),
		}, nil
	}
	withDeps(t, d)

	authProvider = "aws"
	authFormat = "credential_process"
	err := runAuth(nil, nil)
	if err != nil {
		t.Fatalf("runAuth: %v", err)
	}
}

func TestRunAuth_UnknownFormat(t *testing.T) {
	mock, pubKeyPath := setupSigningTest(t)

	d := testDeps(mock)
	cfg := testConfigWithAWS()
	d.loadConfig = func() (*config.Config, error) { return cfg, nil }
	d.publicKeyPath = func() (string, error) { return pubKeyPath, nil }
	withDeps(t, d)

	authProvider = "aws"
	authFormat = "xml"
	err := runAuth(nil, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "unknown format") {
		t.Errorf("error should mention unknown format: %v", err)
	}
}

func TestRunAuth_EnvFormat(t *testing.T) {
	mock, pubKeyPath := setupSigningTest(t)

	d := testDeps(mock)
	cfg := testConfigWithAWS()
	d.loadConfig = func() (*config.Config, error) { return cfg, nil }
	d.publicKeyPath = func() (string, error) { return pubKeyPath, nil }
	withDeps(t, d)

	authProvider = "aws"
	authFormat = "env"
	err := runAuth(nil, nil)
	if err != nil {
		t.Fatalf("runAuth with env format: %v", err)
	}
}

func TestRunAuth_STSError(t *testing.T) {
	mock, pubKeyPath := setupSigningTest(t)

	d := testDeps(mock)
	cfg := testConfigWithAWS()
	d.loadConfig = func() (*config.Config, error) { return cfg, nil }
	d.publicKeyPath = func() (string, error) { return pubKeyPath, nil }
	d.assumeRole = func(roleARN, sessionName, token, region string) (*aws.Credentials, error) {
		return nil, errMock("STS error (AccessDenied): not authorized")
	}
	withDeps(t, d)

	authProvider = "aws"
	authFormat = "credential_process"
	err := runAuth(nil, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "assume role") {
		t.Errorf("error should mention assume role: %v", err)
	}
}

func TestRunAuth_UnknownProvider(t *testing.T) {
	mock := &mockEnclave{available: true}
	d := testDeps(mock)
	cfg := testConfig()
	d.loadConfig = func() (*config.Config, error) { return cfg, nil }
	withDeps(t, d)

	authProvider = "azure"
	err := runAuth(nil, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "unknown provider") {
		t.Errorf("error should mention unknown provider: %v", err)
	}
}

// --- GCP auth tests ---

func TestRunAuth_GCP_NotConfigured(t *testing.T) {
	mock := &mockEnclave{available: true}
	d := testDeps(mock)
	cfg := testConfig()
	d.loadConfig = func() (*config.Config, error) { return cfg, nil }
	withDeps(t, d)

	authProvider = "gcp"
	authFormat = "executable"
	err := runAuth(nil, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "GCP not configured") {
		t.Errorf("error should mention GCP not configured: %v", err)
	}
}

func TestRunAuth_GCP_ExecutableFormat(t *testing.T) {
	mock, pubKeyPath := setupSigningTest(t)

	d := testDeps(mock)
	cfg := testConfigWithGCP()
	d.loadConfig = func() (*config.Config, error) { return cfg, nil }
	d.publicKeyPath = func() (string, error) { return pubKeyPath, nil }
	withDeps(t, d)

	authProvider = "gcp"
	authFormat = "executable"
	err := runAuth(nil, nil)
	if err != nil {
		t.Fatalf("runAuth GCP executable: %v", err)
	}
}

func TestRunAuth_GCP_EnvFormat(t *testing.T) {
	mock, pubKeyPath := setupSigningTest(t)

	d := testDeps(mock)
	cfg := testConfigWithGCP()
	d.loadConfig = func() (*config.Config, error) { return cfg, nil }
	d.publicKeyPath = func() (string, error) { return pubKeyPath, nil }
	withDeps(t, d)

	authProvider = "gcp"
	authFormat = "env"
	err := runAuth(nil, nil)
	if err != nil {
		t.Fatalf("runAuth GCP env: %v", err)
	}
}

func TestRunAuth_GCP_ExchangeError(t *testing.T) {
	mock, pubKeyPath := setupSigningTest(t)

	d := testDeps(mock)
	cfg := testConfigWithGCP()
	d.loadConfig = func() (*config.Config, error) { return cfg, nil }
	d.publicKeyPath = func() (string, error) { return pubKeyPath, nil }
	d.gcpExchangeToken = func(audience, subjectToken string) (*gcp.FederatedToken, error) {
		return nil, fmt.Errorf("STS error (INVALID_ARGUMENT): invalid token")
	}
	withDeps(t, d)

	authProvider = "gcp"
	authFormat = "env"
	err := runAuth(nil, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "token exchange") {
		t.Errorf("error should mention token exchange: %v", err)
	}
}

func TestRunAuth_GCP_GenerateAccessTokenError(t *testing.T) {
	mock, pubKeyPath := setupSigningTest(t)

	d := testDeps(mock)
	cfg := testConfigWithGCP()
	d.loadConfig = func() (*config.Config, error) { return cfg, nil }
	d.publicKeyPath = func() (string, error) { return pubKeyPath, nil }
	d.gcpGenerateAccessToken = func(sa, token string, scopes []string) (*gcp.AccessToken, error) {
		return nil, fmt.Errorf("IAM error (PERMISSION_DENIED): not authorized")
	}
	withDeps(t, d)

	authProvider = "gcp"
	authFormat = "env"
	err := runAuth(nil, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "generate access token") {
		t.Errorf("error should mention generate access token: %v", err)
	}
}

func TestRunAuth_GCP_DefaultFormat(t *testing.T) {
	mock, pubKeyPath := setupSigningTest(t)

	d := testDeps(mock)
	cfg := testConfigWithGCP()
	d.loadConfig = func() (*config.Config, error) { return cfg, nil }
	d.publicKeyPath = func() (string, error) { return pubKeyPath, nil }
	withDeps(t, d)

	authProvider = "gcp"
	authFormat = "" // should default to executable
	err := runAuth(nil, nil)
	if err != nil {
		t.Fatalf("runAuth GCP default format: %v", err)
	}
}

func TestRunAuth_GCP_UnknownFormat(t *testing.T) {
	mock, pubKeyPath := setupSigningTest(t)

	d := testDeps(mock)
	cfg := testConfigWithGCP()
	d.loadConfig = func() (*config.Config, error) { return cfg, nil }
	d.publicKeyPath = func() (string, error) { return pubKeyPath, nil }
	withDeps(t, d)

	authProvider = "gcp"
	authFormat = "xml"
	err := runAuth(nil, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "unknown format") {
		t.Errorf("error should mention unknown format: %v", err)
	}
}

func TestRunAuth_AWS_DefaultFormat(t *testing.T) {
	mock, pubKeyPath := setupSigningTest(t)

	d := testDeps(mock)
	cfg := testConfigWithAWS()
	d.loadConfig = func() (*config.Config, error) { return cfg, nil }
	d.publicKeyPath = func() (string, error) { return pubKeyPath, nil }
	withDeps(t, d)

	authProvider = "aws"
	authFormat = "" // should default to credential_process
	err := runAuth(nil, nil)
	if err != nil {
		t.Fatalf("runAuth AWS default format: %v", err)
	}
}

func TestRunAuth_SignError(t *testing.T) {
	mock := &mockEnclave{
		available: true,
		sign: func(tag string, data []byte) ([]byte, error) {
			return nil, errMock("Touch ID cancelled")
		},
	}

	tmpDir := t.TempDir()
	// Need a real public key on disk for prepareSign to work.
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	pubKeyPath := filepath.Join(tmpDir, "device.pub")
	os.WriteFile(pubKeyPath, pubPEM, 0600)

	d := testDeps(mock)
	cfg := testConfigWithAWS()
	d.loadConfig = func() (*config.Config, error) { return cfg, nil }
	d.publicKeyPath = func() (string, error) { return pubKeyPath, nil }
	withDeps(t, d)

	authProvider = "aws"
	authFormat = "credential_process"
	err := runAuth(nil, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "build JWT") {
		t.Errorf("error should mention JWT build: %v", err)
	}
}

func TestRunAuth_PublicKeyNotFound(t *testing.T) {
	mock := &mockEnclave{available: true}
	d := testDeps(mock)
	cfg := testConfigWithAWS()
	d.loadConfig = func() (*config.Config, error) { return cfg, nil }
	d.publicKeyPath = func() (string, error) { return "/nonexistent/device.pub", nil }
	withDeps(t, d)

	authProvider = "aws"
	authFormat = "credential_process"
	err := runAuth(nil, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "read public key") {
		t.Errorf("error should mention public key: %v", err)
	}
}
