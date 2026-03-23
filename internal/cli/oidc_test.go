package cli

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/credctl/credctl/internal/config"
)

func setupOIDCTest(t *testing.T) (string, string) {
	t.Helper()
	// Generate a real EC key for OIDC tests.
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
	return tmpDir, pubKeyPath
}

func TestRunOIDCGenerate_Success(t *testing.T) {
	tmpDir, _ := setupOIDCTest(t)

	mock := &mockEnclave{available: true}
	d := testDeps(mock)
	cfg := testConfigWithAWS()
	d.loadConfig = func() (*config.Config, error) { return cfg, nil }
	d.configDir = func() (string, error) { return tmpDir, nil }
	d.publicKeyPath = func() (string, error) { return filepath.Join(tmpDir, "device.pub"), nil }
	d.saveConfig = func(c *config.Config) error { return nil }
	withDeps(t, d)

	oidcIssuerURL = "https://d1234.cloudfront.net"
	err := runOIDCGenerate(nil, nil)
	if err != nil {
		t.Fatalf("runOIDCGenerate: %v", err)
	}

	// Verify files were created.
	discoveryPath := filepath.Join(tmpDir, "oidc", ".well-known", "openid-configuration")
	if _, err := os.Stat(discoveryPath); err != nil {
		t.Errorf("discovery document not created: %v", err)
	}
	keysPath := filepath.Join(tmpDir, "oidc", "keys.json")
	if _, err := os.Stat(keysPath); err != nil {
		t.Errorf("keys.json not created: %v", err)
	}
}

func TestRunOIDCGenerate_MergesExistingJWKS(t *testing.T) {
	tmpDir, _ := setupOIDCTest(t)

	mock := &mockEnclave{available: true}
	d := testDeps(mock)
	cfg := testConfigWithAWS()
	d.loadConfig = func() (*config.Config, error) { return cfg, nil }
	d.configDir = func() (string, error) { return tmpDir, nil }
	d.publicKeyPath = func() (string, error) { return filepath.Join(tmpDir, "device.pub"), nil }
	d.saveConfig = func(c *config.Config) error { return nil }
	withDeps(t, d)

	// Create an existing JWKS file.
	oidcDir := filepath.Join(tmpDir, "oidc")
	os.MkdirAll(filepath.Join(oidcDir, ".well-known"), 0700)
	existingJWKS := `{"keys":[{"kty":"EC","crv":"P-256","x":"abc","y":"def","kid":"old-key","use":"sig","alg":"ES256"}]}`
	os.WriteFile(filepath.Join(oidcDir, "keys.json"), []byte(existingJWKS), 0600)

	oidcIssuerURL = "https://d1234.cloudfront.net"
	err := runOIDCGenerate(nil, nil)
	if err != nil {
		t.Fatalf("runOIDCGenerate: %v", err)
	}

	// Read and verify JWKS has the new key.
	data, err := os.ReadFile(filepath.Join(oidcDir, "keys.json"))
	if err != nil {
		t.Fatalf("read JWKS: %v", err)
	}
	if !strings.Contains(string(data), "keys") {
		t.Error("JWKS should contain keys array")
	}
}

func TestRunOIDCGenerate_InvalidIssuerHTTP(t *testing.T) {
	oidcIssuerURL = "http://not-secure.example.com"
	err := runOIDCGenerate(nil, nil)
	if err == nil {
		t.Fatal("expected error for HTTP issuer URL")
	}
	if !strings.Contains(err.Error(), "HTTPS") {
		t.Errorf("error should mention HTTPS: %v", err)
	}
}

func TestRunOIDCGenerate_InvalidIssuerNoHost(t *testing.T) {
	oidcIssuerURL = "https://"
	err := runOIDCGenerate(nil, nil)
	if err == nil {
		t.Fatal("expected error for no hostname")
	}
	if !strings.Contains(err.Error(), "hostname") {
		t.Errorf("error should mention hostname: %v", err)
	}
}

func TestRunOIDCGenerate_NotInitialised(t *testing.T) {
	mock := &mockEnclave{available: true}
	d := testDeps(mock)
	d.loadConfig = func() (*config.Config, error) { return nil, nil }
	withDeps(t, d)

	oidcIssuerURL = "https://d1234.cloudfront.net"
	err := runOIDCGenerate(nil, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "device not initialised") {
		t.Errorf("error should mention not initialised: %v", err)
	}
}

func TestRunOIDCGenerate_ConfigLoadError(t *testing.T) {
	mock := &mockEnclave{available: true}
	d := testDeps(mock)
	d.loadConfig = func() (*config.Config, error) { return nil, errMock("disk error") }
	withDeps(t, d)

	oidcIssuerURL = "https://d1234.cloudfront.net"
	err := runOIDCGenerate(nil, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "failed to read config") {
		t.Errorf("error should mention config: %v", err)
	}
}

func TestRunOIDCPublish_FilesNotFound(t *testing.T) {
	tmpDir := t.TempDir()

	mock := &mockEnclave{available: true}
	d := testDeps(mock)
	d.configDir = func() (string, error) { return tmpDir, nil }
	withDeps(t, d)

	oidcPublishBucket = "test-bucket"
	oidcPublishRegion = "us-east-1"
	err := runOIDCPublish(nil, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "OIDC files not found") {
		t.Errorf("error should mention files not found: %v", err)
	}
}

func TestRunOIDCPublish_Success(t *testing.T) {
	tmpDir := t.TempDir()

	// Create the expected OIDC files.
	oidcDir := filepath.Join(tmpDir, "oidc")
	os.MkdirAll(filepath.Join(oidcDir, ".well-known"), 0700)
	os.WriteFile(filepath.Join(oidcDir, ".well-known", "openid-configuration"), []byte(`{}`), 0600)
	os.WriteFile(filepath.Join(oidcDir, "keys.json"), []byte(`{}`), 0600)

	mock := &mockEnclave{available: true}
	d := testDeps(mock)
	cfg := testConfigWithAWS()
	d.configDir = func() (string, error) { return tmpDir, nil }
	d.loadConfig = func() (*config.Config, error) { return cfg, nil }
	d.saveConfig = func(c *config.Config) error { return nil }
	d.execCommand = func(name string, args ...string) ([]byte, error) {
		return nil, nil // s3 cp succeeds
	}
	withDeps(t, d)

	oidcPublishBucket = "test-bucket"
	oidcPublishRegion = "us-east-1"
	err := runOIDCPublish(nil, nil)
	if err != nil {
		t.Fatalf("runOIDCPublish: %v", err)
	}
}

func TestRunOIDCPublish_S3UploadFails(t *testing.T) {
	tmpDir := t.TempDir()

	oidcDir := filepath.Join(tmpDir, "oidc")
	os.MkdirAll(filepath.Join(oidcDir, ".well-known"), 0700)
	os.WriteFile(filepath.Join(oidcDir, ".well-known", "openid-configuration"), []byte(`{}`), 0600)
	os.WriteFile(filepath.Join(oidcDir, "keys.json"), []byte(`{}`), 0600)

	mock := &mockEnclave{available: true}
	d := testDeps(mock)
	d.configDir = func() (string, error) { return tmpDir, nil }
	d.execCommand = func(name string, args ...string) ([]byte, error) {
		return []byte("access denied"), errMock("exit status 1")
	}
	withDeps(t, d)

	oidcPublishBucket = "test-bucket"
	oidcPublishRegion = "us-east-1"
	err := runOIDCPublish(nil, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "upload discovery") {
		t.Errorf("error should mention upload: %v", err)
	}
}

func TestRunOIDCPublish_ConfigDirError(t *testing.T) {
	mock := &mockEnclave{available: true}
	d := testDeps(mock)
	d.configDir = func() (string, error) { return "", errMock("no home dir") }
	withDeps(t, d)

	err := runOIDCPublish(nil, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "config dir") {
		t.Errorf("error should mention config dir: %v", err)
	}
}

func TestRunOIDCGenerate_SaveConfigError(t *testing.T) {
	tmpDir, _ := setupOIDCTest(t)

	mock := &mockEnclave{available: true}
	d := testDeps(mock)
	cfg := testConfigWithAWS()
	d.loadConfig = func() (*config.Config, error) { return cfg, nil }
	d.configDir = func() (string, error) { return tmpDir, nil }
	d.publicKeyPath = func() (string, error) { return filepath.Join(tmpDir, "device.pub"), nil }
	d.saveConfig = func(c *config.Config) error { return errMock("disk full") }
	withDeps(t, d)

	oidcIssuerURL = "https://d1234.cloudfront.net"
	err := runOIDCGenerate(nil, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "save config") {
		t.Errorf("error should mention save config: %v", err)
	}
}
