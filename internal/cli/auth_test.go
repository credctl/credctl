package cli

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/credctl/credctl/internal/aws"
	"github.com/credctl/credctl/internal/config"
)

func TestRunAuth_NotInitialised(t *testing.T) {
	mock := &mockEnclave{available: true}
	d := testDeps(mock)
	d.loadConfig = func() (*config.Config, error) { return nil, nil }
	withDeps(t, d)

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
	cfg := testConfig() // no AWS config
	d.loadConfig = func() (*config.Config, error) { return cfg, nil }
	withDeps(t, d)

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
	// Generate a real EC key so JWT signing works
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})

	// Write public key to temp file
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

	authFormat = "credential_process"
	err = runAuth(nil, nil)
	if err != nil {
		t.Fatalf("runAuth: %v", err)
	}
}

func TestRunAuth_UnknownFormat(t *testing.T) {
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
	os.WriteFile(pubKeyPath, pubPEM, 0600)

	mock := &mockEnclave{
		available: true,
		sign: func(tag string, data []byte) ([]byte, error) {
			hash := sha256.Sum256(data)
			return ecdsa.SignASN1(rand.Reader, priv, hash[:])
		},
	}

	d := testDeps(mock)
	cfg := testConfigWithAWS()
	d.loadConfig = func() (*config.Config, error) { return cfg, nil }
	d.publicKeyPath = func() (string, error) { return pubKeyPath, nil }
	withDeps(t, d)

	authFormat = "xml"
	err = runAuth(nil, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "unknown format") {
		t.Errorf("error should mention unknown format: %v", err)
	}
}

func TestRunAuth_EnvFormat(t *testing.T) {
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
	os.WriteFile(pubKeyPath, pubPEM, 0600)

	mock := &mockEnclave{
		available: true,
		sign: func(tag string, data []byte) ([]byte, error) {
			hash := sha256.Sum256(data)
			return ecdsa.SignASN1(rand.Reader, priv, hash[:])
		},
	}

	d := testDeps(mock)
	cfg := testConfigWithAWS()
	d.loadConfig = func() (*config.Config, error) { return cfg, nil }
	d.publicKeyPath = func() (string, error) { return pubKeyPath, nil }
	withDeps(t, d)

	authFormat = "env"
	err = runAuth(nil, nil)
	if err != nil {
		t.Fatalf("runAuth with env format: %v", err)
	}
}

func TestRunAuth_STSError(t *testing.T) {
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
	os.WriteFile(pubKeyPath, pubPEM, 0600)

	mock := &mockEnclave{
		available: true,
		sign: func(tag string, data []byte) ([]byte, error) {
			hash := sha256.Sum256(data)
			return ecdsa.SignASN1(rand.Reader, priv, hash[:])
		},
	}

	d := testDeps(mock)
	cfg := testConfigWithAWS()
	d.loadConfig = func() (*config.Config, error) { return cfg, nil }
	d.publicKeyPath = func() (string, error) { return pubKeyPath, nil }
	d.assumeRole = func(roleARN, sessionName, token, region string) (*aws.Credentials, error) {
		return nil, errMock("STS error (AccessDenied): not authorized")
	}
	withDeps(t, d)

	authFormat = "credential_process"
	err = runAuth(nil, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "assume role") {
		t.Errorf("error should mention assume role: %v", err)
	}
}
