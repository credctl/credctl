//go:build linux

package enclave

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

// nopCloser wraps a TPMCloser but makes Close() a no-op so the simulator
// stays open across multiple openTPM() calls within a single test.
type nopCloser struct {
	tpm transport.TPMCloser
}

func (n *nopCloser) Send(input []byte) ([]byte, error) {
	return n.tpm.Send(input)
}

func (n *nopCloser) Close() error { return nil }

// withSimulator opens a single TPM simulator for the test and overrides
// openTPM to return it on every call. The simulator is closed at test cleanup.
func withSimulator(t *testing.T) {
	t.Helper()
	orig := openTPM

	sim, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not open TPM simulator: %v", err)
	}

	openTPM = func() (transport.TPMCloser, error) {
		return &nopCloser{tpm: sim}, nil
	}

	t.Cleanup(func() {
		openTPM = orig
		sim.Close()
	})
}

func TestTPM_GenerateLoadDelete(t *testing.T) {
	withSimulator(t)
	enc := &tpmEnclave{}

	tag := "com.crzy.credctl.test-key"

	// Generate
	key, err := enc.GenerateKey(tag)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	// Verify PEM format
	block, _ := pem.Decode(key.PublicKey)
	if block == nil {
		t.Fatal("public key is not valid PEM")
	}
	if block.Type != "PUBLIC KEY" {
		t.Errorf("PEM type = %q, want PUBLIC KEY", block.Type)
	}

	// Parse and verify P-256 curve
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("ParsePKIXPublicKey: %v", err)
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", pub)
	}
	if ecPub.Curve != elliptic.P256() {
		t.Error("expected P-256 curve")
	}

	// Verify fingerprint format
	if !strings.HasPrefix(key.Fingerprint, "SHA256:") {
		t.Errorf("fingerprint %q does not start with SHA256:", key.Fingerprint)
	}

	// Verify tag
	if key.Tag != tag {
		t.Errorf("tag = %q, want %q", key.Tag, tag)
	}

	// Load same key
	loaded, err := enc.LoadKey(tag)
	if err != nil {
		t.Fatalf("LoadKey: %v", err)
	}
	if loaded.Fingerprint != key.Fingerprint {
		t.Errorf("fingerprints differ: generated=%q loaded=%q", key.Fingerprint, loaded.Fingerprint)
	}

	// Delete
	if err := enc.DeleteKey(tag); err != nil {
		t.Fatalf("DeleteKey: %v", err)
	}

	// Load should fail after delete
	_, err = enc.LoadKey(tag)
	if err == nil {
		t.Error("expected error loading deleted key")
	}
}

func TestTPM_Sign(t *testing.T) {
	withSimulator(t)
	enc := &tpmEnclave{}

	tag := "com.crzy.credctl.test-sign"
	key, err := enc.GenerateKey(tag)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	t.Cleanup(func() { enc.DeleteKey(tag) })

	data := []byte("hello, TPM 2.0")
	sig, err := enc.Sign(tag, data)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Parse public key and verify signature
	block, _ := pem.Decode(key.PublicKey)
	if block == nil {
		t.Fatal("invalid PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("ParsePKIXPublicKey: %v", err)
	}
	ecPub := pub.(*ecdsa.PublicKey)

	// TPM signs a SHA-256 digest; verify with the same hash
	hash := sha256.Sum256(data)
	if !ecdsa.VerifyASN1(ecPub, hash[:], sig) {
		t.Error("signature verification failed")
	}
}

func TestTPM_DuplicateKey(t *testing.T) {
	withSimulator(t)
	enc := &tpmEnclave{}

	tag := "com.crzy.credctl.test-dup"
	_, err := enc.GenerateKey(tag)
	if err != nil {
		t.Fatalf("first GenerateKey: %v", err)
	}
	t.Cleanup(func() { enc.DeleteKey(tag) })

	_, err = enc.GenerateKey(tag)
	if err == nil {
		t.Fatal("expected error generating duplicate key")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestTPM_DeleteNotFound(t *testing.T) {
	withSimulator(t)
	enc := &tpmEnclave{}

	// Deleting a non-existent key should succeed (idempotent)
	err := enc.DeleteKey("com.crzy.credctl.nonexistent")
	if err != nil {
		t.Errorf("delete nonexistent key should succeed: %v", err)
	}
}

func TestTPM_LoadNotFound(t *testing.T) {
	withSimulator(t)
	enc := &tpmEnclave{}

	_, err := enc.LoadKey("com.crzy.credctl.nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent key")
	}
}
