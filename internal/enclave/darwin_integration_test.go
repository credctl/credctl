//go:build integration

package enclave

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
)

const testKeyTag = "com.crzy.credctl.test-key"

// cleanup deletes the test key, ignoring errors (key may not exist).
func cleanup(t *testing.T, enc Enclave, tag string) {
	t.Helper()
	_ = enc.DeleteKey(tag)
}

// requireKeychain attempts to generate a probe key and skips the test if
// the Secure Enclave keychain is not accessible (e.g. unsigned test binary).
func requireKeychain(t *testing.T, enc Enclave) {
	t.Helper()
	tag := testKeyTag + ".probe"
	_, err := enc.GenerateKey(tag, BiometricNone)
	if err != nil {
		_ = enc.DeleteKey(tag)
		if strings.Contains(err.Error(), "-34018") || strings.Contains(err.Error(), "OSStatus") {
			t.Skip("Secure Enclave keychain not accessible (binary not codesigned with entitlements)")
		}
	} else {
		_ = enc.DeleteKey(tag)
	}
}

func TestSecureEnclave_GenerateLoadDelete(t *testing.T) {
	enc := New()
	if !enc.Available() {
		t.Skip("Secure Enclave not available")
	}
	requireKeychain(t, enc)

	tag := testKeyTag + ".gen-load-del"
	t.Cleanup(func() { cleanup(t, enc, tag) })

	// Generate
	key, err := enc.GenerateKey(tag, BiometricNone)
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

func TestSecureEnclave_Sign(t *testing.T) {
	enc := New()
	if !enc.Available() {
		t.Skip("Secure Enclave not available")
	}
	requireKeychain(t, enc)

	tag := testKeyTag + ".sign"
	t.Cleanup(func() { cleanup(t, enc, tag) })

	key, err := enc.GenerateKey(tag, BiometricNone)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	data := []byte("hello, secure enclave")
	sig, err := enc.Sign(tag, data)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Parse the public key from PEM
	block, _ := pem.Decode(key.PublicKey)
	if block == nil {
		t.Fatal("invalid PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("ParsePKIXPublicKey: %v", err)
	}
	ecPub := pub.(*ecdsa.PublicKey)

	// The Secure Enclave signs with kSecKeyAlgorithmECDSASignatureMessageX962SHA256
	// which hashes the data with SHA-256 then signs. The signature is DER-encoded.
	hash := sha256.Sum256(data)
	if !ecdsa.VerifyASN1(ecPub, hash[:], sig) {
		t.Error("signature verification failed")
	}
}

func TestSecureEnclave_LoadNotFound(t *testing.T) {
	enc := New()
	if !enc.Available() {
		t.Skip("Secure Enclave not available")
	}

	_, err := enc.LoadKey("com.crzy.credctl.nonexistent-key-that-does-not-exist")
	if err == nil {
		t.Error("expected error for nonexistent key")
	}
}

func TestSecureEnclave_DeleteNotFound(t *testing.T) {
	enc := New()
	if !enc.Available() {
		t.Skip("Secure Enclave not available")
	}

	// errSecItemNotFound is OK per the implementation
	err := enc.DeleteKey("com.crzy.credctl.nonexistent-key-that-does-not-exist")
	if err != nil {
		t.Errorf("delete nonexistent key should succeed: %v", err)
	}
}

func TestSecureEnclave_DuplicateTag(t *testing.T) {
	enc := New()
	if !enc.Available() {
		t.Skip("Secure Enclave not available")
	}
	requireKeychain(t, enc)

	tag := testKeyTag + ".duplicate"
	t.Cleanup(func() { cleanup(t, enc, tag) })

	_, err := enc.GenerateKey(tag, BiometricNone)
	if err != nil {
		t.Fatalf("first GenerateKey: %v", err)
	}

	_, err = enc.GenerateKey(tag)
	if err == nil {
		t.Error("expected error generating duplicate key")
	}
	if !strings.Contains(err.Error(), "failed") && !strings.Contains(err.Error(), "duplicate") {
		t.Logf("duplicate key error: %v", err)
	}
}
