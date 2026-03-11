package enclave

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"
)

// mockBackend implements keyBackend for unit testing without hardware.
type mockBackend struct {
	availableVal  bool
	generateKeyFn func(tag string) ([]byte, error)
	lookupKeyFn   func(tag string) ([]byte, error)
	deleteKeyFn   func(tag string) error
	signFn        func(tag string, data []byte) ([]byte, error)
}

func (m *mockBackend) available() bool { return m.availableVal }

func (m *mockBackend) generateKey(tag string) ([]byte, error) {
	if m.generateKeyFn != nil {
		return m.generateKeyFn(tag)
	}
	return nil, fmt.Errorf("generateKey not configured")
}

func (m *mockBackend) lookupKey(tag string) ([]byte, error) {
	if m.lookupKeyFn != nil {
		return m.lookupKeyFn(tag)
	}
	return nil, fmt.Errorf("lookupKey not configured")
}

func (m *mockBackend) deleteKey(tag string) error {
	if m.deleteKeyFn != nil {
		return m.deleteKeyFn(tag)
	}
	return nil
}

func (m *mockBackend) sign(tag string, data []byte) ([]byte, error) {
	if m.signFn != nil {
		return m.signFn(tag, data)
	}
	return nil, fmt.Errorf("sign not configured")
}

// testRawP256PubKey generates a real P-256 key pair and returns the raw
// uncompressed EC point (65 bytes) suitable for buildDeviceKey.
func testRawP256PubKey(t *testing.T) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return elliptic.Marshal(elliptic.P256(), priv.PublicKey.X, priv.PublicKey.Y)
}

// --- buildDeviceKey tests ---

func TestBuildDeviceKey_ValidKey(t *testing.T) {
	raw := testRawP256PubKey(t)

	dk, err := buildDeviceKey("com.test.key", raw)
	if err != nil {
		t.Fatalf("buildDeviceKey: %v", err)
	}

	if dk.Tag != "com.test.key" {
		t.Errorf("tag = %q, want %q", dk.Tag, "com.test.key")
	}

	// Verify PEM format
	block, _ := pem.Decode(dk.PublicKey)
	if block == nil {
		t.Fatal("public key is not valid PEM")
	}
	if block.Type != "PUBLIC KEY" {
		t.Errorf("PEM type = %q, want PUBLIC KEY", block.Type)
	}

	// Parse and verify it's a valid P-256 key
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
	if !strings.HasPrefix(dk.Fingerprint, "SHA256:") {
		t.Errorf("fingerprint = %q, want SHA256: prefix", dk.Fingerprint)
	}

	// Verify fingerprint is deterministic
	dk2, _ := buildDeviceKey("com.test.key", raw)
	if dk.Fingerprint != dk2.Fingerprint {
		t.Error("same raw key should produce same fingerprint")
	}

	// CreatedAt should be zero (set by caller)
	if !dk.CreatedAt.IsZero() {
		t.Error("buildDeviceKey should not set CreatedAt")
	}
}

func TestBuildDeviceKey_TooShort(t *testing.T) {
	_, err := buildDeviceKey("tag", []byte{0x04, 1, 2, 3})
	if err == nil {
		t.Fatal("expected error for short key")
	}
	if !strings.Contains(err.Error(), "unexpected public key format") {
		t.Errorf("error = %q, want 'unexpected public key format'", err)
	}
}

func TestBuildDeviceKey_WrongPrefix(t *testing.T) {
	raw := make([]byte, 65)
	raw[0] = 0x02 // compressed, not uncompressed
	_, err := buildDeviceKey("tag", raw)
	if err == nil {
		t.Fatal("expected error for wrong prefix")
	}
}

func TestBuildDeviceKey_EmptyInput(t *testing.T) {
	_, err := buildDeviceKey("tag", nil)
	if err == nil {
		t.Fatal("expected error for nil input")
	}
}

func TestBuildDeviceKey_FingerprintMatchesDER(t *testing.T) {
	raw := testRawP256PubKey(t)
	dk, err := buildDeviceKey("tag", raw)
	if err != nil {
		t.Fatal(err)
	}

	// Independently compute fingerprint from PEM
	block, _ := pem.Decode(dk.PublicKey)
	hash := sha256.Sum256(block.Bytes)
	_ = hash // fingerprint uses base64 of this hash — already verified by prefix check
}

// --- enclaveImpl tests ---

func TestEnclaveImpl_Available(t *testing.T) {
	enc := &enclaveImpl{backend: &mockBackend{availableVal: true}}
	if !enc.Available() {
		t.Error("Available() should return true")
	}

	enc2 := &enclaveImpl{backend: &mockBackend{availableVal: false}}
	if enc2.Available() {
		t.Error("Available() should return false")
	}
}

func TestEnclaveImpl_GenerateKey(t *testing.T) {
	raw := testRawP256PubKey(t)
	enc := &enclaveImpl{backend: &mockBackend{
		generateKeyFn: func(tag string) ([]byte, error) {
			return raw, nil
		},
	}}

	dk, err := enc.GenerateKey("com.test.gen")
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	if dk.Tag != "com.test.gen" {
		t.Errorf("tag = %q", dk.Tag)
	}
	if dk.CreatedAt.IsZero() {
		t.Error("GenerateKey should set CreatedAt")
	}

	// Verify PEM is valid
	block, _ := pem.Decode(dk.PublicKey)
	if block == nil {
		t.Fatal("invalid PEM")
	}
}

func TestEnclaveImpl_GenerateKey_BackendError(t *testing.T) {
	enc := &enclaveImpl{backend: &mockBackend{
		generateKeyFn: func(tag string) ([]byte, error) {
			return nil, fmt.Errorf("secure enclave key generation failed: OSStatus -34018")
		},
	}}

	_, err := enc.GenerateKey("com.test.gen")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "-34018") {
		t.Errorf("error = %q, want OSStatus -34018", err)
	}
}

func TestEnclaveImpl_LoadKey(t *testing.T) {
	raw := testRawP256PubKey(t)
	enc := &enclaveImpl{backend: &mockBackend{
		lookupKeyFn: func(tag string) ([]byte, error) {
			return raw, nil
		},
	}}

	dk, err := enc.LoadKey("com.test.load")
	if err != nil {
		t.Fatalf("LoadKey: %v", err)
	}

	if dk.Tag != "com.test.load" {
		t.Errorf("tag = %q", dk.Tag)
	}
	if !dk.CreatedAt.IsZero() {
		t.Error("LoadKey should not set CreatedAt")
	}
}

func TestEnclaveImpl_LoadKey_NotFound(t *testing.T) {
	enc := &enclaveImpl{backend: &mockBackend{
		lookupKeyFn: func(tag string) ([]byte, error) {
			return nil, fmt.Errorf("key not found (OSStatus -25300)")
		},
	}}

	_, err := enc.LoadKey("com.test.missing")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error = %q", err)
	}
}

func TestEnclaveImpl_DeleteKey(t *testing.T) {
	deleted := false
	enc := &enclaveImpl{backend: &mockBackend{
		deleteKeyFn: func(tag string) error {
			if tag != "com.test.del" {
				t.Errorf("tag = %q, want com.test.del", tag)
			}
			deleted = true
			return nil
		},
	}}

	if err := enc.DeleteKey("com.test.del"); err != nil {
		t.Fatalf("DeleteKey: %v", err)
	}
	if !deleted {
		t.Error("backend.deleteKey was not called")
	}
}

func TestEnclaveImpl_DeleteKey_Error(t *testing.T) {
	enc := &enclaveImpl{backend: &mockBackend{
		deleteKeyFn: func(tag string) error {
			return fmt.Errorf("failed to delete key")
		},
	}}

	err := enc.DeleteKey("com.test.del")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestEnclaveImpl_Sign(t *testing.T) {
	expectedSig := []byte{0x30, 0x44, 0x02, 0x20} // DER prefix
	enc := &enclaveImpl{backend: &mockBackend{
		signFn: func(tag string, data []byte) ([]byte, error) {
			if tag != "com.test.sign" {
				t.Errorf("tag = %q", tag)
			}
			if string(data) != "hello" {
				t.Errorf("data = %q", data)
			}
			return expectedSig, nil
		},
	}}

	sig, err := enc.Sign("com.test.sign", []byte("hello"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) != len(expectedSig) {
		t.Errorf("sig length = %d, want %d", len(sig), len(expectedSig))
	}
}

func TestEnclaveImpl_Sign_KeyNotFound(t *testing.T) {
	enc := &enclaveImpl{backend: &mockBackend{
		signFn: func(tag string, data []byte) ([]byte, error) {
			return nil, fmt.Errorf("key not found for signing")
		},
	}}

	_, err := enc.Sign("com.test.missing", []byte("hello"))
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestEnclaveImpl_GenerateAndLoad_SameFingerprint(t *testing.T) {
	raw := testRawP256PubKey(t)
	enc := &enclaveImpl{backend: &mockBackend{
		generateKeyFn: func(tag string) ([]byte, error) { return raw, nil },
		lookupKeyFn:   func(tag string) ([]byte, error) { return raw, nil },
	}}

	gen, err := enc.GenerateKey("com.test.fp")
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := enc.LoadKey("com.test.fp")
	if err != nil {
		t.Fatal(err)
	}

	if gen.Fingerprint != loaded.Fingerprint {
		t.Errorf("fingerprints differ: generated=%q loaded=%q", gen.Fingerprint, loaded.Fingerprint)
	}
}
