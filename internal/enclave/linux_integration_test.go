//go:build integration && linux

package enclave

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"
)

func requireTPM(t *testing.T) {
	t.Helper()
	if _, err := os.Stat("/dev/tpmrm0"); err != nil {
		t.Skip("TPM not available: /dev/tpmrm0 not found")
	}
}

func TestTPMIntegration_GenerateLoadDelete(t *testing.T) {
	requireTPM(t)
	enc := New()
	if !enc.Available() {
		t.Skip("TPM not accessible")
	}

	tag := "com.crzy.credctl.integration-test"
	t.Cleanup(func() { enc.DeleteKey(tag) })

	// Clean up any leftover key from a previous failed run
	enc.DeleteKey(tag)

	key, err := enc.GenerateKey(tag)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	block, _ := pem.Decode(key.PublicKey)
	if block == nil {
		t.Fatal("public key is not valid PEM")
	}

	loaded, err := enc.LoadKey(tag)
	if err != nil {
		t.Fatalf("LoadKey: %v", err)
	}
	if loaded.Fingerprint != key.Fingerprint {
		t.Errorf("fingerprints differ: generated=%q loaded=%q", key.Fingerprint, loaded.Fingerprint)
	}

	if err := enc.DeleteKey(tag); err != nil {
		t.Fatalf("DeleteKey: %v", err)
	}

	_, err = enc.LoadKey(tag)
	if err == nil {
		t.Error("expected error loading deleted key")
	}
}

func TestTPMIntegration_Sign(t *testing.T) {
	requireTPM(t)
	enc := New()
	if !enc.Available() {
		t.Skip("TPM not accessible")
	}

	tag := "com.crzy.credctl.integration-sign"
	t.Cleanup(func() { enc.DeleteKey(tag) })

	enc.DeleteKey(tag)

	key, err := enc.GenerateKey(tag)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	data := []byte("integration test signing")
	sig, err := enc.Sign(tag, data)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	block, _ := pem.Decode(key.PublicKey)
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("ParsePKIXPublicKey: %v", err)
	}

	hash := sha256.Sum256(data)
	if !ecdsa.VerifyASN1(pub.(*ecdsa.PublicKey), hash[:], sig) {
		t.Error("signature verification failed")
	}
}
