package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"
)

func generateTestKey(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	return priv, pemBytes
}

func TestDERToRaw(t *testing.T) {
	tests := []struct {
		name string
		r, s *big.Int
	}{
		{
			name: "normal 32-byte values",
			r:    new(big.Int).SetBytes(fill32(0x01)),
			s:    new(big.Int).SetBytes(fill32(0x02)),
		},
		{
			name: "small R needs left-padding",
			r:    big.NewInt(1),
			s:    new(big.Int).SetBytes(fill32(0xff)),
		},
		{
			name: "both small values",
			r:    big.NewInt(42),
			s:    big.NewInt(99),
		},
		{
			name: "max P-256 values",
			r:    new(big.Int).SetBytes(fill32(0xff)),
			s:    new(big.Int).SetBytes(fill32(0xff)),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			der, err := asn1.Marshal(ecdsaSig{R: tt.r, S: tt.s})
			if err != nil {
				t.Fatalf("marshal DER: %v", err)
			}

			raw, err := DERToRaw(der)
			if err != nil {
				t.Fatalf("DERToRaw: %v", err)
			}

			if len(raw) != 64 {
				t.Errorf("got length %d, want 64", len(raw))
			}

			gotR := new(big.Int).SetBytes(raw[:32])
			gotS := new(big.Int).SetBytes(raw[32:])
			if gotR.Cmp(tt.r) != 0 {
				t.Errorf("R mismatch: got %s, want %s", gotR, tt.r)
			}
			if gotS.Cmp(tt.s) != 0 {
				t.Errorf("S mismatch: got %s, want %s", gotS, tt.s)
			}
		})
	}
}

func TestDERToRaw_InvalidInput(t *testing.T) {
	_, err := DERToRaw([]byte("not a DER signature"))
	if err == nil {
		t.Fatal("expected error for invalid DER input")
	}
}

func TestKIDFromPublicKeyPEM(t *testing.T) {
	_, pemBytes := generateTestKey(t)

	kid, err := KIDFromPublicKeyPEM(pemBytes)
	if err != nil {
		t.Fatalf("KIDFromPublicKeyPEM: %v", err)
	}

	if len(kid) != 16 {
		t.Errorf("KID length = %d, want 16", len(kid))
	}

	// Deterministic
	kid2, _ := KIDFromPublicKeyPEM(pemBytes)
	if kid != kid2 {
		t.Errorf("KID not deterministic: %q != %q", kid, kid2)
	}
}

func TestKIDFromPublicKeyPEM_DifferentKeys(t *testing.T) {
	_, pem1 := generateTestKey(t)
	_, pem2 := generateTestKey(t)

	kid1, _ := KIDFromPublicKeyPEM(pem1)
	kid2, _ := KIDFromPublicKeyPEM(pem2)

	if kid1 == kid2 {
		t.Error("different keys should produce different KIDs")
	}
}

func TestKIDFromPublicKeyPEM_InvalidPEM(t *testing.T) {
	_, err := KIDFromPublicKeyPEM([]byte("not a pem"))
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}

func TestPublicKeyFromPEM(t *testing.T) {
	_, pemBytes := generateTestKey(t)

	key, err := PublicKeyFromPEM(pemBytes)
	if err != nil {
		t.Fatalf("PublicKeyFromPEM: %v", err)
	}

	ecKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", key)
	}
	if ecKey.Curve != elliptic.P256() {
		t.Error("expected P-256 curve")
	}
}

func TestPublicKeyFromPEM_InvalidPEM(t *testing.T) {
	_, err := PublicKeyFromPEM([]byte("garbage"))
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestPublicKeyFromPEM_InvalidDER(t *testing.T) {
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("not a key")})
	_, err := PublicKeyFromPEM(pemBytes)
	if err == nil {
		t.Fatal("expected error for invalid DER inside PEM")
	}
}

func TestBuildAndSign(t *testing.T) {
	priv, _ := generateTestKey(t)

	// Software signing function that mimics DER output format
	signFn := func(data []byte) ([]byte, error) {
		hash := sha256.Sum256(data)
		return ecdsa.SignASN1(rand.Reader, priv, hash[:])
	}

	token, err := BuildAndSign("test-kid", "https://example.com", "device-123", signFn)
	if err != nil {
		t.Fatalf("BuildAndSign: %v", err)
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 parts, got %d", len(parts))
	}

	// Verify header
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	var h header
	if err := json.Unmarshal(headerJSON, &h); err != nil {
		t.Fatalf("unmarshal header: %v", err)
	}
	if h.Alg != "ES256" {
		t.Errorf("alg = %q, want ES256", h.Alg)
	}
	if h.Typ != "JWT" {
		t.Errorf("typ = %q, want JWT", h.Typ)
	}
	if h.Kid != "test-kid" {
		t.Errorf("kid = %q, want test-kid", h.Kid)
	}

	// Verify claims
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode claims: %v", err)
	}
	var c claims
	if err := json.Unmarshal(claimsJSON, &c); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	if c.Iss != "https://example.com" {
		t.Errorf("iss = %q, want https://example.com", c.Iss)
	}
	if c.Sub != "device-123" {
		t.Errorf("sub = %q, want device-123", c.Sub)
	}
	if c.Aud != "sts.amazonaws.com" {
		t.Errorf("aud = %q, want sts.amazonaws.com", c.Aud)
	}
	if c.Exp-c.Iat != 300 {
		t.Errorf("exp-iat = %d, want 300 (5 minutes)", c.Exp-c.Iat)
	}
	if time.Unix(c.Iat, 0).Before(time.Now().Add(-10 * time.Second)) {
		t.Error("iat is too far in the past")
	}

	// Verify signature is 64 bytes raw R||S
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	if len(sigBytes) != 64 {
		t.Errorf("signature length = %d, want 64", len(sigBytes))
	}

	// Verify signature against public key
	sigInput := parts[0] + "." + parts[1]
	hash := sha256.Sum256([]byte(sigInput))
	r := new(big.Int).SetBytes(sigBytes[:32])
	s := new(big.Int).SetBytes(sigBytes[32:])
	if !ecdsa.Verify(&priv.PublicKey, hash[:], r, s) {
		t.Error("signature verification failed")
	}
}

func TestBuildAndSign_SignError(t *testing.T) {
	signFn := func(data []byte) ([]byte, error) {
		return nil, fmt.Errorf("hardware error")
	}

	_, err := BuildAndSign("kid", "iss", "sub", signFn)
	if err == nil {
		t.Fatal("expected error when signing fails")
	}
	if !strings.Contains(err.Error(), "sign") {
		t.Errorf("error should mention signing: %v", err)
	}
}

func TestBuildAndSign_InvalidDERSignature(t *testing.T) {
	signFn := func(data []byte) ([]byte, error) {
		return []byte("not a DER signature"), nil
	}

	_, err := BuildAndSign("kid", "iss", "sub", signFn)
	if err == nil {
		t.Fatal("expected error for invalid DER signature")
	}
}

func fill32(b byte) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = b
	}
	return out
}
