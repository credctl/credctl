package oidc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"testing"
)

func generateTestPEM(t *testing.T) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func TestGenerateDiscovery(t *testing.T) {
	issuer := "https://d1234.cloudfront.net"
	doc := GenerateDiscovery(issuer)

	if doc.Issuer != issuer {
		t.Errorf("issuer = %q, want %q", doc.Issuer, issuer)
	}
	if doc.JWKSURI != issuer+"/keys.json" {
		t.Errorf("jwks_uri = %q, want %q", doc.JWKSURI, issuer+"/keys.json")
	}
	if len(doc.ResponseTypesSupported) != 1 || doc.ResponseTypesSupported[0] != "id_token" {
		t.Errorf("response_types_supported = %v", doc.ResponseTypesSupported)
	}
	if len(doc.SubjectTypesSupported) != 1 || doc.SubjectTypesSupported[0] != "public" {
		t.Errorf("subject_types_supported = %v", doc.SubjectTypesSupported)
	}
	if len(doc.IDTokenSigningAlgValuesSupported) != 1 || doc.IDTokenSigningAlgValuesSupported[0] != "ES256" {
		t.Errorf("id_token_signing_alg_values_supported = %v", doc.IDTokenSigningAlgValuesSupported)
	}
}

func TestGenerateDiscovery_JSONRoundTrip(t *testing.T) {
	doc := GenerateDiscovery("https://example.com")
	data, err := MarshalJSON(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var parsed OpenIDConfiguration
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if parsed.Issuer != doc.Issuer {
		t.Errorf("roundtrip issuer mismatch")
	}
	if parsed.JWKSURI != doc.JWKSURI {
		t.Errorf("roundtrip jwks_uri mismatch")
	}
}

func TestJWKFromPublicKeyPEM(t *testing.T) {
	pemData := generateTestPEM(t)

	jwk, err := JWKFromPublicKeyPEM(pemData, "test-kid")
	if err != nil {
		t.Fatalf("JWKFromPublicKeyPEM: %v", err)
	}

	if jwk.Kty != "EC" {
		t.Errorf("kty = %q, want EC", jwk.Kty)
	}
	if jwk.Crv != "P-256" {
		t.Errorf("crv = %q, want P-256", jwk.Crv)
	}
	if jwk.Kid != "test-kid" {
		t.Errorf("kid = %q, want test-kid", jwk.Kid)
	}
	if jwk.Use != "sig" {
		t.Errorf("use = %q, want sig", jwk.Use)
	}
	if jwk.Alg != "ES256" {
		t.Errorf("alg = %q, want ES256", jwk.Alg)
	}

	// X and Y should be valid base64url and 32 bytes when decoded
	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		t.Fatalf("decode X: %v", err)
	}
	if len(xBytes) != 32 {
		t.Errorf("X length = %d, want 32", len(xBytes))
	}

	yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		t.Fatalf("decode Y: %v", err)
	}
	if len(yBytes) != 32 {
		t.Errorf("Y length = %d, want 32", len(yBytes))
	}
}

func TestJWKFromPublicKeyPEM_InvalidPEM(t *testing.T) {
	_, err := JWKFromPublicKeyPEM([]byte("garbage"), "kid")
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}

func TestJWKFromPublicKeyPEM_NonECKey(t *testing.T) {
	// Create an RSA-ish invalid key by using a non-EC PEM
	// We can't easily make a non-EC PKIX key without more deps,
	// so just test with invalid PEM data
	badPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("bad")})
	_, err := JWKFromPublicKeyPEM(badPEM, "kid")
	if err == nil {
		t.Fatal("expected error for non-EC key data")
	}
}

func TestGenerateJWKS(t *testing.T) {
	keys := []JWK{
		{Kty: "EC", Kid: "key1"},
		{Kty: "EC", Kid: "key2"},
	}

	jwks := GenerateJWKS(keys)
	if len(jwks.Keys) != 2 {
		t.Errorf("got %d keys, want 2", len(jwks.Keys))
	}
	if jwks.Keys[0].Kid != "key1" {
		t.Errorf("first key kid = %q, want key1", jwks.Keys[0].Kid)
	}
}

func TestMergeJWKS_AddsNewKey(t *testing.T) {
	existing := &JWKS{Keys: []JWK{
		{Kty: "EC", Kid: "key1"},
	}}
	newKey := &JWK{Kty: "EC", Kid: "key2"}

	merged := MergeJWKS(existing, newKey)
	if len(merged.Keys) != 2 {
		t.Errorf("got %d keys, want 2", len(merged.Keys))
	}
}

func TestMergeJWKS_ReplacesExistingKey(t *testing.T) {
	existing := &JWKS{Keys: []JWK{
		{Kty: "EC", Kid: "key1", X: "old"},
		{Kty: "EC", Kid: "key2"},
	}}
	newKey := &JWK{Kty: "EC", Kid: "key1", X: "new"}

	merged := MergeJWKS(existing, newKey)
	if len(merged.Keys) != 2 {
		t.Errorf("got %d keys, want 2", len(merged.Keys))
	}

	// Find key1 and verify it was replaced
	for _, k := range merged.Keys {
		if k.Kid == "key1" {
			if k.X != "new" {
				t.Errorf("key1.X = %q, want 'new'", k.X)
			}
			return
		}
	}
	t.Error("key1 not found in merged JWKS")
}

func TestMergeJWKS_EmptyExisting(t *testing.T) {
	existing := &JWKS{Keys: []JWK{}}
	newKey := &JWK{Kty: "EC", Kid: "key1"}

	merged := MergeJWKS(existing, newKey)
	if len(merged.Keys) != 1 {
		t.Errorf("got %d keys, want 1", len(merged.Keys))
	}
}

func TestJWKS_JSONRoundTrip(t *testing.T) {
	pemData := generateTestPEM(t)
	jwk, err := JWKFromPublicKeyPEM(pemData, "roundtrip-kid")
	if err != nil {
		t.Fatalf("create JWK: %v", err)
	}

	jwks := GenerateJWKS([]JWK{*jwk})
	data, err := MarshalJSON(jwks)
	if err != nil {
		t.Fatalf("marshal JWKS: %v", err)
	}

	parsed, err := UnmarshalJWKS(data)
	if err != nil {
		t.Fatalf("unmarshal JWKS: %v", err)
	}

	if len(parsed.Keys) != 1 {
		t.Fatalf("got %d keys, want 1", len(parsed.Keys))
	}
	if parsed.Keys[0].Kid != "roundtrip-kid" {
		t.Errorf("kid = %q, want roundtrip-kid", parsed.Keys[0].Kid)
	}
	if parsed.Keys[0].X != jwk.X {
		t.Errorf("X mismatch after roundtrip")
	}
	if parsed.Keys[0].Y != jwk.Y {
		t.Errorf("Y mismatch after roundtrip")
	}
}

func TestUnmarshalJWKS_InvalidJSON(t *testing.T) {
	_, err := UnmarshalJWKS([]byte("not json"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestMarshalJSON_Indented(t *testing.T) {
	data, err := MarshalJSON(map[string]string{"key": "value"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	expected := "{\n  \"key\": \"value\"\n}"
	if string(data) != expected {
		t.Errorf("got %q, want %q", string(data), expected)
	}
}

func TestJWKFromPublicKeyPEM_CoordinatesMatchKey(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	pemData := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})

	jwk, err := JWKFromPublicKeyPEM(pemData, "coord-test")
	if err != nil {
		t.Fatalf("JWKFromPublicKeyPEM: %v", err)
	}

	// Decode X,Y from JWK and compare to original key
	xBytes, _ := base64.RawURLEncoding.DecodeString(jwk.X)
	yBytes, _ := base64.RawURLEncoding.DecodeString(jwk.Y)

	xPad := make([]byte, 32)
	yPad := make([]byte, 32)
	xOrig := priv.PublicKey.X.Bytes()
	yOrig := priv.PublicKey.Y.Bytes()
	copy(xPad[32-len(xOrig):], xOrig)
	copy(yPad[32-len(yOrig):], yOrig)

	if string(xBytes) != string(xPad) {
		t.Error("X coordinate mismatch")
	}
	if string(yBytes) != string(yPad) {
		t.Error("Y coordinate mismatch")
	}
}
