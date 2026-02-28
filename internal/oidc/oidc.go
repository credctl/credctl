package oidc

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/matzhouse/credctl/internal/jwt"
)

// OpenIDConfiguration is the OIDC discovery document.
type OpenIDConfiguration struct {
	Issuer                           string   `json:"issuer"`
	JWKSURI                          string   `json:"jwks_uri"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
}

// JWK represents a JSON Web Key for EC P-256.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
}

// JWKS is a JSON Web Key Set.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// GenerateDiscovery creates an OIDC discovery document for the given issuer URL.
func GenerateDiscovery(issuerURL string) *OpenIDConfiguration {
	return &OpenIDConfiguration{
		Issuer:                           issuerURL,
		JWKSURI:                          issuerURL + "/keys.json",
		ResponseTypesSupported:           []string{"id_token"},
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{"ES256"},
	}
}

// JWKFromPublicKeyPEM extracts an EC P-256 JWK from PEM-encoded public key data.
func JWKFromPublicKeyPEM(pemData []byte, kid string) (*JWK, error) {
	key, err := jwt.PublicKeyFromPEM(pemData)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}

	ecKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an ECDSA public key")
	}

	// X and Y coordinates, zero-padded to 32 bytes for P-256
	const size = 32
	xBytes := make([]byte, size)
	yBytes := make([]byte, size)

	xRaw := ecKey.X.Bytes()
	yRaw := ecKey.Y.Bytes()
	copy(xBytes[size-len(xRaw):], xRaw)
	copy(yBytes[size-len(yRaw):], yRaw)

	return &JWK{
		Kty: "EC",
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(xBytes),
		Y:   base64.RawURLEncoding.EncodeToString(yBytes),
		Kid: kid,
		Use: "sig",
		Alg: "ES256",
	}, nil
}

// GenerateJWKS creates a JWKS from one or more JWKs.
func GenerateJWKS(keys []JWK) *JWKS {
	return &JWKS{Keys: keys}
}

// MergeJWKS adds a new key to an existing JWKS, replacing any key with the same kid.
func MergeJWKS(existing *JWKS, newKey *JWK) *JWKS {
	keys := make([]JWK, 0, len(existing.Keys)+1)
	for _, k := range existing.Keys {
		if k.Kid != newKey.Kid {
			keys = append(keys, k)
		}
	}
	keys = append(keys, *newKey)
	return &JWKS{Keys: keys}
}

// MarshalJSON marshals a value to indented JSON.
func MarshalJSON(v any) ([]byte, error) {
	return json.MarshalIndent(v, "", "  ")
}

// UnmarshalJWKS parses a JWKS from JSON.
func UnmarshalJWKS(data []byte) (*JWKS, error) {
	var jwks JWKS
	if err := json.Unmarshal(data, &jwks); err != nil {
		return nil, err
	}
	return &jwks, nil
}
