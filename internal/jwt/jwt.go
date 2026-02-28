package jwt

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// SigningFunc signs raw data and returns a DER-encoded ECDSA signature.
// The Secure Enclave's kSecKeyAlgorithmECDSASignatureMessageX962SHA256
// hashes internally, so the input should be the raw signing input (not pre-hashed).
type SigningFunc func(data []byte) ([]byte, error)

type header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

type claims struct {
	Iss string `json:"iss"`
	Sub string `json:"sub"`
	Aud string `json:"aud"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
}

// BuildAndSign constructs a JWT with ES256 signing via the provided SigningFunc.
// The SigningFunc receives the raw signing input (header.payload) and must return
// a DER-encoded ECDSA signature (as produced by the Secure Enclave).
func BuildAndSign(kid, issuer, subject string, sign SigningFunc) (string, error) {
	now := time.Now()

	h := header{Alg: "ES256", Typ: "JWT", Kid: kid}
	c := claims{
		Iss: issuer,
		Sub: subject,
		Aud: "sts.amazonaws.com",
		Iat: now.Unix(),
		Exp: now.Add(5 * time.Minute).Unix(),
	}

	headerJSON, err := json.Marshal(h)
	if err != nil {
		return "", fmt.Errorf("marshal header: %w", err)
	}

	claimsJSON, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("marshal claims: %w", err)
	}

	signingInput := base64URLEncode(headerJSON) + "." + base64URLEncode(claimsJSON)

	derSig, err := sign([]byte(signingInput))
	if err != nil {
		return "", fmt.Errorf("sign: %w", err)
	}

	rawSig, err := DERToRaw(derSig)
	if err != nil {
		return "", fmt.Errorf("convert signature: %w", err)
	}

	return signingInput + "." + base64URLEncode(rawSig), nil
}

// ecdsaSig is the ASN.1 structure for an ECDSA signature.
type ecdsaSig struct {
	R, S *big.Int
}

// DERToRaw converts a DER-encoded ECDSA signature to the raw R||S format
// (64 bytes for P-256) as required by JWS ES256.
func DERToRaw(derSig []byte) ([]byte, error) {
	var sig ecdsaSig
	if _, err := asn1.Unmarshal(derSig, &sig); err != nil {
		return nil, fmt.Errorf("unmarshal DER signature: %w", err)
	}

	// P-256 uses 32-byte integers
	const size = 32
	raw := make([]byte, 2*size)

	rBytes := sig.R.Bytes()
	sBytes := sig.S.Bytes()

	// Pad with leading zeros if needed, copy right-aligned
	copy(raw[size-len(rBytes):size], rBytes)
	copy(raw[2*size-len(sBytes):2*size], sBytes)

	return raw, nil
}

// KIDFromPublicKeyPEM derives a key ID from a PEM-encoded public key.
// The KID is the base64url-encoded SHA-256 hash of the DER-encoded public key, truncated to 16 chars.
func KIDFromPublicKeyPEM(pemData []byte) (string, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return "", fmt.Errorf("failed to decode PEM")
	}

	hash := sha256.Sum256(block.Bytes)
	kid := base64URLEncode(hash[:])
	if len(kid) > 16 {
		kid = kid[:16]
	}
	return kid, nil
}

// PublicKeyFromPEM parses a PEM-encoded public key and returns the DER bytes and parsed key.
func PublicKeyFromPEM(pemData []byte) (any, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM")
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}

	return key, nil
}

func base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}
