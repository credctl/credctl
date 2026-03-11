package enclave

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// keyBackend abstracts the platform-specific key storage operations.
// Implementations handle actual hardware interaction (Secure Enclave, etc.)
// while the enclaveImpl wrapper handles Go-level processing (PEM encoding,
// fingerprinting).
type keyBackend interface {
	available() bool
	generateKey(tag string) (rawPubKey []byte, err error)
	lookupKey(tag string) (rawPubKey []byte, err error)
	deleteKey(tag string) error
	sign(tag string, data []byte) ([]byte, error)
}

// enclaveImpl implements Enclave by delegating to a keyBackend and adding
// Go-level processing (PEM encoding, fingerprinting) on top.
type enclaveImpl struct {
	backend keyBackend
}

func (e *enclaveImpl) Available() bool {
	return e.backend.available()
}

func (e *enclaveImpl) GenerateKey(tag string) (*DeviceKey, error) {
	rawPub, err := e.backend.generateKey(tag)
	if err != nil {
		return nil, err
	}
	dk, err := buildDeviceKey(tag, rawPub)
	if err != nil {
		return nil, err
	}
	dk.CreatedAt = time.Now()
	return dk, nil
}

func (e *enclaveImpl) LoadKey(tag string) (*DeviceKey, error) {
	rawPub, err := e.backend.lookupKey(tag)
	if err != nil {
		return nil, err
	}
	return buildDeviceKey(tag, rawPub)
}

func (e *enclaveImpl) DeleteKey(tag string) error {
	return e.backend.deleteKey(tag)
}

func (e *enclaveImpl) Sign(tag string, data []byte) ([]byte, error) {
	return e.backend.sign(tag, data)
}

// buildDeviceKey converts a raw uncompressed EC point (65 bytes: 0x04 || x || y)
// into a DeviceKey with PEM-encoded public key and SHA-256 fingerprint.
func buildDeviceKey(tag string, rawBytes []byte) (*DeviceKey, error) {
	if len(rawBytes) != 65 || rawBytes[0] != 0x04 {
		return nil, fmt.Errorf("unexpected public key format: %d bytes", len(rawBytes))
	}

	x := new(big.Int).SetBytes(rawBytes[1:33])
	y := new(big.Int).SetBytes(rawBytes[33:65])

	pubKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}

	derBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	pemBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derBytes,
	})

	hash := sha256.Sum256(derBytes)
	fingerprint := "SHA256:" + base64.StdEncoding.EncodeToString(hash[:])

	return &DeviceKey{
		Fingerprint: fingerprint,
		PublicKey:   pemBlock,
		Tag:         tag,
	}, nil
}

// cGoString converts a null-terminated C string in a Go byte slice to a Go string.
func cGoString(buf []byte) string {
	for i, b := range buf {
		if b == 0 {
			return string(buf[:i])
		}
	}
	return string(buf)
}
