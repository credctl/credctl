//go:build linux

package enclave

import (
	"crypto/sha256"
	"encoding/asn1"
	"fmt"
	"math/big"
	"os"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

// See ADR-006 for the rationale behind these choices.
const (
	tpmDevicePath = "/dev/tpmrm0"
	srkPersistent = 0x81000001
	keyPersistent = 0x81010001
)

// openTPM opens a connection to the TPM. Package-level var for test injection.
var openTPM = func() (transport.TPMCloser, error) {
	return linuxtpm.Open(tpmDevicePath)
}

// linuxTPMBackend implements keyBackend using Linux TPM 2.0.
type linuxTPMBackend struct{}

func newPlatformEnclave() Enclave {
	return &enclaveImpl{backend: &linuxTPMBackend{}}
}

func (b *linuxTPMBackend) available() bool {
	if _, err := os.Stat(tpmDevicePath); err != nil {
		return false
	}
	tpm, err := openTPM()
	if err != nil {
		return false
	}
	tpm.Close()
	return true
}

func (b *linuxTPMBackend) generateKey(tag string, biometric BiometricPolicy) ([]byte, error) {
	if biometric == BiometricFingerprint {
		return nil, fmt.Errorf("biometric=fingerprint is not supported on Linux TPM 2.0 (see ADR-006)")
	}

	tpm, err := openTPM()
	if err != nil {
		return nil, fmt.Errorf("failed to open TPM: %w", err)
	}
	defer tpm.Close()

	// Refuse to clobber an existing key.
	_, err = tpm2.ReadPublic{
		ObjectHandle: tpm2.TPMHandle(keyPersistent),
	}.Execute(tpm)
	if err == nil {
		return nil, fmt.Errorf("key already exists at TPM handle 0x%08x", keyPersistent)
	}

	srkHandle, err := ensureSRK(tpm)
	if err != nil {
		return nil, fmt.Errorf("failed to ensure SRK: %w", err)
	}

	createRsp, err := tpm2.Create{
		ParentHandle: srkHandle,
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgECC,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM:            true,
				FixedParent:         true,
				SensitiveDataOrigin: true,
				UserWithAuth:        true,
				NoDA:                true,
				SignEncrypt:         true,
			},
			Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
				CurveID: tpm2.TPMECCNistP256,
				Scheme: tpm2.TPMTECCScheme{
					Scheme: tpm2.TPMAlgECDSA,
					Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA,
						&tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA256}),
				},
			}),
		}),
	}.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("failed to create key: %w", err)
	}

	loadRsp, err := tpm2.Load{
		ParentHandle: srkHandle,
		InPrivate:    createRsp.OutPrivate,
		InPublic:     createRsp.OutPublic,
	}.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("failed to load key: %w", err)
	}
	defer tpm2.FlushContext{FlushHandle: loadRsp.ObjectHandle}.Execute(tpm)

	_, err = tpm2.EvictControl{
		Auth: tpm2.TPMRHOwner,
		ObjectHandle: &tpm2.NamedHandle{
			Handle: loadRsp.ObjectHandle,
			Name:   loadRsp.Name,
		},
		PersistentHandle: keyPersistent,
	}.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("failed to persist key: %w", err)
	}

	return readRawPublicKey(tpm, keyPersistent)
}

func (b *linuxTPMBackend) lookupKey(tag string) ([]byte, error) {
	tpm, err := openTPM()
	if err != nil {
		return nil, fmt.Errorf("failed to open TPM: %w", err)
	}
	defer tpm.Close()

	raw, err := readRawPublicKey(tpm, keyPersistent)
	if err != nil {
		return nil, fmt.Errorf("key not found at TPM handle 0x%08x: %w", keyPersistent, err)
	}
	return raw, nil
}

func (b *linuxTPMBackend) deleteKey(tag string) error {
	tpm, err := openTPM()
	if err != nil {
		return fmt.Errorf("failed to open TPM: %w", err)
	}
	defer tpm.Close()

	readRsp, err := tpm2.ReadPublic{
		ObjectHandle: tpm2.TPMHandle(keyPersistent),
	}.Execute(tpm)
	if err != nil {
		// Idempotent: nothing to delete.
		return nil
	}

	_, err = tpm2.EvictControl{
		Auth: tpm2.TPMRHOwner,
		ObjectHandle: &tpm2.NamedHandle{
			Handle: tpm2.TPMHandle(keyPersistent),
			Name:   readRsp.Name,
		},
		PersistentHandle: keyPersistent,
	}.Execute(tpm)
	if err != nil {
		return fmt.Errorf("failed to evict key: %w", err)
	}
	return nil
}

func (b *linuxTPMBackend) sign(tag string, data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("cannot sign empty data")
	}

	tpm, err := openTPM()
	if err != nil {
		return nil, fmt.Errorf("failed to open TPM: %w", err)
	}
	defer tpm.Close()

	readRsp, err := tpm2.ReadPublic{
		ObjectHandle: tpm2.TPMHandle(keyPersistent),
	}.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("key not found for signing: %w", err)
	}

	digest := sha256.Sum256(data)

	signRsp, err := tpm2.Sign{
		KeyHandle: tpm2.NamedHandle{
			Handle: tpm2.TPMHandle(keyPersistent),
			Name:   readRsp.Name,
		},
		Digest: tpm2.TPM2BDigest{Buffer: digest[:]},
		Validation: tpm2.TPMTTKHashCheck{
			Tag:       tpm2.TPMSTHashCheck,
			Hierarchy: tpm2.TPMRHNull,
		},
	}.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("signing failed: %w", err)
	}

	eccSig, err := signRsp.Signature.Signature.ECDSA()
	if err != nil {
		return nil, fmt.Errorf("failed to extract ECDSA signature: %w", err)
	}

	r := new(big.Int).SetBytes(eccSig.SignatureR.Buffer)
	s := new(big.Int).SetBytes(eccSig.SignatureS.Buffer)

	return asn1MarshalECDSA(r, s)
}

// ensureSRK ensures the Storage Root Key exists at the standard persistent handle.
func ensureSRK(tpm transport.TPM) (tpm2.NamedHandle, error) {
	readRsp, err := tpm2.ReadPublic{
		ObjectHandle: tpm2.TPMHandle(srkPersistent),
	}.Execute(tpm)
	if err == nil {
		return tpm2.NamedHandle{
			Handle: tpm2.TPMHandle(srkPersistent),
			Name:   readRsp.Name,
		}, nil
	}

	srkRsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.ECCSRKTemplate),
	}.Execute(tpm)
	if err != nil {
		return tpm2.NamedHandle{}, fmt.Errorf("failed to create SRK: %w", err)
	}
	defer tpm2.FlushContext{FlushHandle: srkRsp.ObjectHandle}.Execute(tpm)

	_, err = tpm2.EvictControl{
		Auth: tpm2.TPMRHOwner,
		ObjectHandle: &tpm2.NamedHandle{
			Handle: srkRsp.ObjectHandle,
			Name:   srkRsp.Name,
		},
		PersistentHandle: srkPersistent,
	}.Execute(tpm)
	if err != nil {
		return tpm2.NamedHandle{}, fmt.Errorf("failed to persist SRK: %w", err)
	}

	return tpm2.NamedHandle{
		Handle: tpm2.TPMHandle(srkPersistent),
		Name:   srkRsp.Name,
	}, nil
}

// readRawPublicKey reads the public key at a persistent handle and returns
// the 65-byte uncompressed EC point (0x04 || X || Y). The enclaveImpl wrapper
// converts this to PEM and computes the fingerprint.
func readRawPublicKey(tpm transport.TPM, handle uint32) ([]byte, error) {
	readRsp, err := tpm2.ReadPublic{
		ObjectHandle: tpm2.TPMHandle(handle),
	}.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key: %w", err)
	}

	pub, err := readRsp.OutPublic.Contents()
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	eccPoint, err := pub.Unique.ECC()
	if err != nil {
		return nil, fmt.Errorf("failed to get ECC point: %w", err)
	}

	x := eccPoint.X.Buffer
	y := eccPoint.Y.Buffer
	if len(x) > 32 || len(y) > 32 {
		return nil, fmt.Errorf("unexpected ECC point size: X=%d Y=%d", len(x), len(y))
	}

	raw := make([]byte, 65)
	raw[0] = 0x04
	copy(raw[33-len(x):33], x)
	copy(raw[65-len(y):65], y)
	return raw, nil
}

// asn1MarshalECDSA DER-encodes an ECDSA signature.
func asn1MarshalECDSA(r, s *big.Int) ([]byte, error) {
	type ecdsaSig struct {
		R, S *big.Int
	}
	return asn1.Marshal(ecdsaSig{R: r, S: s})
}
