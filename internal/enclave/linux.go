//go:build linux

package enclave

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

const (
	tpmDevicePath = "/dev/tpmrm0"
	srkPersistent = 0x81000001
	keyPersistent = 0x81010001
)

// openTPM opens a connection to the TPM. Package-level var for test injection.
var openTPM = func() (transport.TPMCloser, error) {
	return linuxtpm.Open(tpmDevicePath)
}

type tpmEnclave struct{}

func newPlatformEnclave() Enclave {
	return &tpmEnclave{}
}

func (e *tpmEnclave) Available() bool {
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

func (e *tpmEnclave) GenerateKey(tag string) (*DeviceKey, error) {
	tpm, err := openTPM()
	if err != nil {
		return nil, fmt.Errorf("failed to open TPM: %w", err)
	}
	defer tpm.Close()

	// Check if key already exists at the persistent handle
	_, err = tpm2.ReadPublic{
		ObjectHandle: tpm2.TPMHandle(keyPersistent),
	}.Execute(tpm)
	if err == nil {
		return nil, fmt.Errorf("key already exists at TPM handle 0x%08x", keyPersistent)
	}

	// Ensure SRK exists at the standard handle
	srkHandle, err := ensureSRK(tpm)
	if err != nil {
		return nil, fmt.Errorf("failed to ensure SRK: %w", err)
	}

	// Create ECDSA P-256 child key (non-exportable)
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

	// Load into transient memory
	loadRsp, err := tpm2.Load{
		ParentHandle: srkHandle,
		InPrivate:    createRsp.OutPrivate,
		InPublic:     createRsp.OutPublic,
	}.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("failed to load key: %w", err)
	}
	defer tpm2.FlushContext{FlushHandle: loadRsp.ObjectHandle}.Execute(tpm)

	// Persist to permanent handle
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

	pubPEM, fingerprint, err := readTPMPublicKey(tpm, keyPersistent)
	if err != nil {
		return nil, fmt.Errorf("failed to extract public key: %w", err)
	}

	return &DeviceKey{
		Fingerprint: fingerprint,
		PublicKey:   pubPEM,
		Tag:         tag,
		CreatedAt:   time.Now(),
	}, nil
}

func (e *tpmEnclave) LoadKey(tag string) (*DeviceKey, error) {
	tpm, err := openTPM()
	if err != nil {
		return nil, fmt.Errorf("failed to open TPM: %w", err)
	}
	defer tpm.Close()

	pubPEM, fingerprint, err := readTPMPublicKey(tpm, keyPersistent)
	if err != nil {
		return nil, fmt.Errorf("key not found at TPM handle 0x%08x: %w", keyPersistent, err)
	}

	return &DeviceKey{
		Fingerprint: fingerprint,
		PublicKey:   pubPEM,
		Tag:         tag,
	}, nil
}

func (e *tpmEnclave) DeleteKey(tag string) error {
	tpm, err := openTPM()
	if err != nil {
		return fmt.Errorf("failed to open TPM: %w", err)
	}
	defer tpm.Close()

	// Read public to get the name for EvictControl
	readRsp, err := tpm2.ReadPublic{
		ObjectHandle: tpm2.TPMHandle(keyPersistent),
	}.Execute(tpm)
	if err != nil {
		// Key doesn't exist — idempotent success
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

func (e *tpmEnclave) Sign(tag string, data []byte) ([]byte, error) {
	tpm, err := openTPM()
	if err != nil {
		return nil, fmt.Errorf("failed to open TPM: %w", err)
	}
	defer tpm.Close()

	// Get key name for authorization
	readRsp, err := tpm2.ReadPublic{
		ObjectHandle: tpm2.TPMHandle(keyPersistent),
	}.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("key not found for signing: %w", err)
	}

	// Hash data — TPM requires pre-hashed input
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

	// SRK not found — create from standard template and persist
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

// readTPMPublicKey reads the public key from a persistent TPM handle and returns
// PEM-encoded PKIX bytes and a SHA-256 fingerprint.
func readTPMPublicKey(tpm transport.TPM, handle uint32) ([]byte, string, error) {
	readRsp, err := tpm2.ReadPublic{
		ObjectHandle: tpm2.TPMHandle(handle),
	}.Execute(tpm)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read public key: %w", err)
	}

	pub, err := readRsp.OutPublic.Contents()
	if err != nil {
		return nil, "", fmt.Errorf("failed to parse public key: %w", err)
	}

	eccParms, err := pub.Parameters.ECCDetail()
	if err != nil {
		return nil, "", fmt.Errorf("failed to get ECC parameters: %w", err)
	}

	eccPoint, err := pub.Unique.ECC()
	if err != nil {
		return nil, "", fmt.Errorf("failed to get ECC point: %w", err)
	}

	ecdsaPub, err := tpm2.ECDSAPub(eccParms, eccPoint)
	if err != nil {
		return nil, "", fmt.Errorf("failed to convert to ECDSA public key: %w", err)
	}

	derBytes, err := x509.MarshalPKIXPublicKey(ecdsaPub)
	if err != nil {
		return nil, "", fmt.Errorf("failed to marshal public key: %w", err)
	}

	pemBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derBytes,
	})

	hash := sha256.Sum256(derBytes)
	fingerprint := "SHA256:" + base64.StdEncoding.EncodeToString(hash[:])

	return pemBlock, fingerprint, nil
}

// asn1MarshalECDSA DER-encodes an ECDSA signature.
func asn1MarshalECDSA(r, s *big.Int) ([]byte, error) {
	type ecdsaSig struct {
		R, S *big.Int
	}
	return asn1.Marshal(ecdsaSig{R: r, S: s})
}
