//go:build linux

package enclave

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"

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

// tpmStateDir returns the directory holding credctl's TPM ownership token.
// Package-level var for test injection.
var tpmStateDir = func() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".credctl"), nil
}

const tpmStateFile = "tpm-state.json"

// tpmState is the on-disk ownership token. We persist the TPM Name (not just
// the public key) because Name is the canonical TPM-side identifier — it
// covers the algorithm, NameAlg, attributes, and public area in a single
// hash. Comparing Names lets us assert "this is the exact object credctl
// created" rather than just "this object has the right shape".
type tpmState struct {
	Version int    `json:"version"`
	Name    string `json:"name"` // base64-encoded TPM Name (alg || hash(public_area))
}

func writeTPMState(name []byte) error {
	dir, err := tpmStateDir()
	if err != nil {
		return fmt.Errorf("resolve state dir: %w", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}
	data, err := json.Marshal(tpmState{
		Version: 1,
		Name:    base64.StdEncoding.EncodeToString(name),
	})
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}
	path := filepath.Join(dir, tpmStateFile)
	return os.WriteFile(path, data, 0o600)
}

// readTPMState returns the persisted Name, or (nil, nil) if no state file exists.
// Any other error (malformed JSON, version mismatch, unreadable) is returned —
// callers must treat that as "do not proceed".
func readTPMState() ([]byte, error) {
	dir, err := tpmStateDir()
	if err != nil {
		return nil, fmt.Errorf("resolve state dir: %w", err)
	}
	path := filepath.Join(dir, tpmStateFile)
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read state: %w", err)
	}
	var s tpmState
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parse state: %w", err)
	}
	if s.Version != 1 {
		return nil, fmt.Errorf("unsupported state version %d", s.Version)
	}
	name, err := base64.StdEncoding.DecodeString(s.Name)
	if err != nil {
		return nil, fmt.Errorf("decode name: %w", err)
	}
	return name, nil
}

func deleteTPMState() error {
	dir, err := tpmStateDir()
	if err != nil {
		return err
	}
	path := filepath.Join(dir, tpmStateFile)
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
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

	// Persist the TPM Name as the ownership token. Used by deleteKey to assert
	// that the object at keyPersistent is the exact one we created.
	if err := writeTPMState(loadRsp.Name.Buffer); err != nil {
		return nil, fmt.Errorf("failed to persist TPM ownership state: %w", err)
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
		// Idempotent: nothing to delete. Clear any orphaned ownership state.
		_ = deleteTPMState()
		return nil
	}

	// Per ADR-006 D3: refuse to evict a persistent object that wasn't created
	// by credctl. Two layers of check:
	//   1. Strong: Name match against the on-disk ownership token. Names are
	//      canonical TPM-side identifiers; a match is cryptographic proof
	//      that this is the exact object credctl created.
	//   2. Fallback: structural check on the public area, used only when the
	//      ownership token is missing (e.g. user wiped ~/.credctl manually).
	expectedName, err := readTPMState()
	if err != nil {
		return fmt.Errorf("refusing to evict TPM handle 0x%08x: corrupt ownership state: %w", keyPersistent, err)
	}
	if expectedName != nil {
		if subtle.ConstantTimeCompare(expectedName, readRsp.Name.Buffer) != 1 {
			return fmt.Errorf("refusing to evict TPM handle 0x%08x: object Name does not match credctl's recorded ownership token", keyPersistent)
		}
	} else {
		if err := verifyCredctlObject(&readRsp.OutPublic); err != nil {
			return fmt.Errorf("refusing to evict TPM handle 0x%08x: %w", keyPersistent, err)
		}
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

	// Eviction succeeded — clear the now-stale ownership token.
	_ = deleteTPMState()
	return nil
}

// verifyCredctlObject returns nil if the public area matches the template
// linuxTPMBackend.generateKey produces. This is a structural ownership check —
// not cryptographic proof of provenance, but enough to refuse to clobber
// objects parked at this handle by other TPM consumers (e.g. tpm2-tools'
// default templates, OS-provisioned keys).
func verifyCredctlObject(outPublic *tpm2.TPM2BPublic) error {
	pub, err := outPublic.Contents()
	if err != nil {
		return fmt.Errorf("failed to parse public area: %w", err)
	}
	if pub.Type != tpm2.TPMAlgECC {
		return fmt.Errorf("object is not ECC (alg=0x%04x)", uint16(pub.Type))
	}
	if pub.NameAlg != tpm2.TPMAlgSHA256 {
		return fmt.Errorf("object NameAlg is not SHA-256 (alg=0x%04x)", uint16(pub.NameAlg))
	}
	a := pub.ObjectAttributes
	if !a.FixedTPM || !a.FixedParent || !a.SensitiveDataOrigin ||
		!a.UserWithAuth || !a.NoDA || !a.SignEncrypt || a.Restricted {
		return fmt.Errorf("object attributes do not match credctl template")
	}
	eccParms, err := pub.Parameters.ECCDetail()
	if err != nil {
		return fmt.Errorf("failed to read ECC parameters: %w", err)
	}
	if eccParms.CurveID != tpm2.TPMECCNistP256 {
		return fmt.Errorf("object curve is not P-256 (curve=0x%04x)", uint16(eccParms.CurveID))
	}
	if eccParms.Scheme.Scheme != tpm2.TPMAlgECDSA {
		return fmt.Errorf("object scheme is not ECDSA (scheme=0x%04x)", uint16(eccParms.Scheme.Scheme))
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
