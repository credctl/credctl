package enclave

import "time"

// DeviceKey represents a key pair managed by the Secure Enclave.
type DeviceKey struct {
	Fingerprint string
	PublicKey   []byte // PEM-encoded public key
	Tag         string
	CreatedAt   time.Time
}

// Enclave abstracts Secure Enclave operations.
type Enclave interface {
	Available() bool
	GenerateKey(tag string) (*DeviceKey, error)
	LoadKey(tag string) (*DeviceKey, error)
	DeleteKey(tag string) error
	Sign(tag string, data []byte) ([]byte, error)
}

// New returns the platform-specific Enclave implementation.
func New() Enclave {
	return newPlatformEnclave()
}
