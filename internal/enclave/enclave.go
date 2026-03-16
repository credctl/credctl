package enclave

import "time"

// BiometricPolicy controls the user verification required for Secure Enclave signing.
type BiometricPolicy string

const (
	BiometricAny         BiometricPolicy = "any"         // Touch ID with passcode fallback
	BiometricFingerprint BiometricPolicy = "fingerprint"  // Touch ID only, no fallback
	BiometricNone        BiometricPolicy = "none"         // No user verification
)

// DeviceKey represents a key pair managed by the Secure Enclave.
type DeviceKey struct {
	Fingerprint string
	PublicKey   []byte // PEM-encoded public key
	Tag         string
	CreatedAt   time.Time
	Biometric   BiometricPolicy
}

// Enclave abstracts Secure Enclave operations.
type Enclave interface {
	Available() bool
	GenerateKey(tag string, biometric BiometricPolicy) (*DeviceKey, error)
	LoadKey(tag string) (*DeviceKey, error)
	DeleteKey(tag string) error
	Sign(tag string, data []byte) ([]byte, error)
}

// New returns the platform-specific Enclave implementation.
func New() Enclave {
	return newPlatformEnclave()
}
