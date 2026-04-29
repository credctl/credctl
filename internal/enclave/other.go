//go:build !darwin && !linux

package enclave

import "fmt"

// stubBackend implements keyBackend for platforms without a hardware enclave.
type stubBackend struct{}

func newPlatformEnclave() Enclave {
	return &enclaveImpl{backend: &stubBackend{}}
}

func (b *stubBackend) available() bool {
	return false
}

func (b *stubBackend) generateKey(tag string, biometric BiometricPolicy) ([]byte, error) {
	return nil, fmt.Errorf("hardware enclave is not available on this platform")
}

func (b *stubBackend) lookupKey(tag string) ([]byte, error) {
	return nil, fmt.Errorf("hardware enclave is not available on this platform")
}

func (b *stubBackend) deleteKey(tag string) error {
	return fmt.Errorf("hardware enclave is not available on this platform")
}

func (b *stubBackend) sign(tag string, data []byte) ([]byte, error) {
	return nil, fmt.Errorf("hardware enclave is not available on this platform")
}
