//go:build !darwin

package enclave

import "fmt"

// stubBackend implements keyBackend for non-macOS platforms.
type stubBackend struct{}

func newPlatformEnclave() Enclave {
	return &enclaveImpl{backend: &stubBackend{}}
}

func (b *stubBackend) available() bool {
	return false
}

func (b *stubBackend) generateKey(tag string) ([]byte, error) {
	return nil, fmt.Errorf("Secure Enclave is only available on macOS")
}

func (b *stubBackend) lookupKey(tag string) ([]byte, error) {
	return nil, fmt.Errorf("Secure Enclave is only available on macOS")
}

func (b *stubBackend) deleteKey(tag string) error {
	return fmt.Errorf("Secure Enclave is only available on macOS")
}

func (b *stubBackend) sign(tag string, data []byte) ([]byte, error) {
	return nil, fmt.Errorf("Secure Enclave is only available on macOS")
}
