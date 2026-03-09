//go:build !darwin && !linux

package enclave

import "fmt"

type stubEnclave struct{}

func newPlatformEnclave() Enclave {
	return &stubEnclave{}
}

func (e *stubEnclave) Available() bool {
	return false
}

func (e *stubEnclave) GenerateKey(tag string) (*DeviceKey, error) {
	return nil, fmt.Errorf("hardware enclave not available on this platform")
}

func (e *stubEnclave) LoadKey(tag string) (*DeviceKey, error) {
	return nil, fmt.Errorf("hardware enclave not available on this platform")
}

func (e *stubEnclave) DeleteKey(tag string) error {
	return fmt.Errorf("hardware enclave not available on this platform")
}

func (e *stubEnclave) Sign(tag string, data []byte) ([]byte, error) {
	return nil, fmt.Errorf("hardware enclave not available on this platform")
}
