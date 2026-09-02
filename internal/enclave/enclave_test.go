package enclave

import (
	"runtime"
	"testing"
)

func TestNew_ReturnsNonNil(t *testing.T) {
	enc := New()
	if enc == nil {
		t.Fatal("New() returned nil")
	}
}

func TestNew_AvailableMatchesPlatform(t *testing.T) {
	enc := New()
	got := enc.Available()
	if runtime.GOOS == "darwin" && !got {
		t.Error("Available() should be true on darwin")
	}
	if runtime.GOOS == "linux" {
		// On linux, availability depends on TPM hardware presence.
		t.Logf("Available() on linux = %v (depends on /dev/tpmrm0)", got)
	}
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" && got {
		t.Error("Available() should be false on unsupported platform")
	}
}
