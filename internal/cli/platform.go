package cli

import "runtime"

// enclaveDisplayName returns the user-facing name of the hardware enclave on
// this platform — used in help text and runtime messages.
func enclaveDisplayName() string {
	if runtime.GOOS == "linux" {
		return "TPM 2.0"
	}
	return "Secure Enclave"
}

// enclaveStorageName returns the user-facing name of the platform's key store.
// Used in messages like "key not found in <store>".
func enclaveStorageName() string {
	if runtime.GOOS == "linux" {
		return "TPM"
	}
	return "keychain"
}

// enclaveTypeID returns the config-stored enclave type identifier.
func enclaveTypeID() string {
	if runtime.GOOS == "linux" {
		return "tpm2"
	}
	return "secure_enclave"
}
