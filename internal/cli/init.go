package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/credctl/credctl/internal/config"
	"github.com/credctl/credctl/internal/enclave"
	"github.com/spf13/cobra"
)

var (
	initForce     bool
	initKeyTag    string
	initBiometric string
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Generate a Secure Enclave key pair and create device identity",
	RunE:  runInit,
}

func init() {
	initCmd.Flags().BoolVar(&initForce, "force", false, "Delete existing key and reinitialise")
	initCmd.Flags().StringVar(&initKeyTag, "key-tag", config.DefaultKeyTag, "Override the keychain application tag")
	initCmd.Flags().StringVar(&initBiometric, "biometric", "any", "Biometric policy for signing: any, fingerprint, none")
	rootCmd.AddCommand(initCmd)
}

func runInit(cmd *cobra.Command, args []string) error {
	// Check for existing config
	cfg, err := activeDeps.loadConfig()
	if err != nil {
		return fmt.Errorf("failed to read config: %w", err)
	}

	if cfg != nil && !initForce {
		fmt.Fprintln(os.Stderr, "Device identity already exists.")
		fmt.Fprintf(os.Stderr, "  Fingerprint: %s\n", cfg.DeviceID)
		fmt.Fprintf(os.Stderr, "  Created:     %s\n", cfg.CreatedAt.Format(time.RFC3339))
		fmt.Fprintln(os.Stderr, "\nUse --force to reinitialise (this will delete the existing key).")
		return nil
	}

	// Validate biometric flag
	biometric := enclave.BiometricPolicy(initBiometric)
	switch biometric {
	case enclave.BiometricAny, enclave.BiometricFingerprint, enclave.BiometricNone:
		// valid
	default:
		return fmt.Errorf("invalid --biometric value %q: must be any, fingerprint, or none", initBiometric)
	}

	// Check Secure Enclave availability
	enc := activeDeps.newEnclave()
	if !enc.Available() {
		return fmt.Errorf("Secure Enclave is not available on this device")
	}

	// If --force, delete existing key
	if cfg != nil && initForce {
		fmt.Println("Deleting existing key...")
		if err := enc.DeleteKey(cfg.KeyTag); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not delete existing key: %v\n", err)
		}
	}

	// Generate key
	fmt.Println("Generating Secure Enclave key pair...")
	key, err := enc.GenerateKey(initKeyTag, biometric)
	if err != nil {
		return fmt.Errorf("key generation failed: %w", err)
	}

	// Write public key PEM
	pubKeyPath, err := activeDeps.publicKeyPath()
	if err != nil {
		return fmt.Errorf("failed to determine public key path: %w", err)
	}

	dir, err := activeDeps.configDir()
	if err != nil {
		return fmt.Errorf("failed to determine config directory: %w", err)
	}

	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	if err := os.WriteFile(pubKeyPath, key.PublicKey, 0600); err != nil {
		return fmt.Errorf("failed to write public key: %w", err)
	}

	// Write config
	newCfg := &config.Config{
		Version:       1,
		DeviceID:      key.Fingerprint,
		KeyTag:        key.Tag,
		CreatedAt:     key.CreatedAt,
		EnclaveType:   "secure_enclave",
		PublicKeyPath: "~/.credctl/device.pub",
		Biometric:     string(biometric),
	}

	if err := activeDeps.saveConfig(newCfg); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	// Print summary
	fmt.Println()
	fmt.Println("\u2713 Device identity created (Secure Enclave)")
	fmt.Printf("  Fingerprint: %s\n", key.Fingerprint)
	fmt.Printf("  Public key:  %s\n", pubKeyPath)
	fmt.Printf("  Biometric:   %s\n", biometricLabel(string(biometric)))
	fmt.Println()
	fmt.Println("  Next: Register this public key with your cloud provider or credctl broker.")

	return nil
}

// biometricLabel returns a human-readable label for a biometric policy value.
func biometricLabel(b string) string {
	switch b {
	case "any":
		return "Touch ID + passcode"
	case "fingerprint":
		return "Touch ID only"
	case "none":
		return "none"
	default:
		return "none (legacy)"
	}
}
