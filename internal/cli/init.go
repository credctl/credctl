package cli

import (
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/credctl/credctl/internal/config"
	"github.com/spf13/cobra"
)

var (
	initForce  bool
	initKeyTag string
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Generate a hardware-bound key pair and create device identity",
	RunE:  runInit,
}

func init() {
	initCmd.Flags().BoolVar(&initForce, "force", false, "Delete existing key and reinitialise")
	initCmd.Flags().StringVar(&initKeyTag, "key-tag", config.DefaultKeyTag, "Override the keychain application tag")
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

	// Check hardware enclave availability
	enc := activeDeps.newEnclave()
	if !enc.Available() {
		if runtime.GOOS == "linux" {
			return fmt.Errorf("TPM 2.0 is not available (check /dev/tpmrm0 permissions: sudo usermod -aG tss $USER)")
		}
		return fmt.Errorf("hardware enclave is not available on this device")
	}

	// If --force, delete existing key
	if cfg != nil && initForce {
		fmt.Println("Deleting existing key...")
		if err := enc.DeleteKey(cfg.KeyTag); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not delete existing key: %v\n", err)
		}
	}

	// Generate key
	enclaveName := "Secure Enclave"
	enclaveType := "secure_enclave"
	if runtime.GOOS == "linux" {
		enclaveName = "TPM 2.0"
		enclaveType = "tpm2"
	}
	fmt.Printf("Generating %s key pair...\n", enclaveName)
	key, err := enc.GenerateKey(initKeyTag)
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
		EnclaveType:   enclaveType,
		PublicKeyPath: "~/.credctl/device.pub",
	}
	if runtime.GOOS == "linux" {
		newCfg.TPMHandle = 0x81010001
	}

	if err := activeDeps.saveConfig(newCfg); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	// Print summary
	fmt.Println()
	fmt.Printf("\u2713 Device identity created (%s)\n", enclaveName)
	fmt.Printf("  Fingerprint: %s\n", key.Fingerprint)
	fmt.Printf("  Public key:  %s\n", pubKeyPath)
	fmt.Println()
	fmt.Println("  Next: Register this public key with your cloud provider or credctl broker.")

	return nil
}
