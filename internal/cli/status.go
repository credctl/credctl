package cli

import (
	"fmt"
	"time"

	"github.com/matzhouse/credctl/internal/config"
	"github.com/matzhouse/credctl/internal/enclave"
	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show current device identity status",
	RunE:  runStatus,
}

func init() {
	rootCmd.AddCommand(statusCmd)
}

func runStatus(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to read config: %w", err)
	}

	if cfg == nil {
		fmt.Println("Status: Not initialised")
		fmt.Println("\nRun 'credctl init' to create a device identity.")
		return nil
	}

	fmt.Println("Status: Initialised")
	fmt.Printf("  Fingerprint:  %s\n", cfg.DeviceID)
	fmt.Printf("  Enclave type: %s\n", cfg.EnclaveType)
	fmt.Printf("  Key tag:      %s\n", cfg.KeyTag)
	fmt.Printf("  Created:      %s\n", cfg.CreatedAt.Format(time.RFC3339))
	fmt.Printf("  Public key:   %s\n", cfg.PublicKeyPath)

	// Verify key is still accessible
	enc := enclave.New()
	_, err = enc.LoadKey(cfg.KeyTag)
	if err != nil {
		fmt.Println("  Key accessible: no (key not found in keychain)")
	} else {
		fmt.Println("  Key accessible: yes")
	}

	// Show AWS config if present
	if cfg.AWS != nil {
		fmt.Println("\nAWS Configuration:")
		fmt.Printf("  Role ARN:   %s\n", cfg.AWS.RoleARN)
		fmt.Printf("  Issuer URL: %s\n", cfg.AWS.IssuerURL)
		if cfg.AWS.Region != "" {
			fmt.Printf("  Region:     %s\n", cfg.AWS.Region)
		}
		if cfg.AWS.S3Bucket != "" {
			fmt.Printf("  S3 Bucket:  %s\n", cfg.AWS.S3Bucket)
		}
	}

	return nil
}
