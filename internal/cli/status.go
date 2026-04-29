package cli

import (
	"fmt"
	"time"

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
	cfg, err := activeDeps.loadConfig()
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
	fmt.Printf("  Biometric:    %s\n", biometricLabel(cfg.Biometric))

	// Verify key is still accessible
	enc := activeDeps.newEnclave()
	_, err = enc.LoadKey(cfg.KeyTag)
	if err != nil {
		fmt.Printf("  Key accessible: no (key not found in %s)\n", enclaveStorageName())
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

	// Show GCP config if present
	if cfg.GCP != nil {
		fmt.Println("\nGCP Configuration:")
		fmt.Printf("  Project number:    %s\n", cfg.GCP.ProjectNumber)
		fmt.Printf("  Workload pool:     %s\n", cfg.GCP.WorkloadPoolID)
		fmt.Printf("  Provider:          %s\n", cfg.GCP.ProviderID)
		fmt.Printf("  Service account:   %s\n", cfg.GCP.ServiceAccountEmail)
		fmt.Printf("  Issuer URL:        %s\n", cfg.GCP.IssuerURL)
		if cfg.GCP.CredentialFilePath != "" {
			fmt.Printf("  Credential file:   %s\n", cfg.GCP.CredentialFilePath)
		}
	}

	return nil
}
