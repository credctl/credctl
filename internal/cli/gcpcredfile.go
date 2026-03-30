package cli

import (
	"fmt"
	"path/filepath"

	"github.com/credctl/credctl/internal/gcp"
	"github.com/spf13/cobra"
)

var gcpCredFileOutput string

var setupGCPCredFileCmd = &cobra.Command{
	Use:        "gcp-cred-file",
	Short:      "Generate a GCP external credential configuration file",
	Deprecated: "use 'credctl setup gcp' instead (it generates the credential file automatically)",
	Long: `Creates a JSON credential configuration file that GCP client libraries
and gcloud can use to authenticate via credctl.

Set GOOGLE_APPLICATION_CREDENTIALS to the output file path, or pass it
to gcloud with --credential-file-override.`,
	RunE: runSetupGCPCredFile,
}

func init() {
	setupGCPCredFileCmd.Flags().StringVar(&gcpCredFileOutput, "output", "", "Output file path (default: ~/.credctl/gcp-credentials.json)")
	setupCmd.AddCommand(setupGCPCredFileCmd)
}

func runSetupGCPCredFile(cmd *cobra.Command, args []string) error {
	cfg, err := activeDeps.loadConfig()
	if err != nil {
		return fmt.Errorf("failed to read config: %w", err)
	}
	if cfg == nil {
		return fmt.Errorf("device not initialised — run 'credctl init' first")
	}
	if cfg.GCP == nil {
		return fmt.Errorf("GCP not configured — run 'credctl setup gcp' first")
	}

	// Resolve credctl binary path
	credctlPath, err := activeDeps.lookPath("credctl")
	if err != nil {
		return fmt.Errorf("credctl not found in PATH: %w", err)
	}

	// Resolve output path
	outputPath := gcpCredFileOutput
	if outputPath == "" {
		configDir, err := activeDeps.configDir()
		if err != nil {
			return fmt.Errorf("config directory: %w", err)
		}
		outputPath = filepath.Join(configDir, "gcp-credentials.json")
	}

	audience := cfg.GCP.Audience()
	tokenCachePath := filepath.Join(filepath.Dir(outputPath), "gcp-token-cache.json")
	credCfg := gcp.GenerateCredentialConfigWithOutput(credctlPath, audience, cfg.GCP.ServiceAccountEmail, tokenCachePath)

	if err := gcp.WriteCredentialConfig(outputPath, credCfg); err != nil {
		return fmt.Errorf("write credential config: %w", err)
	}

	fmt.Printf("Credential configuration written to %s\n", outputPath)
	fmt.Printf("\nTo use with GCP client libraries:\n")
	fmt.Printf("  export GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES=1\n")
	fmt.Printf("  export GOOGLE_APPLICATION_CREDENTIALS=%s\n", outputPath)
	fmt.Printf("\nTo use with gcloud:\n")
	fmt.Printf("  export GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES=1\n")
	fmt.Printf("  gcloud auth login --cred-file=%s\n", outputPath)

	return nil
}
