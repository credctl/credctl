package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/matzhouse/credctl/internal/aws"
	"github.com/matzhouse/credctl/internal/config"
	"github.com/matzhouse/credctl/internal/enclave"
	"github.com/matzhouse/credctl/internal/jwt"
	"github.com/spf13/cobra"
)

var authFormat string

var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "Get temporary AWS credentials using Secure Enclave identity",
	Long: `Authenticates to AWS by signing a JWT with the Secure Enclave key
and exchanging it for temporary credentials via STS AssumeRoleWithWebIdentity.

Use as an AWS credential_process:
  [profile credctl]
  credential_process = /path/to/credctl auth`,
	RunE: runAuth,
}

func init() {
	authCmd.Flags().StringVar(&authFormat, "format", "credential_process", "Output format: credential_process or env")
	rootCmd.AddCommand(authCmd)
}

// credentialProcessOutput matches the AWS credential_process JSON schema.
type credentialProcessOutput struct {
	Version         int    `json:"Version"`
	AccessKeyID     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	SessionToken    string `json:"SessionToken"`
	Expiration      string `json:"Expiration"`
}

func runAuth(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to read config: %w", err)
	}
	if cfg == nil {
		return fmt.Errorf("device not initialised — run 'credctl init' first")
	}
	if cfg.AWS == nil {
		return fmt.Errorf("AWS not configured — run 'credctl setup aws' or configure manually")
	}

	// Read public key to derive KID
	pubKeyPath, err := config.PublicKeyPath()
	if err != nil {
		return fmt.Errorf("public key path: %w", err)
	}
	pubKeyPEM, err := os.ReadFile(pubKeyPath)
	if err != nil {
		return fmt.Errorf("read public key: %w", err)
	}

	kid, err := jwt.KIDFromPublicKeyPEM(pubKeyPEM)
	if err != nil {
		return fmt.Errorf("derive key ID: %w", err)
	}

	// Build and sign JWT using the Secure Enclave
	enc := enclave.New()
	signFn := func(data []byte) ([]byte, error) {
		return enc.Sign(cfg.KeyTag, data)
	}

	fmt.Fprintln(os.Stderr, "Signing JWT with Secure Enclave...")
	token, err := jwt.BuildAndSign(kid, cfg.AWS.IssuerURL, cfg.DeviceID, signFn)
	if err != nil {
		return fmt.Errorf("build JWT: %w", err)
	}

	// Call STS
	sessionName := "credctl-" + cfg.DeviceID[:8]
	fmt.Fprintln(os.Stderr, "Requesting temporary credentials from AWS STS...")
	creds, err := aws.AssumeRoleWithWebIdentity(cfg.AWS.RoleARN, sessionName, token, cfg.AWS.Region)
	if err != nil {
		return fmt.Errorf("assume role: %w", err)
	}

	// Output credentials
	switch authFormat {
	case "credential_process":
		out := credentialProcessOutput{
			Version:         1,
			AccessKeyID:     creds.AccessKeyID,
			SecretAccessKey: creds.SecretAccessKey,
			SessionToken:    creds.SessionToken,
			Expiration:      creds.Expiration.Format(time.RFC3339),
		}
		data, err := json.Marshal(out)
		if err != nil {
			return fmt.Errorf("marshal credentials: %w", err)
		}
		fmt.Println(string(data))

	case "env":
		fmt.Printf("export AWS_ACCESS_KEY_ID=%s\n", creds.AccessKeyID)
		fmt.Printf("export AWS_SECRET_ACCESS_KEY=%s\n", creds.SecretAccessKey)
		fmt.Printf("export AWS_SESSION_TOKEN=%s\n", creds.SessionToken)

	default:
		return fmt.Errorf("unknown format: %s (use 'credential_process' or 'env')", authFormat)
	}

	fmt.Fprintln(os.Stderr, "Credentials valid until", creds.Expiration.Format(time.RFC3339))
	return nil
}
