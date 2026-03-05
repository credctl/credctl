package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/credctl/credctl/internal/config"
	"github.com/credctl/credctl/internal/jwt"
	"github.com/credctl/credctl/internal/oidc"
	"github.com/spf13/cobra"
)

var (
	oidcIssuerURL    string
	oidcPublishBucket string
	oidcPublishRegion string
)

var oidcCmd = &cobra.Command{
	Use:   "oidc",
	Short: "Manage OIDC discovery documents for AWS federation",
}

var oidcGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate OIDC discovery and JWKS documents from device public key",
	RunE:  runOIDCGenerate,
}

var oidcPublishCmd = &cobra.Command{
	Use:   "publish",
	Short: "Upload OIDC documents to S3",
	RunE:  runOIDCPublish,
}

func init() {
	oidcGenerateCmd.Flags().StringVar(&oidcIssuerURL, "issuer-url", "", "OIDC issuer URL (e.g. https://d1234.cloudfront.net)")
	_ = oidcGenerateCmd.MarkFlagRequired("issuer-url")

	oidcPublishCmd.Flags().StringVar(&oidcPublishBucket, "bucket", "", "S3 bucket name")
	oidcPublishCmd.Flags().StringVar(&oidcPublishRegion, "region", "us-east-1", "AWS region")
	_ = oidcPublishCmd.MarkFlagRequired("bucket")

	oidcCmd.AddCommand(oidcGenerateCmd)
	oidcCmd.AddCommand(oidcPublishCmd)
	rootCmd.AddCommand(oidcCmd)
}

func runOIDCGenerate(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to read config: %w", err)
	}
	if cfg == nil {
		return fmt.Errorf("device not initialised — run 'credctl init' first")
	}

	// Read public key
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

	// Generate JWK from public key
	jwk, err := oidc.JWKFromPublicKeyPEM(pubKeyPEM, kid)
	if err != nil {
		return fmt.Errorf("generate JWK: %w", err)
	}

	// Set up output directory
	cfgDir, err := config.ConfigDir()
	if err != nil {
		return fmt.Errorf("config dir: %w", err)
	}

	oidcDir := filepath.Join(cfgDir, "oidc")
	wellKnownDir := filepath.Join(oidcDir, ".well-known")
	if err := os.MkdirAll(wellKnownDir, 0700); err != nil {
		return fmt.Errorf("create oidc directory: %w", err)
	}

	// Generate discovery document
	discovery := oidc.GenerateDiscovery(oidcIssuerURL)
	discoveryJSON, err := oidc.MarshalJSON(discovery)
	if err != nil {
		return fmt.Errorf("marshal discovery: %w", err)
	}
	discoveryPath := filepath.Join(wellKnownDir, "openid-configuration")
	if err := os.WriteFile(discoveryPath, discoveryJSON, 0600); err != nil {
		return fmt.Errorf("write discovery: %w", err)
	}

	// Generate or merge JWKS
	keysPath := filepath.Join(oidcDir, "keys.json")
	var jwks *oidc.JWKS

	if existingData, err := os.ReadFile(keysPath); err == nil {
		existing, err := oidc.UnmarshalJWKS(existingData)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not parse existing JWKS, replacing: %v\n", err)
			jwks = oidc.GenerateJWKS([]oidc.JWK{*jwk})
		} else {
			jwks = oidc.MergeJWKS(existing, jwk)
			fmt.Fprintf(os.Stderr, "Merged into existing JWKS (%d keys total)\n", len(jwks.Keys))
		}
	} else {
		jwks = oidc.GenerateJWKS([]oidc.JWK{*jwk})
	}

	jwksJSON, err := oidc.MarshalJSON(jwks)
	if err != nil {
		return fmt.Errorf("marshal JWKS: %w", err)
	}
	if err := os.WriteFile(keysPath, jwksJSON, 0600); err != nil {
		return fmt.Errorf("write JWKS: %w", err)
	}

	// Update config with issuer URL
	if cfg.AWS == nil {
		cfg.AWS = &config.AWSConfig{}
	}
	cfg.AWS.IssuerURL = oidcIssuerURL
	if err := config.Save(cfg); err != nil {
		return fmt.Errorf("save config: %w", err)
	}

	fmt.Println("OIDC documents generated:")
	fmt.Printf("  Discovery: %s\n", discoveryPath)
	fmt.Printf("  JWKS:      %s\n", keysPath)
	fmt.Printf("  Issuer:    %s\n", oidcIssuerURL)
	fmt.Printf("  Key ID:    %s\n", kid)

	return nil
}

func runOIDCPublish(cmd *cobra.Command, args []string) error {
	cfgDir, err := config.ConfigDir()
	if err != nil {
		return fmt.Errorf("config dir: %w", err)
	}

	oidcDir := filepath.Join(cfgDir, "oidc")
	discoveryPath := filepath.Join(oidcDir, ".well-known", "openid-configuration")
	keysPath := filepath.Join(oidcDir, "keys.json")

	// Verify files exist
	for _, path := range []string{discoveryPath, keysPath} {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return fmt.Errorf("OIDC files not found — run 'credctl oidc generate' first")
		}
	}

	bucket := "s3://" + oidcPublishBucket

	// Upload discovery document
	fmt.Println("Uploading OIDC discovery document...")
	if err := s3Upload(discoveryPath, bucket+"/.well-known/openid-configuration", "application/json", oidcPublishRegion); err != nil {
		return fmt.Errorf("upload discovery: %w", err)
	}

	// Upload JWKS
	fmt.Println("Uploading JWKS...")
	if err := s3Upload(keysPath, bucket+"/keys.json", "application/json", oidcPublishRegion); err != nil {
		return fmt.Errorf("upload JWKS: %w", err)
	}

	// Update config with bucket info
	cfg, err := config.Load()
	if err == nil && cfg != nil {
		if cfg.AWS == nil {
			cfg.AWS = &config.AWSConfig{}
		}
		cfg.AWS.S3Bucket = oidcPublishBucket
		cfg.AWS.Region = oidcPublishRegion
		_ = config.Save(cfg)
	}

	fmt.Println("OIDC documents published to S3.")
	return nil
}

func s3Upload(localPath, s3Path, contentType, region string) error {
	//nolint:gosec // intentional shell-out to aws CLI for one-time operation
	out, err := exec.Command("aws", "s3", "cp", localPath, s3Path,
		"--content-type", contentType,
		"--region", region,
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s", err, string(out))
	}
	return nil
}
