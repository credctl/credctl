package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/credctl/credctl/internal/config"
	"github.com/spf13/cobra"
)

var (
	awsOIDCBucket string
	awsOIDCRegion string
)

var setupAWSOIDCCmd = &cobra.Command{
	Use:        "aws-oidc",
	Short:      "Host OIDC discovery documents on S3 (no CloudFront)",
	Deprecated: "use 'credctl setup aws' instead (it handles OIDC hosting automatically)",
	Long: `Creates a public S3 bucket and uploads OIDC discovery documents so you can use
credctl without a CloudFront distribution. Simpler and cheaper than 'setup aws',
but without CDN caching or DDoS protection.

Use this when you want a lightweight setup or when hosting OIDC for
cross-cloud use (GCP can also trust an S3-hosted issuer).`,
	RunE: runSetupAWSOIDC,
}

func init() {
	setupAWSOIDCCmd.Flags().StringVar(&awsOIDCBucket, "bucket", "", "S3 bucket name (default: credctl-oidc-{account-id})")
	setupAWSOIDCCmd.Flags().StringVar(&awsOIDCRegion, "region", "us-east-1", "AWS region")

	setupCmd.AddCommand(setupAWSOIDCCmd)
}

func runSetupAWSOIDC(cmd *cobra.Command, args []string) error {
	cfg, err := activeDeps.loadConfig()
	if err != nil {
		return fmt.Errorf("failed to read config: %w", err)
	}
	if cfg == nil {
		return fmt.Errorf("device not initialised — run 'credctl init' first")
	}

	if !awsCLIAvailable() {
		return fmt.Errorf("AWS CLI not found — install it from https://aws.amazon.com/cli/")
	}

	// Resolve bucket name
	bucket := awsOIDCBucket
	if bucket == "" {
		accountID, err := awsAccountID(awsOIDCRegion)
		if err != nil {
			return fmt.Errorf("could not determine AWS account ID — use --bucket flag: %w", err)
		}
		bucket = "credctl-oidc-" + accountID
	}

	issuerURL := fmt.Sprintf("https://%s.s3.%s.amazonaws.com", bucket, awsOIDCRegion)

	// Create bucket (ignore error if it already exists)
	fmt.Fprintf(os.Stderr, "Creating S3 bucket '%s'...\n", bucket)
	createArgs := []string{"s3api", "create-bucket",
		"--bucket", bucket,
		"--region", awsOIDCRegion,
	}
	// LocationConstraint is required for regions other than us-east-1
	if awsOIDCRegion != "us-east-1" {
		createArgs = append(createArgs,
			"--create-bucket-configuration",
			fmt.Sprintf("LocationConstraint=%s", awsOIDCRegion),
		)
	}
	if err := activeDeps.execCommandRun("aws", createArgs...); err != nil {
		fmt.Fprintln(os.Stderr, "Bucket may already exist, continuing...")
	}

	// Disable Block Public Access
	fmt.Fprintln(os.Stderr, "Configuring public access...")
	if err := activeDeps.execCommandRun("aws", "s3api", "put-public-access-block",
		"--bucket", bucket,
		"--public-access-block-configuration",
		"BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false",
		"--region", awsOIDCRegion,
	); err != nil {
		return fmt.Errorf("failed to disable block public access: %w", err)
	}

	// Set bucket policy for public read on OIDC paths only
	policy := map[string]interface{}{
		"Version": "2012-10-17",
		"Statement": []map[string]interface{}{
			{
				"Sid":       "AllowPublicReadOIDC",
				"Effect":    "Allow",
				"Principal": "*",
				"Action":    "s3:GetObject",
				"Resource": []string{
					fmt.Sprintf("arn:aws:s3:::%s/.well-known/*", bucket),
					fmt.Sprintf("arn:aws:s3:::%s/keys.json", bucket),
				},
			},
		},
	}
	policyJSON, _ := json.Marshal(policy)

	if err := activeDeps.execCommandRun("aws", "s3api", "put-bucket-policy",
		"--bucket", bucket,
		"--policy", string(policyJSON),
		"--region", awsOIDCRegion,
	); err != nil {
		return fmt.Errorf("failed to set bucket policy: %w", err)
	}

	// Generate OIDC documents
	fmt.Fprintln(os.Stderr, "Generating OIDC documents...")
	oidcIssuerURL = issuerURL
	if err := runOIDCGenerate(cmd, nil); err != nil {
		return fmt.Errorf("oidc generate: %w", err)
	}

	// Upload to S3
	fmt.Fprintln(os.Stderr, "Uploading OIDC documents to S3...")
	cfgDir, err := activeDeps.configDir()
	if err != nil {
		return fmt.Errorf("config dir: %w", err)
	}
	oidcDir := filepath.Join(cfgDir, "oidc")

	discoveryPath := filepath.Join(oidcDir, ".well-known", "openid-configuration")
	keysPath := filepath.Join(oidcDir, "keys.json")

	s3Bucket := "s3://" + bucket
	if err := s3Upload(discoveryPath, s3Bucket+"/.well-known/openid-configuration", "application/json", awsOIDCRegion); err != nil {
		return fmt.Errorf("upload discovery: %w", err)
	}
	if err := s3Upload(keysPath, s3Bucket+"/keys.json", "application/json", awsOIDCRegion); err != nil {
		return fmt.Errorf("upload JWKS: %w", err)
	}

	// Save config
	if cfg.AWS == nil {
		cfg.AWS = &config.AWSConfig{}
	}
	cfg.AWS.IssuerURL = issuerURL
	cfg.AWS.S3Bucket = bucket
	cfg.AWS.Region = awsOIDCRegion

	if cfg.GCP == nil {
		cfg.GCP = &config.GCPConfig{}
	}
	cfg.GCP.IssuerURL = issuerURL

	if err := activeDeps.saveConfig(cfg); err != nil {
		return fmt.Errorf("save config: %w", err)
	}

	fmt.Fprintf(os.Stderr, "\nAWS OIDC setup complete.\n")
	fmt.Fprintf(os.Stderr, "  Issuer URL: %s\n", issuerURL)
	fmt.Fprintf(os.Stderr, "  Bucket:     s3://%s\n", bucket)

	if cfg.AWS.RoleARN == "" {
		fmt.Fprintln(os.Stderr, "\nNext: create the IAM OIDC provider and role:")
		fmt.Fprintf(os.Stderr, "  credctl setup aws --issuer-url %s --policy-arn <arn>\n", issuerURL)
	}

	return nil
}
