package cli

import (
	"crypto" //nolint:gosec // AWS IAM requires SHA-1 thumbprints for OIDC providers
	"crypto/tls"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/credctl/credctl/internal/config"
	"github.com/spf13/cobra"
)

//go:embed templates/credctl-infra.yaml
var cfnTemplate embed.FS

var (
	setupStackName   string
	setupRoleName    string
	setupRegion      string
	setupPolicyARN   string
	setupIssuerURL   string
	setupCloudFront  bool
	setupAWSBucket   string
)

var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Set up cloud provider infrastructure",
}

var setupAWSCmd = &cobra.Command{
	Use:   "aws",
	Short: "Set up AWS infrastructure for credctl",
	Long: `Creates all AWS infrastructure needed for credctl OIDC federation:

1. OIDC hosting — creates an S3 bucket and uploads discovery documents
   (or reuses an existing OIDC endpoint if one is already configured)
2. IAM OIDC provider — tells AWS to trust your OIDC issuer
3. IAM role — the role credctl assumes, with your policy attached
4. AWS CLI profile — configures credential_process for transparent use

If you previously set up GCP, the existing OIDC endpoint is reused automatically.

Use --cloudfront to deploy via CloudFormation with a CloudFront CDN instead of
direct S3 hosting.

Requires the AWS CLI to be installed and configured.`,
	RunE: runSetupAWS,
}

func init() {
	setupAWSCmd.Flags().StringVar(&setupPolicyARN, "policy-arn", "", "Managed policy ARN to attach to the role")
	setupAWSCmd.Flags().StringVar(&setupRoleName, "role-name", "credctl-device-role", "IAM role name")
	setupAWSCmd.Flags().StringVar(&setupRegion, "region", "us-east-1", "AWS region")
	setupAWSCmd.Flags().BoolVar(&setupCloudFront, "cloudfront", false, "Deploy via CloudFormation with CloudFront CDN")
	setupAWSCmd.Flags().StringVar(&setupAWSBucket, "bucket", "", "S3 bucket name for OIDC hosting (default: credctl-oidc-{account-id})")
	setupAWSCmd.Flags().StringVar(&setupStackName, "stack-name", "credctl-infra", "CloudFormation stack name (only with --cloudfront)")
	setupAWSCmd.Flags().StringVar(&setupIssuerURL, "issuer-url", "", "Use an existing OIDC issuer URL (advanced)")
	_ = setupAWSCmd.MarkFlagRequired("policy-arn")
	_ = setupAWSCmd.Flags().MarkHidden("issuer-url")
	_ = setupAWSCmd.Flags().MarkHidden("stack-name")

	setupCmd.AddCommand(setupAWSCmd)
	rootCmd.AddCommand(setupCmd)
}

func runSetupAWS(cmd *cobra.Command, args []string) error {
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

	// --cloudfront: use the original CloudFormation path
	if setupCloudFront {
		return runSetupAWSCloudFormation(cmd, cfg)
	}

	// Step 1: Resolve issuer URL
	issuerURL := resolveIssuerURL(cfg)

	// Step 2: If no issuer URL exists anywhere, create S3 OIDC hosting
	if issuerURL == "" {
		var err error
		issuerURL, err = createS3OIDCBucket(cfg)
		if err != nil {
			return fmt.Errorf("create OIDC hosting: %w", err)
		}
	} else {
		// Re-publish OIDC docs in case key was rotated
		fmt.Fprintf(os.Stderr, "Using existing OIDC issuer: %s\n", issuerURL)
		oidcIssuerURL = issuerURL
		if err := runOIDCGenerate(cmd, nil); err != nil {
			return fmt.Errorf("oidc generate: %w", err)
		}
		// Re-publish if we own an S3 bucket
		if cfg.AWS != nil && cfg.AWS.S3Bucket != "" {
			oidcPublishBucket = cfg.AWS.S3Bucket
			oidcPublishRegion = setupRegion
			_ = runOIDCPublish(cmd, nil)
		}
	}

	// Step 3: Create/update IAM resources
	roleARN, err := createAWSIAMResources(cfg, issuerURL)
	if err != nil {
		return err
	}

	// Step 4: Save config
	if cfg.AWS == nil {
		cfg.AWS = &config.AWSConfig{}
	}
	cfg.AWS.RoleARN = roleARN
	cfg.AWS.IssuerURL = issuerURL
	cfg.AWS.Region = setupRegion
	if err := activeDeps.saveConfig(cfg); err != nil {
		return fmt.Errorf("save config: %w", err)
	}

	// Step 5: Auto-run aws-profile
	fmt.Fprintln(os.Stderr, "\nConfiguring AWS CLI profile...")
	awsProfileName = "credctl"
	awsProfileForce = true
	if err := runSetupAWSProfile(cmd, nil); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not configure AWS profile: %v\n", err)
	}

	fmt.Fprintf(os.Stderr, "\nAWS setup complete.\n")
	fmt.Fprintf(os.Stderr, "  Issuer URL: %s\n", issuerURL)
	fmt.Fprintf(os.Stderr, "  Role ARN:   %s\n", roleARN)
	fmt.Fprintf(os.Stderr, "\nTest it:\n")
	fmt.Fprintf(os.Stderr, "  credctl auth\n")

	return nil
}

// resolveIssuerURL returns an existing issuer URL from config or flags.
// Returns "" if none exists (caller should create one).
func resolveIssuerURL(cfg *config.Config) string {
	// Priority 1: explicit flag
	if setupIssuerURL != "" {
		return setupIssuerURL
	}
	// Priority 2: existing AWS config
	if cfg.AWS != nil && cfg.AWS.IssuerURL != "" {
		return cfg.AWS.IssuerURL
	}
	// Priority 3: existing GCP config
	if cfg.GCP != nil && cfg.GCP.IssuerURL != "" {
		return cfg.GCP.IssuerURL
	}
	return ""
}

// createS3OIDCBucket creates a public S3 bucket and uploads OIDC documents.
func createS3OIDCBucket(cfg *config.Config) (string, error) {
	bucket := setupAWSBucket
	if bucket == "" {
		accountID, err := awsAccountID(setupRegion)
		if err != nil {
			return "", fmt.Errorf("could not determine AWS account ID: %w", err)
		}
		bucket = "credctl-oidc-" + accountID
	}

	issuerURL := fmt.Sprintf("https://%s.s3.%s.amazonaws.com", bucket, setupRegion)

	// Create bucket
	fmt.Fprintf(os.Stderr, "Creating S3 bucket '%s'...\n", bucket)
	createArgs := []string{"s3api", "create-bucket",
		"--bucket", bucket,
		"--region", setupRegion,
	}
	if setupRegion != "us-east-1" {
		createArgs = append(createArgs,
			"--create-bucket-configuration",
			fmt.Sprintf("LocationConstraint=%s", setupRegion),
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
		"--region", setupRegion,
	); err != nil {
		return "", fmt.Errorf("failed to disable block public access: %w", err)
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
		"--region", setupRegion,
	); err != nil {
		return "", fmt.Errorf("failed to set bucket policy: %w", err)
	}

	// Generate and upload OIDC documents
	fmt.Fprintln(os.Stderr, "Generating OIDC documents...")
	oidcIssuerURL = issuerURL
	if err := runOIDCGenerate(nil, nil); err != nil {
		return "", fmt.Errorf("oidc generate: %w", err)
	}

	fmt.Fprintln(os.Stderr, "Uploading OIDC documents...")
	cfgDir, err := activeDeps.configDir()
	if err != nil {
		return "", fmt.Errorf("config dir: %w", err)
	}
	oidcDir := filepath.Join(cfgDir, "oidc")
	s3Bucket := "s3://" + bucket
	if err := s3Upload(filepath.Join(oidcDir, ".well-known", "openid-configuration"), s3Bucket+"/.well-known/openid-configuration", "application/json", setupRegion); err != nil {
		return "", fmt.Errorf("upload discovery: %w", err)
	}
	if err := s3Upload(filepath.Join(oidcDir, "keys.json"), s3Bucket+"/keys.json", "application/json", setupRegion); err != nil {
		return "", fmt.Errorf("upload JWKS: %w", err)
	}

	// Save bucket to config
	if cfg.AWS == nil {
		cfg.AWS = &config.AWSConfig{}
	}
	cfg.AWS.S3Bucket = bucket

	return issuerURL, nil
}

// createAWSIAMResources creates or updates the IAM OIDC provider and role.
func createAWSIAMResources(cfg *config.Config, issuerURL string) (string, error) {
	issuerHost := strings.TrimPrefix(issuerURL, "https://")

	// Compute the TLS certificate thumbprint for the OIDC endpoint
	fmt.Fprintf(os.Stderr, "Fetching TLS thumbprint for %s...\n", issuerHost)
	thumbprint, err := activeDeps.tlsThumbprint(issuerHost)
	if err != nil {
		return "", fmt.Errorf("get TLS thumbprint: %w", err)
	}

	accountID, err := awsAccountID(setupRegion)
	if err != nil {
		return "", fmt.Errorf("get AWS account ID: %w", err)
	}

	// Delete old OIDC provider if issuer URL has changed
	if cfg.AWS != nil && cfg.AWS.IssuerURL != "" && cfg.AWS.IssuerURL != issuerURL {
		oldHost := strings.TrimPrefix(cfg.AWS.IssuerURL, "https://")
		oldProviderARN := fmt.Sprintf("arn:aws:iam::%s:oidc-provider/%s", accountID, oldHost)
		fmt.Fprintf(os.Stderr, "Removing old OIDC provider (%s)...\n", cfg.AWS.IssuerURL)
		_ = activeDeps.execCommandRun("aws", "iam", "delete-open-id-connect-provider",
			"--open-id-connect-provider-arn", oldProviderARN,
			"--region", setupRegion,
		)
	}

	// Create IAM OIDC provider
	fmt.Fprintf(os.Stderr, "Creating IAM OIDC provider for %s...\n", issuerURL)
	if err := activeDeps.execCommandRun("aws", "iam", "create-open-id-connect-provider",
		"--url", issuerURL,
		"--client-id-list", "sts.amazonaws.com",
		"--thumbprint-list", thumbprint,
		"--region", setupRegion,
	); err != nil {
		fmt.Fprintln(os.Stderr, "OIDC provider may already exist, continuing...")
	}

	oidcProviderARN := fmt.Sprintf("arn:aws:iam::%s:oidc-provider/%s", accountID, issuerHost)

	// Build trust policy
	trustPolicy := map[string]interface{}{
		"Version": "2012-10-17",
		"Statement": []map[string]interface{}{
			{
				"Effect": "Allow",
				"Principal": map[string]string{
					"Federated": oidcProviderARN,
				},
				"Action": "sts:AssumeRoleWithWebIdentity",
				"Condition": map[string]interface{}{
					"StringEquals": map[string]string{
						issuerHost + ":sub": cfg.DeviceID,
						issuerHost + ":aud": "sts.amazonaws.com",
					},
				},
			},
		},
	}
	trustPolicyJSON, _ := json.Marshal(trustPolicy)

	// Create or update role
	fmt.Fprintf(os.Stderr, "Creating IAM role '%s'...\n", setupRoleName)
	if err := activeDeps.execCommandRun("aws", "iam", "create-role",
		"--role-name", setupRoleName,
		"--assume-role-policy-document", string(trustPolicyJSON),
		"--region", setupRegion,
	); err != nil {
		fmt.Fprintln(os.Stderr, "Role exists, updating trust policy...")
		if err := activeDeps.execCommandRun("aws", "iam", "update-assume-role-policy",
			"--role-name", setupRoleName,
			"--policy-document", string(trustPolicyJSON),
			"--region", setupRegion,
		); err != nil {
			return "", fmt.Errorf("failed to update role trust policy: %w", err)
		}
	}

	// Attach policy
	fmt.Fprintf(os.Stderr, "Attaching policy %s...\n", setupPolicyARN)
	if err := activeDeps.execCommandRun("aws", "iam", "attach-role-policy",
		"--role-name", setupRoleName,
		"--policy-arn", setupPolicyARN,
		"--region", setupRegion,
	); err != nil {
		return "", fmt.Errorf("attach policy: %w", err)
	}

	return fmt.Sprintf("arn:aws:iam::%s:role/%s", accountID, setupRoleName), nil
}

// runSetupAWSCloudFormation runs the original CloudFormation-based setup path.
func runSetupAWSCloudFormation(cmd *cobra.Command, cfg *config.Config) error {
	templateData, err := cfnTemplate.ReadFile("templates/credctl-infra.yaml")
	if err != nil {
		return fmt.Errorf("read embedded template: %w", err)
	}

	tmpFile, err := os.CreateTemp("", "credctl-cfn-*.yaml")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write(templateData); err != nil {
		tmpFile.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	tmpFile.Close()

	fmt.Printf("Deploying CloudFormation stack '%s' in %s...\n", setupStackName, setupRegion)

	deployArgs := []string{
		"cloudformation", "deploy",
		"--template-file", tmpFile.Name(),
		"--stack-name", setupStackName,
		"--region", setupRegion,
		"--capabilities", "CAPABILITY_NAMED_IAM",
		"--parameter-overrides",
		fmt.Sprintf("DeviceFingerprint=%s", cfg.DeviceID),
		fmt.Sprintf("RoleName=%s", setupRoleName),
		fmt.Sprintf("RolePolicyArn=%s", setupPolicyARN),
	}

	if err := activeDeps.execCommandRun("aws", deployArgs...); err != nil {
		return fmt.Errorf("CloudFormation deploy failed: %w", err)
	}

	fmt.Println("Waiting for stack to complete...")
	time.Sleep(2 * time.Second)

	outputs, err := getStackOutputs(setupStackName, setupRegion)
	if err != nil {
		return fmt.Errorf("get stack outputs: %w", err)
	}

	issuerURL := outputs["IssuerURL"]
	roleARN := outputs["RoleARN"]
	bucketName := outputs["BucketName"]

	if issuerURL == "" || roleARN == "" {
		return fmt.Errorf("stack outputs missing — check CloudFormation console")
	}

	// Update config
	if cfg.AWS == nil {
		cfg.AWS = &config.AWSConfig{}
	}
	cfg.AWS.RoleARN = roleARN
	cfg.AWS.IssuerURL = issuerURL
	cfg.AWS.Region = setupRegion
	cfg.AWS.S3Bucket = bucketName
	if err := activeDeps.saveConfig(cfg); err != nil {
		return fmt.Errorf("save config: %w", err)
	}

	// Generate + publish OIDC docs
	fmt.Println("\nGenerating OIDC documents...")
	oidcIssuerURL = issuerURL
	if err := runOIDCGenerate(cmd, nil); err != nil {
		return fmt.Errorf("oidc generate: %w", err)
	}

	fmt.Println("\nPublishing OIDC documents...")
	oidcPublishBucket = bucketName
	oidcPublishRegion = setupRegion
	if err := runOIDCPublish(cmd, nil); err != nil {
		return fmt.Errorf("oidc publish: %w", err)
	}

	// Auto-run aws-profile
	fmt.Fprintln(os.Stderr, "\nConfiguring AWS CLI profile...")
	awsProfileName = "credctl"
	awsProfileForce = true
	if err := runSetupAWSProfile(cmd, nil); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not configure AWS profile: %v\n", err)
	}

	fmt.Fprintf(os.Stderr, "\nAWS setup complete.\n")
	fmt.Fprintf(os.Stderr, "  Issuer URL: %s\n", issuerURL)
	fmt.Fprintf(os.Stderr, "  Role ARN:   %s\n", roleARN)
	fmt.Fprintf(os.Stderr, "  S3 Bucket:  %s\n", bucketName)
	fmt.Fprintf(os.Stderr, "\nTest it:\n")
	fmt.Fprintf(os.Stderr, "  credctl auth\n")

	return nil
}

type stackOutput struct {
	OutputKey   string `json:"OutputKey"`
	OutputValue string `json:"OutputValue"`
}

type describeStacksOutput struct {
	Stacks []struct {
		Outputs []stackOutput `json:"Outputs"`
	} `json:"Stacks"`
}

func getStackOutputs(stackName, region string) (map[string]string, error) {
	out, err := activeDeps.execCommand("aws", "cloudformation", "describe-stacks",
		"--stack-name", stackName,
		"--region", region,
		"--output", "json",
	)
	if err != nil {
		return nil, fmt.Errorf("describe-stacks: %w", err)
	}

	var result describeStacksOutput
	if err := json.Unmarshal(out, &result); err != nil {
		return nil, fmt.Errorf("parse describe-stacks: %w", err)
	}

	if len(result.Stacks) == 0 {
		return nil, fmt.Errorf("stack not found")
	}

	outputs := make(map[string]string)
	for _, o := range result.Stacks[0].Outputs {
		outputs[o.OutputKey] = o.OutputValue
	}
	return outputs, nil
}

// tlsThumbprint connects to a host on port 443 and returns the SHA-1
// fingerprint of the leaf TLS certificate, lowercase hex encoded.
// This is the format AWS IAM expects for OIDC provider thumbprints.
func tlsThumbprint(host string) (string, error) {
	conn, err := tls.Dial("tcp", host+":443", &tls.Config{
		MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		return "", fmt.Errorf("TLS connect to %s: %w", host, err)
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return "", fmt.Errorf("no certificates from %s", host)
	}

	// Use the last cert in the chain (root or intermediate closest to root)
	// AWS docs say to use the top intermediate CA certificate
	cert := certs[len(certs)-1]
	h := crypto.SHA1.New() //nolint:gosec // AWS IAM requires SHA-1 thumbprints for OIDC providers
	h.Write(cert.Raw)
	fingerprint := h.Sum(nil)
	return hex.EncodeToString(fingerprint[:]), nil
}

// awsCLIAvailable checks if the AWS CLI is installed.
func awsCLIAvailable() bool {
	_, err := activeDeps.lookPath("aws")
	return err == nil
}

// awsAccountID returns the current AWS account ID.
func awsAccountID(region string) (string, error) {
	out, err := activeDeps.execCommand("aws", "sts", "get-caller-identity",
		"--query", "Account",
		"--output", "text",
		"--region", region,
	)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}
