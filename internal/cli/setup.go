package cli

import (
	"embed"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/matzhouse/credctl/internal/config"
	"github.com/spf13/cobra"
)

//go:embed templates/credctl-infra.yaml
var cfnTemplate embed.FS

var (
	setupStackName string
	setupRoleName  string
	setupRegion    string
	setupPolicyARN string
)

var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Set up cloud provider infrastructure",
}

var setupAWSCmd = &cobra.Command{
	Use:   "aws",
	Short: "Create AWS infrastructure for credctl OIDC federation",
	Long: `Creates S3 bucket, CloudFront distribution, IAM OIDC provider, and IAM role
using CloudFormation. Requires the AWS CLI to be installed and configured.`,
	RunE: runSetupAWS,
}

func init() {
	setupAWSCmd.Flags().StringVar(&setupStackName, "stack-name", "credctl-infra", "CloudFormation stack name")
	setupAWSCmd.Flags().StringVar(&setupRoleName, "role-name", "credctl-device-role", "IAM role name")
	setupAWSCmd.Flags().StringVar(&setupRegion, "region", "us-east-1", "AWS region")
	setupAWSCmd.Flags().StringVar(&setupPolicyARN, "policy-arn", "", "Managed policy ARN to attach to the role")
	_ = setupAWSCmd.MarkFlagRequired("policy-arn")

	setupCmd.AddCommand(setupAWSCmd)
	rootCmd.AddCommand(setupCmd)
}

func runSetupAWS(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to read config: %w", err)
	}
	if cfg == nil {
		return fmt.Errorf("device not initialised — run 'credctl init' first")
	}

	// Write CloudFormation template to a temp file
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

	// Deploy CloudFormation stack
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

	//nolint:gosec // intentional shell-out to aws CLI
	deployCmd := exec.Command("aws", deployArgs...)
	deployCmd.Stdout = os.Stderr
	deployCmd.Stderr = os.Stderr

	if err := deployCmd.Run(); err != nil {
		return fmt.Errorf("CloudFormation deploy failed: %w", err)
	}

	// Wait for stack to complete and get outputs
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

	fmt.Printf("\nStack outputs:\n")
	fmt.Printf("  Issuer URL: %s\n", issuerURL)
	fmt.Printf("  Role ARN:   %s\n", roleARN)
	fmt.Printf("  S3 Bucket:  %s\n", bucketName)

	// Update config
	if cfg.AWS == nil {
		cfg.AWS = &config.AWSConfig{}
	}
	cfg.AWS.RoleARN = roleARN
	cfg.AWS.IssuerURL = issuerURL
	cfg.AWS.Region = setupRegion
	cfg.AWS.S3Bucket = bucketName
	if err := config.Save(cfg); err != nil {
		return fmt.Errorf("save config: %w", err)
	}

	// Run oidc generate + publish
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

	fmt.Println("\nAWS setup complete. Configure your AWS CLI:")
	fmt.Printf("  echo '[profile credctl]\ncredential_process = credctl auth' >> ~/.aws/config\n")

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
	//nolint:gosec // intentional shell-out to aws CLI
	out, err := exec.Command("aws", "cloudformation", "describe-stacks",
		"--stack-name", stackName,
		"--region", region,
		"--output", "json",
	).Output()
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

// awsCLIAvailable checks if the AWS CLI is installed.
func awsCLIAvailable() bool {
	_, err := exec.LookPath("aws")
	return err == nil
}

// awsAccountID returns the current AWS account ID.
func awsAccountID(region string) (string, error) {
	//nolint:gosec // intentional shell-out to aws CLI
	out, err := exec.Command("aws", "sts", "get-caller-identity",
		"--query", "Account",
		"--output", "text",
		"--region", region,
	).Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}
