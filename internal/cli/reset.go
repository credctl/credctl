package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/credctl/credctl/internal/config"
	"github.com/spf13/cobra"
)

var resetForce bool

var resetCmd = &cobra.Command{
	Use:   "reset",
	Short: "Delete all credctl state and cloud resources",
	Long: `Removes the ~/.credctl directory and optionally tears down cloud infrastructure:
  - AWS: deletes CloudFormation stack, IAM role, IAM OIDC provider, S3 OIDC bucket
  - GCP: deletes Workload Identity Pool (cascades to providers and bindings), GCS OIDC bucket

This is destructive and irreversible. The hardware-bound key in the ` + enclaveDisplayName() + `
is left in place; run 'credctl init --force' if you also want to rotate the key.`,
	RunE: runReset,
}

func init() {
	resetCmd.Flags().BoolVar(&resetForce, "force", false, "Skip confirmation prompt")
	rootCmd.AddCommand(resetCmd)
}

func runReset(cmd *cobra.Command, args []string) error {
	if !resetForce {
		fmt.Fprint(os.Stderr, "This will delete all credctl config and tear down cloud resources. Continue? [y/N] ")
		reader := bufio.NewReader(os.Stdin)
		answer, _ := reader.ReadString('\n')
		if strings.TrimSpace(strings.ToLower(answer)) != "y" {
			fmt.Fprintln(os.Stderr, "Aborted.")
			return nil
		}
	}

	cfg, _ := activeDeps.loadConfig()

	// Tear down AWS resources
	if cfg != nil && cfg.AWS != nil {
		teardownAWS(cfg)
	}

	// Tear down GCP resources
	if cfg != nil && cfg.GCP != nil {
		teardownGCP(cfg)
	}

	// Delete ~/.credctl
	cfgDir, err := activeDeps.configDir()
	if err == nil {
		fmt.Fprintf(os.Stderr, "Removing %s...\n", cfgDir)
		if err := os.RemoveAll(cfgDir); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not remove %s: %v\n", cfgDir, err)
		}
	}

	fmt.Fprintln(os.Stderr, "\nReset complete.")
	return nil
}

func teardownAWS(cfg *config.Config) {
	region := cfg.AWS.Region
	if region == "" {
		region = "us-east-1"
	}

	// Delete CloudFormation stack (if it was used)
	if cfg.AWS.S3Bucket != "" && cfg.AWS.RoleARN != "" {
		stackName := "credctl-infra"
		fmt.Fprintf(os.Stderr, "Deleting CloudFormation stack '%s'...\n", stackName)
		if err := activeDeps.execCommandRun("aws", "cloudformation", "delete-stack",
			"--stack-name", stackName,
			"--region", region,
		); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not delete stack: %v\n", err)
		}
	}

	// Delete IAM role (detach policy first)
	if cfg.AWS.RoleARN != "" {
		roleName := roleNameFromARN(cfg.AWS.RoleARN)
		if roleName != "" {
			fmt.Fprintf(os.Stderr, "Cleaning up IAM role '%s'...\n", roleName)

			// List and detach all managed policies
			out, err := activeDeps.execCommand("aws", "iam", "list-attached-role-policies",
				"--role-name", roleName,
				"--query", "AttachedPolicies[].PolicyArn",
				"--output", "text",
				"--region", region,
			)
			if err == nil {
				for _, arn := range strings.Fields(string(out)) {
					_ = activeDeps.execCommandRun("aws", "iam", "detach-role-policy",
						"--role-name", roleName,
						"--policy-arn", arn,
						"--region", region,
					)
				}
			}

			_ = activeDeps.execCommandRun("aws", "iam", "delete-role",
				"--role-name", roleName,
				"--region", region,
			)
		}
	}

	// Delete OIDC provider
	if cfg.AWS.IssuerURL != "" {
		issuerHost := strings.TrimPrefix(cfg.AWS.IssuerURL, "https://")
		accountID, err := awsAccountID(region)
		if err == nil {
			providerARN := fmt.Sprintf("arn:aws:iam::%s:oidc-provider/%s", accountID, issuerHost)
			fmt.Fprintf(os.Stderr, "Deleting IAM OIDC provider...\n")
			_ = activeDeps.execCommandRun("aws", "iam", "delete-open-id-connect-provider",
				"--open-id-connect-provider-arn", providerARN,
				"--region", region,
			)
		}
	}

	// Delete S3 OIDC bucket (if it was a standalone bucket, not from CloudFormation)
	if cfg.AWS.S3Bucket != "" && strings.HasPrefix(cfg.AWS.S3Bucket, "credctl-oidc-") {
		fmt.Fprintf(os.Stderr, "Deleting S3 bucket '%s'...\n", cfg.AWS.S3Bucket)
		_ = activeDeps.execCommandRun("aws", "s3", "rb",
			"s3://"+cfg.AWS.S3Bucket, "--force",
			"--region", region,
		)
	}
}

func teardownGCP(cfg *config.Config) {
	project := ""
	// Try to get project from gcloud config
	out, err := activeDeps.execCommand("gcloud", "config", "get-value", "project", "--quiet")
	if err == nil {
		project = strings.TrimSpace(string(out))
	}
	if project == "" {
		fmt.Fprintln(os.Stderr, "Warning: could not determine GCP project, skipping GCP teardown")
		return
	}

	// Delete Workload Identity Pool (cascades to providers and bindings)
	if cfg.GCP.WorkloadPoolID != "" {
		fmt.Fprintf(os.Stderr, "Deleting Workload Identity Pool '%s'...\n", cfg.GCP.WorkloadPoolID)
		_ = activeDeps.execCommandRun("gcloud", "iam", "workload-identity-pools", "delete",
			cfg.GCP.WorkloadPoolID,
			"--project", project,
			"--location", "global",
			"--quiet",
		)
	}

	// Delete GCS OIDC bucket
	if cfg.GCP.IssuerURL != "" && strings.Contains(cfg.GCP.IssuerURL, "storage.googleapis.com/") {
		bucket := strings.TrimPrefix(cfg.GCP.IssuerURL, "https://storage.googleapis.com/")
		if bucket != "" {
			fmt.Fprintf(os.Stderr, "Deleting GCS bucket '%s'...\n", bucket)
			_ = activeDeps.execCommandRun("gcloud", "storage", "rm", "-r",
				"gs://"+bucket,
				"--project", project,
				"--quiet",
			)
		}
	}

	// Delete credential file
	if cfg.GCP.CredentialFilePath != "" {
		fmt.Fprintf(os.Stderr, "Removing %s...\n", cfg.GCP.CredentialFilePath)
		os.Remove(cfg.GCP.CredentialFilePath)
	}
}

func roleNameFromARN(arn string) string {
	// arn:aws:iam::123456789012:role/credctl-device-role
	parts := strings.Split(arn, "/")
	if len(parts) >= 2 {
		return parts[len(parts)-1]
	}
	return ""
}
