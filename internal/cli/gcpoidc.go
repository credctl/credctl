package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/credctl/credctl/internal/config"
	"github.com/spf13/cobra"
)

var (
	gcpOIDCBucket  string
	gcpOIDCProject string
	gcpOIDCRegion  string
)

var setupGCPOIDCCmd = &cobra.Command{
	Use:        "gcp-oidc",
	Short:      "Host OIDC discovery documents on Google Cloud Storage",
	Deprecated: "use 'credctl setup gcp' instead (it handles OIDC hosting automatically)",
	Long: `Creates a GCS bucket and uploads OIDC discovery documents so you can use
credctl with GCP (or AWS) without needing an AWS CloudFront distribution.

The bucket is made publicly readable so that cloud providers can fetch
the JWKS during credential exchange.`,
	RunE: runSetupGCPOIDC,
}

func init() {
	setupGCPOIDCCmd.Flags().StringVar(&gcpOIDCBucket, "bucket", "", "GCS bucket name (default: credctl-oidc-{project})")
	setupGCPOIDCCmd.Flags().StringVar(&gcpOIDCProject, "project", "", "GCP project ID (defaults to gcloud config)")
	setupGCPOIDCCmd.Flags().StringVar(&gcpOIDCRegion, "region", "us-central1", "GCS bucket location")

	setupCmd.AddCommand(setupGCPOIDCCmd)
}

func runSetupGCPOIDC(cmd *cobra.Command, args []string) error {
	cfg, err := activeDeps.loadConfig()
	if err != nil {
		return fmt.Errorf("failed to read config: %w", err)
	}
	if cfg == nil {
		return fmt.Errorf("device not initialised — run 'credctl init' first")
	}

	// Check gcloud is available
	if _, err := activeDeps.lookPath("gcloud"); err != nil {
		return fmt.Errorf("gcloud CLI not found — install it from https://cloud.google.com/sdk/docs/install")
	}

	// Resolve project
	project := gcpOIDCProject
	if project == "" {
		out, err := activeDeps.execCommand("gcloud", "config", "get-value", "project", "--quiet")
		if err != nil {
			return fmt.Errorf("could not determine GCP project — use --project flag: %w", err)
		}
		project = strings.TrimSpace(string(out))
		if project == "" {
			return fmt.Errorf("no GCP project configured — use --project flag")
		}
	}
	fmt.Fprintf(os.Stderr, "Using GCP project: %s\n", project)

	// Resolve bucket name
	bucket := gcpOIDCBucket
	if bucket == "" {
		bucket = "credctl-oidc-" + project
	}

	issuerURL := "https://storage.googleapis.com/" + bucket

	// Create bucket (ignore error if it already exists)
	fmt.Fprintf(os.Stderr, "Creating GCS bucket '%s'...\n", bucket)
	if err := activeDeps.execCommandRun("gcloud", "storage", "buckets", "create",
		"gs://"+bucket,
		"--project", project,
		"--location", gcpOIDCRegion,
		"--uniform-bucket-level-access",
		"--quiet",
	); err != nil {
		fmt.Fprintln(os.Stderr, "Bucket may already exist, continuing...")
	}

	// Make bucket publicly readable
	fmt.Fprintln(os.Stderr, "Setting public read access...")
	if err := activeDeps.execCommandRun("gcloud", "storage", "buckets", "add-iam-policy-binding",
		"gs://"+bucket,
		"--member", "allUsers",
		"--role", "roles/storage.objectViewer",
		"--project", project,
		"--quiet",
	); err != nil {
		return fmt.Errorf("failed to set public access on bucket: %w", err)
	}

	// Generate OIDC documents
	fmt.Fprintln(os.Stderr, "Generating OIDC documents...")
	oidcIssuerURL = issuerURL
	if err := runOIDCGenerate(cmd, nil); err != nil {
		return fmt.Errorf("oidc generate: %w", err)
	}

	// Upload to GCS
	fmt.Fprintln(os.Stderr, "Uploading OIDC documents to GCS...")
	cfgDir, err := activeDeps.configDir()
	if err != nil {
		return fmt.Errorf("config dir: %w", err)
	}
	oidcDir := filepath.Join(cfgDir, "oidc")

	discoveryPath := filepath.Join(oidcDir, ".well-known", "openid-configuration")
	keysPath := filepath.Join(oidcDir, "keys.json")

	if err := gcsUpload(discoveryPath, bucket, ".well-known/openid-configuration"); err != nil {
		return fmt.Errorf("upload discovery: %w", err)
	}
	if err := gcsUpload(keysPath, bucket, "keys.json"); err != nil {
		return fmt.Errorf("upload JWKS: %w", err)
	}

	// Save config — set issuer URL for both GCP and AWS so either can use it
	if cfg.GCP == nil {
		cfg.GCP = &config.GCPConfig{}
	}
	cfg.GCP.IssuerURL = issuerURL

	if cfg.AWS == nil {
		cfg.AWS = &config.AWSConfig{}
	}
	cfg.AWS.IssuerURL = issuerURL

	if err := activeDeps.saveConfig(cfg); err != nil {
		return fmt.Errorf("save config: %w", err)
	}

	// If GCP WIF provider already exists, update its issuer URL
	if cfg.GCP.ProviderID != "" && cfg.GCP.WorkloadPoolID != "" {
		gcpUpdateProject := project
		fmt.Fprintf(os.Stderr, "Updating WIF provider issuer URL to %s...\n", issuerURL)
		if err := activeDeps.execCommandRun("gcloud", "iam", "workload-identity-pools", "providers",
			"update-oidc", cfg.GCP.ProviderID,
			"--workload-identity-pool", cfg.GCP.WorkloadPoolID,
			"--location", "global",
			"--issuer-uri", issuerURL,
			"--project", gcpUpdateProject,
			"--quiet",
		); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not update WIF provider: %v\n", err)
		}
	}

	fmt.Fprintf(os.Stderr, "\nGCP OIDC setup complete.\n")
	fmt.Fprintf(os.Stderr, "  Issuer URL: %s\n", issuerURL)
	fmt.Fprintf(os.Stderr, "  Bucket:     gs://%s\n", bucket)

	if cfg.GCP.ServiceAccountEmail == "" {
		fmt.Fprintln(os.Stderr, "\nNext steps:")
		fmt.Fprintln(os.Stderr, "  credctl setup gcp --service-account <email>")
	}

	return nil
}

func gcsUpload(localPath, bucket, objectPath string) error {
	dest := fmt.Sprintf("gs://%s/%s", bucket, objectPath)
	out, err := activeDeps.execCommand("gcloud", "storage", "cp",
		localPath, dest,
		"--content-type", "application/json",
		"--quiet",
	)
	if err != nil {
		return fmt.Errorf("%s: %s", err, string(out))
	}
	return nil
}
