package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/credctl/credctl/internal/config"
	"github.com/spf13/cobra"
)

var (
	gcpProject        string
	gcpPoolID         string
	gcpProviderID     string
	gcpServiceAccount string
	gcpIssuerURL      string
	gcpBucket         string
	gcpBucketRegion   string
)

var setupGCPCmd = &cobra.Command{
	Use:   "gcp",
	Short: "Set up GCP infrastructure for credctl",
	Long: `Creates all GCP infrastructure needed for credctl Workload Identity Federation:

1. OIDC hosting — creates a GCS bucket and uploads discovery documents
   (or reuses an existing OIDC endpoint if one is already configured)
2. Workload Identity Pool and OIDC Provider
3. Service account IAM binding
4. Credential configuration file for GCP client libraries

If you previously set up AWS, the existing OIDC endpoint is reused automatically.

Requires the gcloud CLI to be installed and authenticated.`,
	RunE: runSetupGCP,
}

func init() {
	setupGCPCmd.Flags().StringVar(&gcpServiceAccount, "service-account", "", "Service account email to impersonate")
	setupGCPCmd.Flags().StringVar(&gcpProject, "project", "", "GCP project ID (defaults to gcloud config)")
	setupGCPCmd.Flags().StringVar(&gcpBucket, "bucket", "", "GCS bucket name for OIDC hosting (default: credctl-oidc-{project})")
	setupGCPCmd.Flags().StringVar(&gcpBucketRegion, "region", "us-central1", "GCS bucket location")
	setupGCPCmd.Flags().StringVar(&gcpPoolID, "pool-id", "credctl-pool", "Workload Identity Pool ID")
	setupGCPCmd.Flags().StringVar(&gcpProviderID, "provider-id", "credctl-provider", "Workload Identity Provider ID")
	setupGCPCmd.Flags().StringVar(&gcpIssuerURL, "issuer-url", "", "Use an existing OIDC issuer URL (advanced)")
	_ = setupGCPCmd.MarkFlagRequired("service-account")
	_ = setupGCPCmd.Flags().MarkHidden("issuer-url")
	_ = setupGCPCmd.Flags().MarkHidden("pool-id")
	_ = setupGCPCmd.Flags().MarkHidden("provider-id")

	setupCmd.AddCommand(setupGCPCmd)
}

func runSetupGCP(cmd *cobra.Command, args []string) error {
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
	project := gcpProject
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

	// Get project number
	projectNumber, err := getProjectNumber(project)
	if err != nil {
		return fmt.Errorf("get project number: %w", err)
	}

	// Step 1: Resolve issuer URL
	issuerURL := resolveGCPIssuerURL(cfg)

	// Step 2: If no issuer URL exists, create GCS OIDC hosting
	if issuerURL == "" {
		var err error
		issuerURL, err = createGCSOIDCBucket(cfg, project)
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
		// Re-publish if we own a GCS bucket
		if strings.Contains(issuerURL, "storage.googleapis.com/") {
			bucket := strings.TrimPrefix(issuerURL, "https://storage.googleapis.com/")
			cfgDir, _ := activeDeps.configDir()
			oidcDir := filepath.Join(cfgDir, "oidc")
			_ = gcsUpload(filepath.Join(oidcDir, ".well-known", "openid-configuration"), bucket, ".well-known/openid-configuration")
			_ = gcsUpload(filepath.Join(oidcDir, "keys.json"), bucket, "keys.json")
		}
	}

	// Step 3: Create WIF resources
	fmt.Fprintf(os.Stderr, "Creating Workload Identity Pool '%s'...\n", gcpPoolID)
	if err := activeDeps.execCommandRun("gcloud", "iam", "workload-identity-pools", "create", gcpPoolID,
		"--project", project,
		"--location", "global",
		"--display-name", "credctl Device Identity Pool",
		"--quiet",
	); err != nil {
		fmt.Fprintln(os.Stderr, "Pool may already exist, continuing...")
	}

	// Create or update OIDC Provider
	audience := fmt.Sprintf("//iam.googleapis.com/projects/%s/locations/global/workloadIdentityPools/%s/providers/%s",
		projectNumber, gcpPoolID, gcpProviderID)

	fmt.Fprintf(os.Stderr, "Creating OIDC Provider '%s'...\n", gcpProviderID)
	if err := activeDeps.execCommandRun("gcloud", "iam", "workload-identity-pools", "providers", "create-oidc", gcpProviderID,
		"--project", project,
		"--location", "global",
		"--workload-identity-pool", gcpPoolID,
		"--issuer-uri", issuerURL,
		"--attribute-mapping", "google.subject=assertion.sub",
		"--allowed-audiences", audience,
		"--quiet",
	); err != nil {
		// Provider exists — update it (issuer URL may have changed)
		fmt.Fprintln(os.Stderr, "Provider exists, updating issuer URL...")
		_ = activeDeps.execCommandRun("gcloud", "iam", "workload-identity-pools", "providers",
			"update-oidc", gcpProviderID,
			"--workload-identity-pool", gcpPoolID,
			"--location", "global",
			"--issuer-uri", issuerURL,
			"--project", project,
			"--quiet",
		)
	}

	// Bind service account
	member := fmt.Sprintf("principal://iam.googleapis.com/projects/%s/locations/global/workloadIdentityPools/%s/subject/%s",
		projectNumber, gcpPoolID, cfg.DeviceID)

	fmt.Fprintf(os.Stderr, "Binding service account '%s'...\n", gcpServiceAccount)
	if err := activeDeps.execCommandRun("gcloud", "iam", "service-accounts", "add-iam-policy-binding", gcpServiceAccount,
		"--project", project,
		"--role", "roles/iam.workloadIdentityUser",
		"--member", member,
		"--quiet",
	); err != nil {
		return fmt.Errorf("bind service account: %w", err)
	}

	// Step 4: Save config
	if cfg.GCP == nil {
		cfg.GCP = &config.GCPConfig{}
	}
	cfg.GCP.ProjectNumber = projectNumber
	cfg.GCP.WorkloadPoolID = gcpPoolID
	cfg.GCP.ProviderID = gcpProviderID
	cfg.GCP.ServiceAccountEmail = gcpServiceAccount
	cfg.GCP.IssuerURL = issuerURL
	if err := activeDeps.saveConfig(cfg); err != nil {
		return fmt.Errorf("save config: %w", err)
	}

	// Step 5: Auto-generate credential file
	fmt.Fprintln(os.Stderr, "\nGenerating GCP credential file...")
	gcpCredFileOutput = "" // use default path
	if err := runSetupGCPCredFile(cmd, nil); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not generate credential file: %v\n", err)
	}

	fmt.Fprintf(os.Stderr, "\nGCP setup complete.\n")
	fmt.Fprintf(os.Stderr, "  Issuer URL:       %s\n", issuerURL)
	fmt.Fprintf(os.Stderr, "  Service account:  %s\n", gcpServiceAccount)
	fmt.Fprintf(os.Stderr, "\nTest it:\n")
	fmt.Fprintf(os.Stderr, "  credctl auth --provider gcp\n")

	return nil
}

// resolveGCPIssuerURL returns an existing issuer URL from config or flags.
func resolveGCPIssuerURL(cfg *config.Config) string {
	if gcpIssuerURL != "" {
		return gcpIssuerURL
	}
	if cfg.GCP != nil && cfg.GCP.IssuerURL != "" {
		return cfg.GCP.IssuerURL
	}
	if cfg.AWS != nil && cfg.AWS.IssuerURL != "" {
		return cfg.AWS.IssuerURL
	}
	return ""
}

// createGCSOIDCBucket creates a public GCS bucket and uploads OIDC documents.
func createGCSOIDCBucket(cfg *config.Config, project string) (string, error) {
	bucket := gcpBucket
	if bucket == "" {
		bucket = "credctl-oidc-" + project
	}

	issuerURL := "https://storage.googleapis.com/" + bucket

	fmt.Fprintf(os.Stderr, "Creating GCS bucket '%s'...\n", bucket)
	if err := activeDeps.execCommandRun("gcloud", "storage", "buckets", "create",
		"gs://"+bucket,
		"--project", project,
		"--location", gcpBucketRegion,
		"--uniform-bucket-level-access",
		"--quiet",
	); err != nil {
		fmt.Fprintln(os.Stderr, "Bucket may already exist, continuing...")
	}

	fmt.Fprintln(os.Stderr, "Setting public read access...")
	if err := activeDeps.execCommandRun("gcloud", "storage", "buckets", "add-iam-policy-binding",
		"gs://"+bucket,
		"--member", "allUsers",
		"--role", "roles/storage.objectViewer",
		"--project", project,
		"--quiet",
	); err != nil {
		return "", fmt.Errorf("failed to set public access on bucket: %w", err)
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
	if err := gcsUpload(filepath.Join(oidcDir, ".well-known", "openid-configuration"), bucket, ".well-known/openid-configuration"); err != nil {
		return "", fmt.Errorf("upload discovery: %w", err)
	}
	if err := gcsUpload(filepath.Join(oidcDir, "keys.json"), bucket, "keys.json"); err != nil {
		return "", fmt.Errorf("upload JWKS: %w", err)
	}

	return issuerURL, nil
}

func getProjectNumber(project string) (string, error) {
	type projectInfo struct {
		ProjectNumber string `json:"projectNumber"`
	}

	out, err := activeDeps.execCommand("gcloud", "projects", "describe", project,
		"--format", "json(projectNumber)",
		"--quiet",
	)
	if err != nil {
		return "", fmt.Errorf("describe project: %w", err)
	}

	var info projectInfo
	if err := json.Unmarshal(out, &info); err != nil {
		return "", fmt.Errorf("parse project info: %w", err)
	}

	return info.ProjectNumber, nil
}
