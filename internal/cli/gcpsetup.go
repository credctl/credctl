package cli

import (
	"encoding/json"
	"fmt"
	"os"
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
)

var setupGCPCmd = &cobra.Command{
	Use:   "gcp",
	Short: "Create GCP infrastructure for credctl Workload Identity Federation",
	Long: `Creates a Workload Identity Pool, OIDC Provider, and service account binding
using the gcloud CLI. Requires gcloud to be installed and authenticated.`,
	RunE: runSetupGCP,
}

func init() {
	setupGCPCmd.Flags().StringVar(&gcpProject, "project", "", "GCP project ID (defaults to gcloud config)")
	setupGCPCmd.Flags().StringVar(&gcpPoolID, "pool-id", "credctl-pool", "Workload Identity Pool ID")
	setupGCPCmd.Flags().StringVar(&gcpProviderID, "provider-id", "credctl-provider", "Workload Identity Provider ID")
	setupGCPCmd.Flags().StringVar(&gcpServiceAccount, "service-account", "", "Service account email to impersonate")
	setupGCPCmd.Flags().StringVar(&gcpIssuerURL, "issuer-url", "", "OIDC issuer URL (defaults to AWS issuer if configured)")
	_ = setupGCPCmd.MarkFlagRequired("service-account")

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

	// Resolve issuer URL
	issuerURL := gcpIssuerURL
	if issuerURL == "" && cfg.AWS != nil {
		issuerURL = cfg.AWS.IssuerURL
	}
	if issuerURL == "" {
		return fmt.Errorf("no issuer URL — use --issuer-url flag or set up AWS first")
	}

	// Create Workload Identity Pool
	fmt.Fprintf(os.Stderr, "Creating Workload Identity Pool '%s'...\n", gcpPoolID)
	if err := activeDeps.execCommandRun("gcloud", "iam", "workload-identity-pools", "create", gcpPoolID,
		"--project", project,
		"--location", "global",
		"--display-name", "credctl Device Identity Pool",
		"--quiet",
	); err != nil {
		// Pool may already exist, try to continue
		fmt.Fprintln(os.Stderr, "Pool may already exist, continuing...")
	}

	// Create OIDC Provider
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
		fmt.Fprintln(os.Stderr, "Provider may already exist, continuing...")
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

	// Save config
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

	fmt.Fprintln(os.Stderr, "\nGCP setup complete. Configure credentials:")
	fmt.Fprintln(os.Stderr, "  credctl setup gcp-cred-file")

	return nil
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
