package cli

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/credctl/credctl/internal/config"
	"github.com/credctl/credctl/internal/daemon"
	"github.com/credctl/credctl/internal/jwt"
	"github.com/spf13/cobra"
)

var (
	authFormat   string
	authProvider string
)

var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "Get temporary cloud credentials using Secure Enclave identity",
	Long: `Authenticates to a cloud provider by signing a JWT with the Secure Enclave key
and exchanging it for temporary credentials.

AWS — use as a credential_process:
  [profile credctl]
  credential_process = credctl auth

GCP — use with executable-sourced credentials:
  credctl auth --provider gcp --format executable`,
	RunE: runAuth,
}

func init() {
	authCmd.Flags().StringVar(&authFormat, "format", "", "Output format (aws: credential_process|env, gcp: executable|env)")
	authCmd.Flags().StringVar(&authProvider, "provider", "aws", "Cloud provider: aws or gcp")
	rootCmd.AddCommand(authCmd)
}

func runAuth(cmd *cobra.Command, args []string) error {
	cfg, err := activeDeps.loadConfig()
	if err != nil {
		return fmt.Errorf("failed to read config: %w", err)
	}
	if cfg == nil {
		return fmt.Errorf("device not initialised — run 'credctl init' first")
	}

	switch authProvider {
	case "aws":
		return runAuthAWS(cfg)
	case "gcp":
		return runAuthGCP(cfg)
	default:
		return fmt.Errorf("unknown provider: %s (use 'aws' or 'gcp')", authProvider)
	}
}

// credentialProcessOutput matches the AWS credential_process JSON schema.
type credentialProcessOutput struct {
	Version         int    `json:"Version"`
	AccessKeyID     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	SessionToken    string `json:"SessionToken"`
	Expiration      string `json:"Expiration"`
}

func runAuthAWS(cfg *config.Config) error {
	if cfg.AWS == nil {
		return fmt.Errorf("AWS not configured — run 'credctl setup aws' or configure manually")
	}

	format := authFormat
	if format == "" {
		format = "credential_process"
	}

	// Try the daemon first — if running, fetch cached credentials.
	if data, err := tryDaemon("aws", format); err == nil {
		fmt.Print(string(data))
		return nil
	}

	kid, signFn, err := prepareSign(cfg)
	if err != nil {
		return err
	}

	fmt.Fprintln(os.Stderr, "Signing JWT with Secure Enclave...")
	token, err := jwt.BuildAndSign(kid, cfg.AWS.IssuerURL, cfg.DeviceID, "sts.amazonaws.com", signFn)
	if err != nil {
		return fmt.Errorf("build JWT: %w", err)
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "JWT KID:    %s\n", kid)
		fmt.Fprintf(os.Stderr, "JWT issuer: %s\n", cfg.AWS.IssuerURL)
		fmt.Fprintf(os.Stderr, "JWT sub:    %s\n", cfg.DeviceID)
		fmt.Fprintf(os.Stderr, "JWT aud:    sts.amazonaws.com\n")
		fmt.Fprintf(os.Stderr, "JWT token:  %s\n", token)

		// Self-verify: check JWT signature against device.pub
		pubKeyPath, _ := activeDeps.publicKeyPath()
		pubKeyPEM, _ := os.ReadFile(pubKeyPath)
		if verifyErr := jwt.VerifyToken(token, pubKeyPEM); verifyErr != nil {
			fmt.Fprintf(os.Stderr, "WARNING: JWT self-verification FAILED: %v\n", verifyErr)
			fmt.Fprintln(os.Stderr, "The Secure Enclave may be signing with a different key than device.pub")
		} else {
			fmt.Fprintln(os.Stderr, "JWT self-verification: OK")
		}
	}

	// Call STS — session name must match [\w+=,.@-]*
	fingerprint := strings.TrimPrefix(cfg.DeviceID, "SHA256:")
	randBytes := make([]byte, 4)
	_, _ = rand.Read(randBytes)
	sessionName := "credctl-" + fingerprint[:8] + "-" + hex.EncodeToString(randBytes)
	fmt.Fprintln(os.Stderr, "Requesting temporary credentials from AWS STS...")
	creds, err := activeDeps.assumeRole(cfg.AWS.RoleARN, sessionName, token, cfg.AWS.Region)
	if err != nil {
		return fmt.Errorf("assume role: %w", err)
	}

	switch format {
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
		return fmt.Errorf("unknown format: %s (use 'credential_process' or 'env')", format)
	}

	fmt.Fprintln(os.Stderr, "Credentials valid until", creds.Expiration.Format(time.RFC3339))
	return nil
}

// executableOutput matches the GCP executable-sourced credentials JSON schema.
type executableOutput struct {
	Version          int    `json:"version"`
	Success          bool   `json:"success"`
	TokenType        string `json:"token_type"`
	ExpirationTime   int64  `json:"expiration_time"`
	SubjectToken     string `json:"subject_token"`
}

func runAuthGCP(cfg *config.Config) error {
	if cfg.GCP == nil {
		return fmt.Errorf("GCP not configured — run 'credctl setup gcp' or configure manually")
	}

	format := authFormat
	if format == "" {
		format = "executable"
	}

	// Try the daemon first — if running, fetch cached credentials.
	if data, err := tryDaemon("gcp", format); err == nil {
		fmt.Print(string(data))
		return nil
	}

	kid, signFn, err := prepareSign(cfg)
	if err != nil {
		return err
	}

	audience := cfg.GCP.Audience()

	fmt.Fprintln(os.Stderr, "Signing JWT with Secure Enclave...")
	token, err := jwt.BuildAndSign(kid, cfg.GCP.IssuerURL, cfg.DeviceID, audience, signFn)
	if err != nil {
		return fmt.Errorf("build JWT: %w", err)
	}

	switch format {
	case "executable":
		// Output the signed JWT in GCP executable credential format.
		// The GCP client library handles the STS exchange itself.
		out := executableOutput{ // #nosec G101 -- not hardcoded credentials, this is the output structure
			Version:        1,
			Success:        true,
			TokenType:      "urn:ietf:params:oauth:token-type:jwt",
			ExpirationTime: time.Now().Add(5 * time.Minute).Unix(),
			SubjectToken:   token,
		}
		data, err := json.Marshal(out)
		if err != nil {
			return fmt.Errorf("marshal executable output: %w", err)
		}
		fmt.Println(string(data))

	case "env":
		// For env format, do the full exchange to get an access token
		fmt.Fprintln(os.Stderr, "Exchanging JWT for GCP federated token...")
		fedToken, err := activeDeps.gcpExchangeToken(audience, token)
		if err != nil {
			return fmt.Errorf("token exchange: %w", err)
		}

		fmt.Fprintln(os.Stderr, "Generating service account access token...")
		accessToken, err := activeDeps.gcpGenerateAccessToken(
			cfg.GCP.ServiceAccountEmail,
			fedToken.AccessToken,
			[]string{"https://www.googleapis.com/auth/cloud-platform"},
		)
		if err != nil {
			return fmt.Errorf("generate access token: %w", err)
		}

		fmt.Printf("export CLOUDSDK_AUTH_ACCESS_TOKEN=%s\n", accessToken.Token)
		fmt.Fprintln(os.Stderr, "Credentials valid until", accessToken.ExpireTime.Format(time.RFC3339))

	default:
		return fmt.Errorf("unknown format: %s (use 'executable' or 'env')", format)
	}

	return nil
}

// tryDaemon attempts to fetch credentials from the running daemon.
// Returns the raw JSON data on success, or an error if the daemon is not running
// or the fetch fails (in which case the caller should fall back to the direct path).
func tryDaemon(provider, format string) ([]byte, error) {
	cfgDir, err := activeDeps.configDir()
	if err != nil {
		return nil, err
	}
	socketPath := daemon.SocketPath(cfgDir)
	if !daemon.DaemonRunning(socketPath) {
		return nil, fmt.Errorf("daemon not running")
	}
	data, err := daemon.FetchCredentials(socketPath, provider, format)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Daemon fetch failed, falling back to direct auth: %v\n", err)
		return nil, err
	}
	return data, nil
}

// prepareSign loads the public key and returns the KID and signing function.
func prepareSign(cfg *config.Config) (string, jwt.SigningFunc, error) {
	pubKeyPath, err := activeDeps.publicKeyPath()
	if err != nil {
		return "", nil, fmt.Errorf("public key path: %w", err)
	}
	pubKeyPEM, err := os.ReadFile(pubKeyPath)
	if err != nil {
		return "", nil, fmt.Errorf("read public key: %w", err)
	}

	kid, err := jwt.KIDFromPublicKeyPEM(pubKeyPEM)
	if err != nil {
		return "", nil, fmt.Errorf("derive key ID: %w", err)
	}

	enc := activeDeps.newEnclave()
	signFn := func(data []byte) ([]byte, error) {
		return enc.Sign(cfg.KeyTag, data)
	}

	return kid, signFn, nil
}
