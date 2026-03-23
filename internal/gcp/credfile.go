package gcp

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// ExternalCredentialConfig is the JSON structure consumed by GCP client libraries
// via GOOGLE_APPLICATION_CREDENTIALS for executable-sourced credentials.
type ExternalCredentialConfig struct {
	Type                           string           `json:"type"`
	Audience                       string           `json:"audience"`
	SubjectTokenType               string           `json:"subject_token_type"`
	TokenURL                       string           `json:"token_url"`
	ServiceAccountImpersonationURL string           `json:"service_account_impersonation_url"`
	CredentialSource               credentialSource `json:"credential_source"`
}

type credentialSource struct {
	Executable executableConfig `json:"executable"`
}

type executableConfig struct {
	Command       string `json:"command"`
	TimeoutMillis int    `json:"timeout_millis"`
	OutputFile    string `json:"output_file,omitempty"`
}

// GenerateCredentialConfig builds the external credential config JSON structure.
func GenerateCredentialConfig(credctlPath, audience, serviceAccountEmail string) *ExternalCredentialConfig {
	return GenerateCredentialConfigWithOutput(credctlPath, audience, serviceAccountEmail, "")
}

// GenerateCredentialConfigWithOutput builds the external credential config with an optional output file path.
// GCP client libraries use the output file to cache the executable response, avoiding repeated invocations.
func GenerateCredentialConfigWithOutput(credctlPath, audience, serviceAccountEmail, outputFile string) *ExternalCredentialConfig {
	return &ExternalCredentialConfig{ // #nosec G101 -- not hardcoded credentials, this is a config template
		Type:             "external_account",
		Audience:         audience,
		SubjectTokenType: "urn:ietf:params:oauth:token-type:jwt",
		TokenURL:         "https://sts.googleapis.com/v1/token",
		ServiceAccountImpersonationURL: fmt.Sprintf(
			"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateAccessToken",
			serviceAccountEmail,
		),
		CredentialSource: credentialSource{
			Executable: executableConfig{
				Command:       credctlPath + " auth --provider gcp --format executable",
				TimeoutMillis: 30000,
				OutputFile:    outputFile,
			},
		},
	}
}

// WriteCredentialConfig writes the external credential config to a file.
func WriteCredentialConfig(path string, cfg *ExternalCredentialConfig) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal credential config: %w", err)
	}

	return os.WriteFile(path, data, 0600)
}
