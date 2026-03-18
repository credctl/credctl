package cli

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/credctl/credctl/internal/aws"
	"github.com/credctl/credctl/internal/config"
	"github.com/credctl/credctl/internal/enclave"
	"github.com/credctl/credctl/internal/gcp"
	"github.com/spf13/cobra"
)

// deps holds injectable dependencies for testability.
type deps struct {
	newEnclave    func() enclave.Enclave
	loadConfig    func() (*config.Config, error)
	saveConfig    func(*config.Config) error
	configDir     func() (string, error)
	publicKeyPath func() (string, error)
	assumeRole             func(string, string, string, string) (*aws.Credentials, error)
	lookPath               func(string) (string, error)
	gcpExchangeToken       func(string, string) (*gcp.FederatedToken, error)
	gcpGenerateAccessToken func(string, string, []string) (*gcp.AccessToken, error)
	// execCommand runs an external command and returns its combined output.
	// Used by setup commands that shell out to aws/gcloud CLIs.
	execCommand func(name string, args ...string) ([]byte, error)
	// execCommandRun runs an external command with stdout/stderr connected to os.Stderr.
	execCommandRun func(name string, args ...string) error
}

// defaultExecCommand runs a command and returns combined output.
func defaultExecCommand(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).Output() //nolint:gosec // callers validate inputs
}

// defaultExecCommandRun runs a command with output to stderr.
func defaultExecCommandRun(name string, args ...string) error {
	cmd := exec.Command(name, args...) //nolint:gosec // callers validate inputs
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

var activeDeps = deps{
	newEnclave:             func() enclave.Enclave { return enclave.New() },
	loadConfig:             config.Load,
	saveConfig:             config.Save,
	configDir:              config.ConfigDir,
	publicKeyPath:          config.PublicKeyPath,
	assumeRole:             aws.AssumeRoleWithWebIdentity,
	lookPath:               exec.LookPath,
	gcpExchangeToken:       gcp.ExchangeToken,
	gcpGenerateAccessToken: gcp.GenerateAccessToken,
	execCommand:            defaultExecCommand,
	execCommandRun:         defaultExecCommandRun,
}

var rootCmd = &cobra.Command{
	Use:           "credctl",
	Short:         "Manage credentials with machine identity",
	Long:          "credctl uses the macOS Secure Enclave to create hardware-bound device identities for credential management.",
	SilenceUsage:  true,
	SilenceErrors: true,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
