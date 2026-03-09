package cli

import (
	"fmt"
	"os"

	"github.com/credctl/credctl/internal/aws"
	"github.com/credctl/credctl/internal/config"
	"github.com/credctl/credctl/internal/enclave"
	"github.com/spf13/cobra"
)

// deps holds injectable dependencies for testability.
type deps struct {
	newEnclave    func() enclave.Enclave
	loadConfig    func() (*config.Config, error)
	saveConfig    func(*config.Config) error
	configDir     func() (string, error)
	publicKeyPath func() (string, error)
	assumeRole    func(string, string, string, string) (*aws.Credentials, error)
}

var activeDeps = deps{
	newEnclave:    func() enclave.Enclave { return enclave.New() },
	loadConfig:    config.Load,
	saveConfig:    config.Save,
	configDir:     config.ConfigDir,
	publicKeyPath: config.PublicKeyPath,
	assumeRole:    aws.AssumeRoleWithWebIdentity,
}

var rootCmd = &cobra.Command{
	Use:           "credctl",
	Short:         "Manage credentials with machine identity",
	Long:          "credctl uses hardware security modules (macOS Secure Enclave, Linux TPM 2.0) to create hardware-bound device identities for credential management.",
	SilenceUsage:  true,
	SilenceErrors: true,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
