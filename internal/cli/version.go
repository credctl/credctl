package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// Set via ldflags at build time:
//
//	go build -ldflags "-X github.com/matzhouse/credctl/internal/cli.Version=v0.1.0 -X github.com/matzhouse/credctl/internal/cli.Commit=abc123"
var (
	Version = "dev"
	Commit  = "none"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("credctl %s (commit: %s)\n", Version, Commit)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
