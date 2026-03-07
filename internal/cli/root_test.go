package cli

import "testing"

func TestRootCommand_Subcommands(t *testing.T) {
	names := make(map[string]bool)
	for _, cmd := range rootCmd.Commands() {
		names[cmd.Name()] = true
	}

	want := []string{"init", "status", "auth", "version", "setup", "oidc"}
	for _, name := range want {
		if !names[name] {
			t.Errorf("subcommand %q not registered", name)
		}
	}
}
