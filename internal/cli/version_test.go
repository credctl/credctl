package cli

import "testing"

func TestVersionVars(t *testing.T) {
	if Version != "dev" {
		t.Errorf("Version = %q, want 'dev'", Version)
	}
	if Commit != "none" {
		t.Errorf("Commit = %q, want 'none'", Commit)
	}
}
