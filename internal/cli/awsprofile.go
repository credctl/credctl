package cli

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

var (
	awsProfileName  string
	awsProfileForce bool
)

var setupAWSProfileCmd = &cobra.Command{
	Use:   "aws-profile",
	Short: "Configure an AWS CLI profile to use credctl for credentials",
	Long: `Adds a credential_process entry to ~/.aws/config so the AWS CLI
uses credctl to obtain temporary credentials automatically.

Example:
  credctl setup aws-profile
  credctl setup aws-profile --profile default
  credctl setup aws-profile --profile myproject --force`,
	RunE: runSetupAWSProfile,
}

func init() {
	setupAWSProfileCmd.Flags().StringVar(&awsProfileName, "profile", "credctl", "AWS CLI profile name")
	setupAWSProfileCmd.Flags().BoolVar(&awsProfileForce, "force", false, "Overwrite existing profile")
	setupCmd.AddCommand(setupAWSProfileCmd)
}

func runSetupAWSProfile(cmd *cobra.Command, args []string) error {
	// Verify credctl is initialised and AWS is configured
	cfg, err := activeDeps.loadConfig()
	if err != nil {
		return fmt.Errorf("failed to read config: %w", err)
	}
	if cfg == nil {
		return fmt.Errorf("device not initialised — run 'credctl init' first")
	}
	if cfg.AWS == nil {
		return fmt.Errorf("AWS not configured — run 'credctl setup aws' first")
	}

	// Resolve credctl binary path
	credctlPath, err := exec.LookPath("credctl")
	if err != nil {
		return fmt.Errorf("credctl not found in PATH: %w", err)
	}

	// Determine region
	region := cfg.AWS.Region

	// Build the AWS config file path
	awsConfigPath, err := awsConfigFilePath()
	if err != nil {
		return err
	}

	// Parse existing config
	sections, err := parseAWSConfig(awsConfigPath)
	if err != nil {
		return err
	}

	// Check for existing profile
	sectionHeader := profileSectionHeader(awsProfileName)
	if _, exists := sections[sectionHeader]; exists && !awsProfileForce {
		return fmt.Errorf("profile '%s' already exists in %s — use --force to overwrite", awsProfileName, awsConfigPath)
	}

	// Build profile settings
	settings := []keyValue{
		{key: "credential_process", value: credctlPath + " auth"},
	}
	if region != "" {
		settings = append(settings, keyValue{key: "region", value: region})
	}

	// Write the profile
	sections[sectionHeader] = settings
	if err := writeAWSConfig(awsConfigPath, sections); err != nil {
		return fmt.Errorf("write AWS config: %w", err)
	}

	fmt.Printf("Configured profile '%s' in %s\n", awsProfileName, awsConfigPath)
	if awsProfileName == "default" {
		fmt.Println("  aws sts get-caller-identity")
	} else {
		fmt.Printf("  AWS_PROFILE=%s aws sts get-caller-identity\n", awsProfileName)
	}

	return nil
}

// awsConfigFilePath returns the path to ~/.aws/config, respecting AWS_CONFIG_FILE.
func awsConfigFilePath() (string, error) {
	if p := os.Getenv("AWS_CONFIG_FILE"); p != "" {
		return p, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("home directory: %w", err)
	}
	return filepath.Join(home, ".aws", "config"), nil
}

// profileSectionHeader returns the INI section header for a profile name.
func profileSectionHeader(name string) string {
	if name == "default" {
		return "[default]"
	}
	return "[profile " + name + "]"
}

// keyValue represents a single key = value line in an INI section.
type keyValue struct {
	key   string
	value string
}

// parseAWSConfig reads an AWS config file into an ordered map of sections.
// Returns an empty map if the file doesn't exist.
func parseAWSConfig(path string) (map[string][]keyValue, error) {
	sections := make(map[string][]keyValue)

	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return sections, nil
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	defer f.Close()

	var currentSection string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			currentSection = trimmed
			if _, exists := sections[currentSection]; !exists {
				sections[currentSection] = nil
			}
			continue
		}

		if currentSection != "" {
			if idx := strings.IndexByte(trimmed, '='); idx > 0 {
				k := strings.TrimSpace(trimmed[:idx])
				v := strings.TrimSpace(trimmed[idx+1:])
				sections[currentSection] = append(sections[currentSection], keyValue{key: k, value: v})
			}
		}
	}

	return sections, scanner.Err()
}

// sectionOrder returns a stable ordering of section keys, preserving insertion order
// for existing sections read from the file.
func sectionOrder(path string, sections map[string][]keyValue) []string {
	// Re-read the file to get original section order
	var order []string
	seen := make(map[string]bool)

	f, err := os.Open(path)
	if err == nil {
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			trimmed := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
				if !seen[trimmed] {
					order = append(order, trimmed)
					seen[trimmed] = true
				}
			}
		}
	}

	// Append any new sections not in the file
	for header := range sections {
		if !seen[header] {
			order = append(order, header)
			seen[header] = true
		}
	}

	return order
}

// writeAWSConfig writes sections back to the AWS config file.
func writeAWSConfig(path string, sections map[string][]keyValue) error {
	// Ensure parent directory exists
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}

	order := sectionOrder(path, sections)

	var b strings.Builder
	for i, header := range order {
		kvs, ok := sections[header]
		if !ok {
			continue
		}
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(header)
		b.WriteByte('\n')
		for _, kv := range kvs {
			b.WriteString(kv.key)
			b.WriteString(" = ")
			b.WriteString(kv.value)
			b.WriteByte('\n')
		}
	}

	return os.WriteFile(path, []byte(b.String()), 0600)
}
