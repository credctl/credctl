package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	DefaultKeyTag = "com.crzy.credctl.device-key"
	configDir     = ".credctl"
	configFile    = "config.json"
	pubKeyFile    = "device.pub"
)

// AWSConfig holds optional AWS authentication settings.
type AWSConfig struct {
	RoleARN   string `json:"role_arn"`
	IssuerURL string `json:"issuer_url"`
	Region    string `json:"region,omitempty"`
	S3Bucket  string `json:"s3_bucket,omitempty"`
}

// Config represents the persisted device identity configuration.
type Config struct {
	Version       int        `json:"version"`
	DeviceID      string     `json:"device_id"`
	KeyTag        string     `json:"key_tag"`
	CreatedAt     time.Time  `json:"created_at"`
	EnclaveType   string     `json:"enclave_type"`
	PublicKeyPath string     `json:"public_key_path"`
	AWS           *AWSConfig `json:"aws,omitempty"`
}

// ConfigDir returns the path to ~/.credctl.
func ConfigDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, configDir), nil
}

// ConfigPath returns the path to ~/.credctl/config.json.
func ConfigPath() (string, error) {
	dir, err := ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, configFile), nil
}

// PublicKeyPath returns the path to ~/.credctl/device.pub.
func PublicKeyPath() (string, error) {
	dir, err := ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, pubKeyFile), nil
}

// Load reads the config from ~/.credctl/config.json.
// Returns nil, nil if the file does not exist.
func Load() (*Config, error) {
	path, err := ConfigPath()
	if err != nil {
		return nil, err
	}

	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}

	// Warn if config file is readable by group or others
	if perm := info.Mode().Perm(); perm&0077 != 0 {
		fmt.Fprintf(os.Stderr, "Warning: %s has permissions %o, expected 0600 — run: chmod 600 %s\n", path, perm, path)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Save writes the config to ~/.credctl/config.json, creating the directory if needed.
func Save(cfg *Config) error {
	dir, err := ConfigDir()
	if err != nil {
		return err
	}

	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	path := filepath.Join(dir, configFile)
	return os.WriteFile(path, data, 0600)
}
