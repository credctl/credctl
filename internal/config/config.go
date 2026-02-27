package config

import (
	"encoding/json"
	"errors"
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

// Config represents the persisted device identity configuration.
type Config struct {
	Version       int       `json:"version"`
	DeviceID      string    `json:"device_id"`
	KeyTag        string    `json:"key_tag"`
	CreatedAt     time.Time `json:"created_at"`
	EnclaveType   string    `json:"enclave_type"`
	PublicKeyPath string    `json:"public_key_path"`
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

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
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
