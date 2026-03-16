package cli

import (
	"fmt"
	"testing"
	"time"

	"github.com/credctl/credctl/internal/aws"
	"github.com/credctl/credctl/internal/config"
	"github.com/credctl/credctl/internal/enclave"
	"github.com/credctl/credctl/internal/gcp"
)

// mockEnclave implements enclave.Enclave for testing.
type mockEnclave struct {
	available    bool
	generateKey  func(tag string, biometric enclave.BiometricPolicy) (*enclave.DeviceKey, error)
	loadKey      func(tag string) (*enclave.DeviceKey, error)
	deleteKey    func(tag string) error
	sign         func(tag string, data []byte) ([]byte, error)
}

func (m *mockEnclave) Available() bool { return m.available }

func (m *mockEnclave) GenerateKey(tag string, biometric enclave.BiometricPolicy) (*enclave.DeviceKey, error) {
	if m.generateKey != nil {
		return m.generateKey(tag, biometric)
	}
	return &enclave.DeviceKey{
		Fingerprint: "SHA256:testfp123456",
		PublicKey:   []byte("-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----\n"),
		Tag:         tag,
		CreatedAt:   time.Now(),
		Biometric:   biometric,
	}, nil
}

func (m *mockEnclave) LoadKey(tag string) (*enclave.DeviceKey, error) {
	if m.loadKey != nil {
		return m.loadKey(tag)
	}
	return &enclave.DeviceKey{
		Fingerprint: "SHA256:testfp123456",
		PublicKey:   []byte("-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----\n"),
		Tag:         tag,
	}, nil
}

func (m *mockEnclave) DeleteKey(tag string) error {
	if m.deleteKey != nil {
		return m.deleteKey(tag)
	}
	return nil
}

func (m *mockEnclave) Sign(tag string, data []byte) ([]byte, error) {
	if m.sign != nil {
		return m.sign(tag, data)
	}
	return []byte("mock-signature"), nil
}

// withDeps replaces activeDeps for the duration of the test and restores it on cleanup.
func withDeps(t *testing.T, d deps) {
	t.Helper()
	orig := activeDeps
	activeDeps = d
	t.Cleanup(func() { activeDeps = orig })
}

// testDeps returns a deps struct with sensible defaults for testing.
func testDeps(enc enclave.Enclave) deps {
	tmpDir := ""
	return deps{
		newEnclave: func() enclave.Enclave { return enc },
		loadConfig: func() (*config.Config, error) { return nil, nil },
		saveConfig: func(cfg *config.Config) error { return nil },
		configDir: func() (string, error) {
			if tmpDir == "" {
				return "/tmp/credctl-test", nil
			}
			return tmpDir, nil
		},
		publicKeyPath: func() (string, error) { return "/tmp/credctl-test/device.pub", nil },
		assumeRole: func(roleARN, sessionName, token, region string) (*aws.Credentials, error) {
			return &aws.Credentials{
				AccessKeyID:    "AKIATEST",
				SecretAccessKey: "secret",
				SessionToken:   "token",
				Expiration:     time.Now().Add(1 * time.Hour),
			}, nil
		},
		lookPath: func(name string) (string, error) { return "/usr/local/bin/" + name, nil },
		gcpExchangeToken: func(audience, subjectToken string) (*gcp.FederatedToken, error) {
			return &gcp.FederatedToken{
				AccessToken: "federated-token",
				ExpiresIn:   3600,
				TokenType:   "Bearer",
			}, nil
		},
		gcpGenerateAccessToken: func(sa, token string, scopes []string) (*gcp.AccessToken, error) {
			return &gcp.AccessToken{
				Token:      "ya29.test-access-token",
				ExpireTime: time.Now().Add(1 * time.Hour),
			}, nil
		},
	}
}

// testConfig returns a Config suitable for testing.
func testConfig() *config.Config {
	return &config.Config{
		Version:       1,
		DeviceID:      "SHA256:testfp12345678",
		KeyTag:        "com.crzy.credctl.test-key",
		CreatedAt:     time.Now(),
		EnclaveType:   "secure_enclave",
		PublicKeyPath: "~/.credctl/device.pub",
	}
}

// testConfigWithAWS returns a Config with AWS settings for testing.
func testConfigWithAWS() *config.Config {
	cfg := testConfig()
	cfg.AWS = &config.AWSConfig{
		RoleARN:   "arn:aws:iam::123456789012:role/test",
		IssuerURL: "https://d1234.cloudfront.net",
		Region:    "us-east-1",
	}
	return cfg
}

// testConfigWithGCP returns a Config with GCP settings for testing.
func testConfigWithGCP() *config.Config {
	cfg := testConfig()
	cfg.GCP = &config.GCPConfig{
		ProjectNumber:       "123456789",
		WorkloadPoolID:      "credctl-pool",
		ProviderID:          "credctl-provider",
		ServiceAccountEmail: "credctl@project.iam.gserviceaccount.com",
		IssuerURL:           "https://d1234.cloudfront.net",
	}
	return cfg
}

// errMock returns an error with the given message.
func errMock(msg string) error {
	return fmt.Errorf("%s", msg)
}
