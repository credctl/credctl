package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

// httpClient returns an HTTP client that dials the given Unix socket.
func httpClient(socketPath string) *http.Client {
	return &http.Client{
		Timeout: 60 * time.Second, // allow time for Touch ID prompt
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.DialTimeout("unix", socketPath, 2*time.Second)
			},
		},
	}
}

// DaemonRunning checks if the daemon socket exists and responds.
func DaemonRunning(socketPath string) bool {
	if _, err := os.Stat(socketPath); err != nil {
		return false
	}

	client := httpClient(socketPath)
	resp, err := client.Get("http://daemon/v1/status")
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// FetchCredentials retrieves credentials from the running daemon.
// Returns the raw JSON response body, or an error if the daemon is
// unreachable or returns an error status.
func FetchCredentials(socketPath, provider, format string) ([]byte, error) {
	client := httpClient(socketPath)

	url := fmt.Sprintf("http://daemon/v1/credentials/%s?format=%s", provider, format)
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("connect to daemon: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read daemon response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			return nil, fmt.Errorf("daemon: %s", errResp.Error)
		}
		return nil, fmt.Errorf("daemon returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	return body, nil
}

// FetchStatus retrieves the daemon status.
func FetchStatus(socketPath string) (*StatusResponse, error) {
	client := httpClient(socketPath)

	resp, err := client.Get("http://daemon/v1/status")
	if err != nil {
		return nil, fmt.Errorf("connect to daemon: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read daemon response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("daemon returned HTTP %d", resp.StatusCode)
	}

	var status StatusResponse
	if err := json.Unmarshal(body, &status); err != nil {
		return nil, fmt.Errorf("parse status: %w", err)
	}
	return &status, nil
}

// ClearCache tells the daemon to clear all cached credentials.
func ClearCache(socketPath string) error {
	client := httpClient(socketPath)

	resp, err := client.Post("http://daemon/v1/clear", "application/json", nil)
	if err != nil {
		return fmt.Errorf("connect to daemon: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("daemon returned HTTP %d", resp.StatusCode)
	}
	return nil
}
