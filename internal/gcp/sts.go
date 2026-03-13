package gcp

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// stsClient is an HTTP client configured for GCP STS calls with TLS 1.2+ and timeouts.
var stsClient = &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	},
}

// FederatedToken holds the result of a GCP STS token exchange.
type FederatedToken struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

// AccessToken holds a GCP service account access token.
type AccessToken struct {
	Token      string    `json:"accessToken"`
	ExpireTime time.Time `json:"expireTime"`
}

// accessTokenResponse is the JSON response from generateAccessToken.
type accessTokenResponse struct {
	AccessToken string `json:"accessToken"`
	ExpireTime  string `json:"expireTime"`
}

// gcpError is the JSON error format returned by GCP APIs.
type gcpError struct {
	Error struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Status  string `json:"status"`
	} `json:"error"`
}

// ExchangeToken exchanges a signed JWT for a GCP federated access token via STS.
func ExchangeToken(audience, subjectToken string) (*FederatedToken, error) {
	return exchangeToken("https://sts.googleapis.com/v1/token", audience, subjectToken)
}

// exchangeToken performs the actual GCP STS token exchange HTTP call.
func exchangeToken(endpoint, audience, subjectToken string) (*FederatedToken, error) {
	body := fmt.Sprintf(
		`{"grant_type":"urn:ietf:params:oauth:grant-type:token-exchange","audience":"%s","subject_token_type":"urn:ietf:params:oauth:token-type:jwt","subject_token":"%s","requested_token_type":"urn:ietf:params:oauth:token-type:access_token"}`,
		audience, subjectToken,
	)

	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := stsClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("STS request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read STS response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp gcpError
		if jsonErr := json.Unmarshal(respBody, &errResp); jsonErr == nil && errResp.Error.Message != "" {
			return nil, fmt.Errorf("STS error (%s): %s", errResp.Error.Status, errResp.Error.Message)
		}
		return nil, fmt.Errorf("STS request failed (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	var token FederatedToken
	if err := json.Unmarshal(respBody, &token); err != nil {
		return nil, fmt.Errorf("parse STS response: %w", err)
	}

	return &token, nil
}

// GenerateAccessToken exchanges a federated token for a service account access token.
func GenerateAccessToken(serviceAccountEmail, federatedToken string, scopes []string) (*AccessToken, error) {
	endpoint := fmt.Sprintf("https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateAccessToken", serviceAccountEmail)
	return generateAccessToken(endpoint, federatedToken, scopes)
}

// generateAccessToken performs the actual IAM Credentials HTTP call.
func generateAccessToken(endpoint, federatedToken string, scopes []string) (*AccessToken, error) {
	scopeJSON, err := json.Marshal(scopes)
	if err != nil {
		return nil, fmt.Errorf("marshal scopes: %w", err)
	}
	body := fmt.Sprintf(`{"scope":%s}`, string(scopeJSON))

	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+federatedToken)

	resp, err := stsClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("IAM request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read IAM response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp gcpError
		if jsonErr := json.Unmarshal(respBody, &errResp); jsonErr == nil && errResp.Error.Message != "" {
			return nil, fmt.Errorf("IAM error (%s): %s", errResp.Error.Status, errResp.Error.Message)
		}
		return nil, fmt.Errorf("IAM request failed (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	var tokenResp accessTokenResponse
	if err := json.Unmarshal(respBody, &tokenResp); err != nil {
		return nil, fmt.Errorf("parse IAM response: %w", err)
	}

	expireTime, err := time.Parse(time.RFC3339, tokenResp.ExpireTime)
	if err != nil {
		return nil, fmt.Errorf("parse expiration: %w", err)
	}

	return &AccessToken{
		Token:      tokenResp.AccessToken,
		ExpireTime: expireTime,
	}, nil
}
