package gcp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestExchangeToken_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("content-type = %s, want application/json", ct)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(FederatedToken{
			AccessToken: "federated-token-123",
			ExpiresIn:   3600,
			TokenType:   "Bearer",
		})
	}))
	defer srv.Close()

	token, err := exchangeToken(srv.URL, "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/prov", "signed-jwt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token.AccessToken != "federated-token-123" {
		t.Errorf("access_token = %q, want federated-token-123", token.AccessToken)
	}
	if token.ExpiresIn != 3600 {
		t.Errorf("expires_in = %d, want 3600", token.ExpiresIn)
	}
}

func TestExchangeToken_RequestBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)

		if body["grant_type"] != "urn:ietf:params:oauth:grant-type:token-exchange" {
			t.Errorf("grant_type = %q", body["grant_type"])
		}
		if body["subject_token_type"] != "urn:ietf:params:oauth:token-type:jwt" {
			t.Errorf("subject_token_type = %q", body["subject_token_type"])
		}
		if body["subject_token"] != "my-jwt" {
			t.Errorf("subject_token = %q", body["subject_token"])
		}
		if body["audience"] != "test-audience" {
			t.Errorf("audience = %q", body["audience"])
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(FederatedToken{AccessToken: "tok", ExpiresIn: 3600, TokenType: "Bearer"})
	}))
	defer srv.Close()

	_, err := exchangeToken(srv.URL, "test-audience", "my-jwt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExchangeToken_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":{"code":400,"message":"Invalid token","status":"INVALID_ARGUMENT"}}`))
	}))
	defer srv.Close()

	_, err := exchangeToken(srv.URL, "aud", "bad-jwt")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "Invalid token") {
		t.Errorf("error should mention Invalid token: %v", err)
	}
}

func TestExchangeToken_NetworkError(t *testing.T) {
	_, err := exchangeToken("http://127.0.0.1:1", "aud", "jwt")
	if err == nil {
		t.Fatal("expected error for unreachable endpoint")
	}
	if !strings.Contains(err.Error(), "STS request failed") {
		t.Errorf("error should mention STS request failed: %v", err)
	}
}

func TestGenerateAccessToken_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		auth := r.Header.Get("Authorization")
		if auth != "Bearer fed-token" {
			t.Errorf("authorization = %q, want Bearer fed-token", auth)
		}

		var body map[string][]string
		json.NewDecoder(r.Body).Decode(&body)
		if len(body["scope"]) != 1 || body["scope"][0] != "https://www.googleapis.com/auth/cloud-platform" {
			t.Errorf("scope = %v", body["scope"])
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"accessToken":"ya29.test-token","expireTime":"2026-03-12T14:00:00Z"}`))
	}))
	defer srv.Close()

	token, err := generateAccessToken(srv.URL, "fed-token", []string{"https://www.googleapis.com/auth/cloud-platform"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token.Token != "ya29.test-token" {
		t.Errorf("token = %q, want ya29.test-token", token.Token)
	}
	if token.ExpireTime.IsZero() {
		t.Error("expire time should not be zero")
	}
}

func TestGenerateAccessToken_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error":{"code":403,"message":"Permission denied","status":"PERMISSION_DENIED"}}`))
	}))
	defer srv.Close()

	_, err := generateAccessToken(srv.URL, "fed-token", []string{"https://www.googleapis.com/auth/cloud-platform"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "Permission denied") {
		t.Errorf("error should mention Permission denied: %v", err)
	}
}

func TestGenerateAccessToken_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not json"))
	}))
	defer srv.Close()

	_, err := generateAccessToken(srv.URL, "fed-token", []string{"https://www.googleapis.com/auth/cloud-platform"})
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestGenerateAccessToken_InvalidExpiration(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"accessToken":"ya29.test","expireTime":"not-a-date"}`))
	}))
	defer srv.Close()

	_, err := generateAccessToken(srv.URL, "fed-token", []string{"https://www.googleapis.com/auth/cloud-platform"})
	if err == nil {
		t.Fatal("expected error for invalid expiration")
	}
	if !strings.Contains(err.Error(), "parse expiration") {
		t.Errorf("error should mention expiration: %v", err)
	}
}

func TestGenerateAccessToken_NetworkError(t *testing.T) {
	_, err := generateAccessToken("http://127.0.0.1:1", "fed-token", []string{"scope"})
	if err == nil {
		t.Fatal("expected error for unreachable endpoint")
	}
	if !strings.Contains(err.Error(), "IAM request failed") {
		t.Errorf("error should mention IAM request: %v", err)
	}
}

func TestGenerateAccessToken_NonJSONError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	}))
	defer srv.Close()

	_, err := generateAccessToken(srv.URL, "fed-token", []string{"scope"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error should contain status code: %v", err)
	}
}

func TestExchangeToken_NonJSONError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("server error"))
	}))
	defer srv.Close()

	_, err := exchangeToken(srv.URL, "aud", "jwt")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error should contain status code: %v", err)
	}
}

func TestExchangeToken_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not json at all"))
	}))
	defer srv.Close()

	_, err := exchangeToken(srv.URL, "aud", "jwt")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
	if !strings.Contains(err.Error(), "parse STS response") {
		t.Errorf("error should mention parsing: %v", err)
	}
}

func TestWriteCredentialConfig_BadPath(t *testing.T) {
	err := WriteCredentialConfig("/dev/null/impossible/path.json", &ExternalCredentialConfig{})
	if err == nil {
		t.Fatal("expected error for invalid path")
	}
}
