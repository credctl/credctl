package daemon

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/credctl/credctl/internal/aws"
	"github.com/credctl/credctl/internal/config"
	"github.com/credctl/credctl/internal/gcp"
	"github.com/credctl/credctl/internal/jwt"
)

// ServerDeps holds injectable dependencies for the daemon server.
type ServerDeps struct {
	LoadConfig             func() (*config.Config, error)
	PublicKeyPath          func() (string, error)
	NewSignFn              func(keyTag string) func(data []byte) ([]byte, error)
	AssumeRole             func(roleARN, sessionName, token, region string) (*aws.Credentials, error)
	GCPExchangeToken       func(audience, subjectToken string) (*gcp.FederatedToken, error)
	GCPGenerateAccessToken func(serviceAccountEmail, federatedToken string, scopes []string) (*gcp.AccessToken, error)
}

// Server is the credential daemon HTTP server over a Unix socket.
type Server struct {
	deps        ServerDeps
	cache       *Cache
	socketPath  string
	pidFilePath string
	idleTimeout time.Duration
	startTime   time.Time

	listener net.Listener
	srv      *http.Server

	idleMu    sync.Mutex
	idleTimer *time.Timer
}

// NewServer creates a new daemon server.
func NewServer(socketPath, pidFilePath string, idleTimeout time.Duration, deps ServerDeps) *Server {
	s := &Server{
		deps:        deps,
		cache:       NewCache(),
		socketPath:  socketPath,
		pidFilePath: pidFilePath,
		idleTimeout: idleTimeout,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/credentials/{provider}", s.handleCredentials)
	mux.HandleFunc("GET /v1/status", s.handleStatus)
	mux.HandleFunc("POST /v1/clear", s.handleClear)

	s.srv = &http.Server{Handler: mux}
	return s
}

// Start begins listening on the Unix socket and serving requests.
func (s *Server) Start() error {
	// Remove stale socket file if it exists.
	_ = os.Remove(s.socketPath)

	if err := WritePIDFile(s.pidFilePath); err != nil {
		return err
	}

	ln, err := net.Listen("unix", s.socketPath)
	if err != nil {
		RemovePIDFile(s.pidFilePath)
		return fmt.Errorf("listen on %s: %w", s.socketPath, err)
	}

	// Set socket permissions to user-only.
	if err := os.Chmod(s.socketPath, 0600); err != nil {
		ln.Close()
		RemovePIDFile(s.pidFilePath)
		return fmt.Errorf("chmod socket: %w", err)
	}

	s.listener = ln
	s.startTime = time.Now()

	if s.idleTimeout > 0 {
		s.resetIdleTimer()
	}

	fmt.Fprintf(os.Stderr, "credctl daemon listening on %s (PID %d)\n", s.socketPath, os.Getpid())
	if err := s.srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// Shutdown gracefully stops the server and cleans up.
func (s *Server) Shutdown(ctx context.Context) error {
	s.idleMu.Lock()
	if s.idleTimer != nil {
		s.idleTimer.Stop()
	}
	s.idleMu.Unlock()

	err := s.srv.Shutdown(ctx)
	_ = os.Remove(s.socketPath)
	RemovePIDFile(s.pidFilePath)
	return err
}

func (s *Server) resetIdleTimer() {
	s.idleMu.Lock()
	defer s.idleMu.Unlock()
	if s.idleTimer != nil {
		s.idleTimer.Stop()
	}
	s.idleTimer = time.AfterFunc(s.idleTimeout, func() {
		fmt.Fprintln(os.Stderr, "idle timeout reached, shutting down")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.Shutdown(ctx)
	})
}

func (s *Server) handleCredentials(w http.ResponseWriter, r *http.Request) {
	if s.idleTimeout > 0 {
		s.resetIdleTimer()
	}

	provider := r.PathValue("provider")
	format := r.URL.Query().Get("format")

	switch provider {
	case "aws":
		if format == "" {
			format = "credential_process"
		}
		s.handleAWSCredentials(w, format)
	case "gcp":
		if format == "" {
			format = "executable"
		}
		s.handleGCPCredentials(w, format)
	default:
		http.Error(w, fmt.Sprintf(`{"error":"unknown provider: %s"}`, provider), http.StatusBadRequest)
	}
}

func (s *Server) handleAWSCredentials(w http.ResponseWriter, format string) {
	if format != "credential_process" && format != "env" {
		http.Error(w, `{"error":"unknown format"}`, http.StatusBadRequest)
		return
	}

	// Check cache first.
	cached := s.cache.Get("aws", format)
	if cached != nil && !cached.NeedsRefresh() {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Credctl-Cache", "hit")
		w.Write(cached.Data)
		return
	}

	// Acquire per-key fetch lock to avoid duplicate fetches.
	mu := s.cache.FetchLock("aws", format)
	mu.Lock()
	defer mu.Unlock()

	// Double-check after acquiring lock.
	cached = s.cache.Get("aws", format)
	if cached != nil && !cached.NeedsRefresh() {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Credctl-Cache", "hit")
		w.Write(cached.Data)
		return
	}

	cfg, err := s.deps.LoadConfig()
	if err != nil || cfg == nil || cfg.AWS == nil {
		http.Error(w, `{"error":"AWS not configured"}`, http.StatusBadRequest)
		return
	}

	kid, signFn, err := s.prepareSign(cfg)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	token, err := jwt.BuildAndSign(kid, cfg.AWS.IssuerURL, cfg.DeviceID, "sts.amazonaws.com", signFn)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"build JWT: %s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	fingerprint := strings.TrimPrefix(cfg.DeviceID, "SHA256:")
	randBytes := make([]byte, 4)
	_, _ = rand.Read(randBytes)
	sessionName := "credctl-" + fingerprint[:8] + "-" + hex.EncodeToString(randBytes)

	creds, err := s.deps.AssumeRole(cfg.AWS.RoleARN, sessionName, token, cfg.AWS.Region)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"assume role: %s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	var data []byte
	switch format {
	case "credential_process":
		out := credentialProcessOutput{
			Version:        1,
			AccessKeyID:    creds.AccessKeyID,
			SecretAccessKey: creds.SecretAccessKey,
			SessionToken:   creds.SessionToken,
			Expiration:     creds.Expiration.Format(time.RFC3339),
		}
		data, _ = json.Marshal(out)
	case "env":
		out := envOutput{
			AccessKeyID:    creds.AccessKeyID,
			SecretAccessKey: creds.SecretAccessKey,
			SessionToken:   creds.SessionToken,
			Expiration:     creds.Expiration.Format(time.RFC3339),
		}
		data, _ = json.Marshal(out)
	}

	s.cache.Set("aws", format, &CachedCredential{
		Data:      data,
		ExpiresAt: creds.Expiration,
		Format:    format,
	})

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Credctl-Cache", "miss")
	w.Write(data)
}

func (s *Server) handleGCPCredentials(w http.ResponseWriter, format string) {
	if format != "executable" && format != "env" {
		http.Error(w, `{"error":"unknown format"}`, http.StatusBadRequest)
		return
	}

	// Check cache first.
	cached := s.cache.Get("gcp", format)
	if cached != nil && !cached.NeedsRefresh() {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Credctl-Cache", "hit")
		w.Write(cached.Data)
		return
	}

	// Acquire per-key fetch lock.
	mu := s.cache.FetchLock("gcp", format)
	mu.Lock()
	defer mu.Unlock()

	// Double-check after acquiring lock.
	cached = s.cache.Get("gcp", format)
	if cached != nil && !cached.NeedsRefresh() {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Credctl-Cache", "hit")
		w.Write(cached.Data)
		return
	}

	cfg, err := s.deps.LoadConfig()
	if err != nil || cfg == nil || cfg.GCP == nil {
		http.Error(w, `{"error":"GCP not configured"}`, http.StatusBadRequest)
		return
	}

	kid, signFn, err := s.prepareSign(cfg)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	audience := cfg.GCP.Audience()

	token, err := jwt.BuildAndSign(kid, cfg.GCP.IssuerURL, cfg.DeviceID, audience, signFn)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"build JWT: %s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	var data []byte
	var expiresAt time.Time

	switch format {
	case "executable":
		expiresAt = time.Now().Add(5 * time.Minute)
		out := executableOutput{
			Version:        1,
			Success:        true,
			TokenType:      "urn:ietf:params:oauth:token-type:jwt",
			ExpirationTime: expiresAt.Unix(),
			SubjectToken:   token,
		}
		data, _ = json.Marshal(out)

	case "env":
		fedToken, err := s.deps.GCPExchangeToken(audience, token)
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"token exchange: %s"}`, err.Error()), http.StatusInternalServerError)
			return
		}
		accessToken, err := s.deps.GCPGenerateAccessToken(
			cfg.GCP.ServiceAccountEmail,
			fedToken.AccessToken,
			[]string{"https://www.googleapis.com/auth/cloud-platform"},
		)
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"generate access token: %s"}`, err.Error()), http.StatusInternalServerError)
			return
		}
		expiresAt = accessToken.ExpireTime
		out := gcpEnvOutput{
			AccessToken: accessToken.Token,
			Expiration:  accessToken.ExpireTime.Format(time.RFC3339),
		}
		data, _ = json.Marshal(out)
	}

	s.cache.Set("gcp", format, &CachedCredential{
		Data:      data,
		ExpiresAt: expiresAt,
		Format:    format,
	})

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Credctl-Cache", "miss")
	w.Write(data)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if s.idleTimeout > 0 {
		s.resetIdleTimer()
	}

	status := StatusResponse{
		PID:       os.Getpid(),
		Uptime:    time.Since(s.startTime).String(),
		StartTime: s.startTime.Format(time.RFC3339),
		Cache:     s.cache.Status(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func (s *Server) handleClear(w http.ResponseWriter, r *http.Request) {
	if s.idleTimeout > 0 {
		s.resetIdleTimer()
	}

	s.cache.Clear()
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"ok":true}`))
}

func (s *Server) prepareSign(cfg *config.Config) (string, jwt.SigningFunc, error) {
	pubKeyPath, err := s.deps.PublicKeyPath()
	if err != nil {
		return "", nil, fmt.Errorf("public key path: %w", err)
	}
	pubKeyPEM, err := os.ReadFile(pubKeyPath)
	if err != nil {
		return "", nil, fmt.Errorf("read public key: %w", err)
	}

	kid, err := jwt.KIDFromPublicKeyPEM(pubKeyPEM)
	if err != nil {
		return "", nil, fmt.Errorf("derive key ID: %w", err)
	}

	signFn := s.deps.NewSignFn(cfg.KeyTag)
	return kid, signFn, nil
}

// Response types for the daemon API.

type credentialProcessOutput struct {
	Version        int    `json:"Version"`
	AccessKeyID    string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	SessionToken   string `json:"SessionToken"`
	Expiration     string `json:"Expiration"`
}

type envOutput struct {
	AccessKeyID    string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	SessionToken   string `json:"SessionToken"`
	Expiration     string `json:"Expiration"`
}

type executableOutput struct {
	Version        int    `json:"version"`
	Success        bool   `json:"success"`
	TokenType      string `json:"token_type"`
	ExpirationTime int64  `json:"expiration_time"`
	SubjectToken   string `json:"subject_token"`
}

type gcpEnvOutput struct {
	AccessToken string `json:"access_token"`
	Expiration  string `json:"expiration"`
}

// StatusResponse is the JSON response for GET /v1/status.
type StatusResponse struct {
	PID       int                          `json:"pid"`
	Uptime    string                       `json:"uptime"`
	StartTime string                       `json:"start_time"`
	Cache     map[string]CacheEntryStatus  `json:"cache"`
}
