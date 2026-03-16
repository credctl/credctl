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
	"path/filepath"
	"strings"
	"sync"
	"syscall"
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

	s.srv = &http.Server{
		Handler:        mux,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   65 * time.Second, // allow for Touch ID prompt during credential fetch
		MaxHeaderBytes: 1 << 16,          // 64KB
	}
	return s
}

// Start begins listening on the Unix socket and serving requests.
func (s *Server) Start() error {
	// Verify parent directory permissions. The socket lives inside ~/.credctl/
	// which must be user-only (0700). Combined with the 0600 socket permissions
	// set via umask below, this provides filesystem-based peer access control
	// without requiring platform-specific SO_PEERCRED/LOCAL_PEERCRED checks.
	dir := filepath.Dir(s.socketPath)
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("stat config dir: %w", err)
	}
	if perm := info.Mode().Perm(); perm&0077 != 0 {
		return fmt.Errorf("config directory %s has permissions %04o, expected 0700 — run: chmod 700 %s", dir, perm, dir)
	}

	// Remove stale socket file if it exists.
	_ = os.Remove(s.socketPath)

	if err := WritePIDFile(s.pidFilePath); err != nil {
		return err
	}

	// Set umask to 0177 so the socket is created with 0600 from the start,
	// eliminating the TOCTOU window between Listen and a separate Chmod.
	oldMask := syscall.Umask(0177)
	ln, err := net.Listen("unix", s.socketPath)
	syscall.Umask(oldMask)
	if err != nil {
		RemovePIDFile(s.pidFilePath)
		return fmt.Errorf("listen on %s: %w", s.socketPath, err)
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
		jsonError(w, fmt.Sprintf("unknown provider: %s", provider), http.StatusBadRequest)
	}
}

func (s *Server) handleAWSCredentials(w http.ResponseWriter, format string) {
	if format != "credential_process" && format != "env" {
		jsonError(w, "unknown format", http.StatusBadRequest)
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
		jsonError(w, "AWS not configured", http.StatusBadRequest)
		return
	}

	kid, signFn, err := s.prepareSign(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "prepareSign: %v\n", err)
		jsonError(w, "authentication failed", http.StatusInternalServerError)
		return
	}

	token, err := jwt.BuildAndSign(kid, cfg.AWS.IssuerURL, cfg.DeviceID, "sts.amazonaws.com", signFn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "build JWT: %v\n", err)
		jsonError(w, "authentication failed", http.StatusInternalServerError)
		return
	}

	fingerprint := strings.TrimPrefix(cfg.DeviceID, "SHA256:")
	randBytes := make([]byte, 4)
	_, _ = rand.Read(randBytes)
	sessionName := "credctl-" + fingerprint[:8] + "-" + hex.EncodeToString(randBytes)

	creds, err := s.deps.AssumeRole(cfg.AWS.RoleARN, sessionName, token, cfg.AWS.Region)
	if err != nil {
		fmt.Fprintf(os.Stderr, "assume role: %v\n", err)
		jsonError(w, "credential exchange failed", http.StatusInternalServerError)
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
		jsonError(w, "unknown format", http.StatusBadRequest)
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
		jsonError(w, "GCP not configured", http.StatusBadRequest)
		return
	}

	kid, signFn, err := s.prepareSign(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "prepareSign: %v\n", err)
		jsonError(w, "authentication failed", http.StatusInternalServerError)
		return
	}

	audience := cfg.GCP.Audience()

	token, err := jwt.BuildAndSign(kid, cfg.GCP.IssuerURL, cfg.DeviceID, audience, signFn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "build JWT: %v\n", err)
		jsonError(w, "authentication failed", http.StatusInternalServerError)
		return
	}

	var data []byte
	var expiresAt time.Time

	switch format {
	case "executable":
		expiresAt = time.Now().Add(5 * time.Minute)
		out := executableOutput{ // #nosec G101 -- not hardcoded credentials, this is the output structure
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
			fmt.Fprintf(os.Stderr, "token exchange: %v\n", err)
			jsonError(w, "credential exchange failed", http.StatusInternalServerError)
			return
		}
		accessToken, err := s.deps.GCPGenerateAccessToken(
			cfg.GCP.ServiceAccountEmail,
			fedToken.AccessToken,
			[]string{"https://www.googleapis.com/auth/cloud-platform"},
		)
		if err != nil {
			fmt.Fprintf(os.Stderr, "generate access token: %v\n", err)
			jsonError(w, "credential exchange failed", http.StatusInternalServerError)
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

// jsonError writes a properly JSON-encoded error response and sets the Content-Type header.
func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	data, _ := json.Marshal(map[string]string{"error": msg})
	w.Write(data)
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
