package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/credctl/credctl/internal/daemon"
	"github.com/spf13/cobra"
)

var (
	daemonIdleTimeout time.Duration
	daemonForeground  bool
)

var daemonCmd = &cobra.Command{
	Use:   "daemon",
	Short: "Manage the credential caching daemon",
	Long: `The credential daemon caches cloud credentials in memory after the first
signing operation. Subsequent credctl auth calls return cached credentials
instantly without re-signing or re-issuing cloud STS calls (and on platforms
with a biometric prompt, without re-triggering it).

Credentials are held in process memory only and never written to disk.`,
}

var daemonStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the credential caching daemon",
	Long: `Starts the daemon listening on a Unix socket at ~/.credctl/daemon.sock.

The daemon caches credentials after the first fetch and serves them to
subsequent credctl auth calls. It shuts down automatically after the
idle timeout (default 30m) if no requests are received.`,
	RunE: runDaemonStart,
}

var daemonStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the credential caching daemon",
	RunE:  runDaemonStop,
}

var daemonStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show daemon status and cache state",
	RunE:  runDaemonStatus,
}

func init() {
	daemonStartCmd.Flags().DurationVar(&daemonIdleTimeout, "idle-timeout", 30*time.Minute, "Shut down after this duration of inactivity")
	daemonStartCmd.Flags().BoolVar(&daemonForeground, "foreground", false, "Run in foreground (don't daemonize)")
	daemonCmd.AddCommand(daemonStartCmd)
	daemonCmd.AddCommand(daemonStopCmd)
	daemonCmd.AddCommand(daemonStatusCmd)
	rootCmd.AddCommand(daemonCmd)
}

func runDaemonStart(cmd *cobra.Command, args []string) error {
	cfgDir, err := activeDeps.configDir()
	if err != nil {
		return fmt.Errorf("config dir: %w", err)
	}

	socketPath := daemon.SocketPath(cfgDir)
	pidPath := daemon.PIDFilePath(cfgDir)

	// Check if already running.
	if daemon.DaemonRunning(socketPath) {
		return fmt.Errorf("daemon is already running (socket %s)", socketPath)
	}

	enc := activeDeps.newEnclave()
	deps := daemon.ServerDeps{
		LoadConfig:    activeDeps.loadConfig,
		PublicKeyPath: activeDeps.publicKeyPath,
		NewSignFn: func(keyTag string) func(data []byte) ([]byte, error) {
			return func(data []byte) ([]byte, error) {
				return enc.Sign(keyTag, data)
			}
		},
		AssumeRole:             activeDeps.assumeRole,
		GCPExchangeToken:       activeDeps.gcpExchangeToken,
		GCPGenerateAccessToken: activeDeps.gcpGenerateAccessToken,
	}

	srv := daemon.NewServer(socketPath, pidPath, daemonIdleTimeout, deps)

	if !daemonForeground {
		// Background: re-exec ourselves with --foreground.
		// For now, just run in foreground. Background daemonization
		// will be added with launchd integration in Phase 3.
		fmt.Fprintln(os.Stderr, "Running in foreground (use --foreground flag explicitly, or install as launchd service)")
	}

	// Handle graceful shutdown.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	go func() {
		<-ctx.Done()
		fmt.Fprintln(os.Stderr, "\nShutting down daemon...")
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()

	return srv.Start()
}

func runDaemonStop(cmd *cobra.Command, args []string) error {
	cfgDir, err := activeDeps.configDir()
	if err != nil {
		return fmt.Errorf("config dir: %w", err)
	}

	pidPath := daemon.PIDFilePath(cfgDir)
	pid, err := daemon.ReadPIDFile(pidPath)
	if err != nil {
		return fmt.Errorf("daemon not running (no PID file): %w", err)
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("find process %d: %w", pid, err)
	}

	if err := proc.Signal(syscall.SIGTERM); err != nil {
		// Process might already be gone — clean up stale files.
		daemon.RemovePIDFile(pidPath)
		socketPath := daemon.SocketPath(cfgDir)
		_ = os.Remove(socketPath)
		fmt.Fprintf(os.Stderr, "Daemon process %d not found, cleaned up stale files\n", pid)
		return nil
	}

	fmt.Fprintf(os.Stderr, "Sent SIGTERM to daemon (PID %d)\n", pid)

	// Wait briefly for shutdown.
	for i := 0; i < 10; i++ {
		time.Sleep(200 * time.Millisecond)
		if err := proc.Signal(syscall.Signal(0)); err != nil {
			fmt.Fprintln(os.Stderr, "Daemon stopped")
			return nil
		}
	}

	fmt.Fprintln(os.Stderr, "Daemon still running after 2s — it may take a moment to finish")
	return nil
}

func runDaemonStatus(cmd *cobra.Command, args []string) error {
	cfgDir, err := activeDeps.configDir()
	if err != nil {
		return fmt.Errorf("config dir: %w", err)
	}

	socketPath := daemon.SocketPath(cfgDir)
	if !daemon.DaemonRunning(socketPath) {
		fmt.Println("Daemon is not running")
		return nil
	}

	status, err := daemon.FetchStatus(socketPath)
	if err != nil {
		return fmt.Errorf("query daemon: %w", err)
	}

	fmt.Printf("Daemon running (PID %d)\n", status.PID)
	fmt.Printf("  Uptime:  %s\n", status.Uptime)
	fmt.Printf("  Started: %s\n", status.StartTime)

	if len(status.Cache) == 0 {
		fmt.Println("  Cache:   empty")
	} else {
		fmt.Println("  Cache:")
		for key, entry := range status.Cache {
			state := "valid"
			if !entry.Valid {
				state = "expired"
			} else if entry.NeedsRefresh {
				state = "needs refresh"
			}
			fmt.Printf("    %s: %s (expires %s)\n", key, state, entry.ExpiresAt.Format(time.RFC3339))
		}
	}

	return nil
}
