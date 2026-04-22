package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

const (
	pidFileName  = "daemon.pid"
	sockFileName = "daemon.sock"
)

// pidLockFile holds the open PID file descriptor to maintain the flock
// for the lifetime of the process. The OS releases the lock when the
// process exits.
var pidLockFile *os.File

// SocketPath returns the default Unix socket path.
func SocketPath(configDir string) string {
	return filepath.Join(configDir, sockFileName)
}

// PIDFilePath returns the default PID file path.
func PIDFilePath(configDir string) string {
	return filepath.Join(configDir, pidFileName)
}

// WritePIDFile writes the current process ID to the PID file.
// It uses O_EXCL for atomic creation and flock for advisory locking
// to prevent duplicate daemons even under race conditions.
func WritePIDFile(path string) error {
	// Try to create exclusively — fails if file already exists.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		if os.IsExist(err) {
			// Check if the existing PID is still running.
			pid, readErr := ReadPIDFile(path)
			if readErr == nil && processRunning(pid) {
				return fmt.Errorf("daemon already running (PID %d)", pid)
			}
			// Stale PID file — remove and retry.
			_ = os.Remove(path)
			f, err = os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if err != nil {
				return fmt.Errorf("create PID file: %w", err)
			}
		} else {
			return fmt.Errorf("create PID file: %w", err)
		}
	}

	// Acquire an exclusive non-blocking flock as an additional guard
	// against TOCTOU races between the O_EXCL check and PID write.
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return fmt.Errorf("daemon already running (could not acquire lock)")
	}

	// Keep the file open to hold the flock for the process lifetime.
	pidLockFile = f

	_, err = fmt.Fprintf(f, "%d", os.Getpid())
	return err
}

// ReadPIDFile reads the daemon PID from the PID file.
func ReadPIDFile(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, fmt.Errorf("invalid PID in %s: %w", path, err)
	}
	return pid, nil
}

// RemovePIDFile releases the flock and removes the PID file.
func RemovePIDFile(path string) {
	if pidLockFile != nil {
		pidLockFile.Close()
		pidLockFile = nil
	}
	_ = os.Remove(path)
}

// processRunning checks if a process with the given PID exists.
func processRunning(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	// On Unix, FindProcess always succeeds. Send signal 0 to check.
	err = proc.Signal(syscall.Signal(0))
	return err == nil
}
