//go:build linux

package response

import (
	"errors"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

// These tests use the real pidfd system calls on a test child of their own.
func TestRealPidfdBindsTheSignalToThatInstance(t *testing.T) {
	if err := CheckSupport(); err != nil {
		t.Skipf("pidfd not available: %v", err)
	}
	sys := NewSystem()
	cmd := exec.Command("sleep", "60")
	if err := cmd.Start(); err != nil {
		t.Skipf("no sleep binary: %v", err)
	}
	pid := cmd.Process.Pid
	killed := false
	defer func() {
		if !killed {
			cmd.Process.Kill()
			cmd.Wait()
		}
	}()
	time.Sleep(50 * time.Millisecond)

	fd, err := sys.PidfdOpen(pid)
	if err != nil {
		t.Fatalf("pidfd_open: %v", err)
	}
	defer sys.Close(fd)
	if err := sys.PidfdSignal(fd, 0); err != nil {
		t.Fatalf("probe signal 0: %v", err)
	}
	if exe, err := sys.ExeLink(pid); err != nil || !strings.HasSuffix(exe, "/sleep") {
		t.Fatalf("exe link %q %v", exe, err)
	}
	if raw, more, err := sys.Cmdline(pid, 4096); err != nil || more || string(raw) != "sleep\x0060\x00" {
		t.Fatalf("cmdline %q more=%v %v", raw, more, err)
	}
	if raw, more, _ := sys.Cmdline(pid, 3); !more || len(raw) != 3 {
		t.Fatalf("a cut cmdline must say so: %q %v", raw, more)
	}

	if err := sys.PidfdSignal(fd, syscall.SIGKILL); err != nil {
		t.Fatalf("SIGKILL through the pidfd: %v", err)
	}
	err = cmd.Wait()
	killed = true
	ws := cmd.ProcessState.Sys().(syscall.WaitStatus)
	if !ws.Signaled() || ws.Signal() != syscall.SIGKILL {
		t.Fatalf("child not killed by SIGKILL: %v %v", err, ws)
	}
	// The handle stays bound to the dead instance: it never reaches whoever gets the pid next.
	if err := sys.PidfdSignal(fd, syscall.SIGKILL); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("signal through a stale pidfd: %v, want ESRCH", err)
	}
	if _, err := sys.PidfdOpen(pid); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("pidfd_open of a reaped pid: %v, want ESRCH", err)
	}
}

func TestRealSystemClockHelpers(t *testing.T) {
	sys := NewSystem()
	if sys.BootNS() == 0 || sys.Now().IsZero() {
		t.Fatal("clocks")
	}
}
