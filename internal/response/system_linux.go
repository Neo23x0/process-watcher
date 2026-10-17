//go:build linux

package response

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/Neo23x0/process-watcher/internal/clock"
)

// osSystem is the real System: pidfd_open(2) and pidfd_send_signal(2) with the
// options available on Linux 5.15 (flags 0 only), and /proc.
type osSystem struct{}

// NewSystem returns the operating system backed System.
func NewSystem() System { return osSystem{} }

func (osSystem) PidfdOpen(tgid int) (int, error) { return unix.PidfdOpen(tgid, 0) }

func (osSystem) PidfdSignal(fd int, sig syscall.Signal) error {
	return unix.PidfdSendSignal(fd, unix.Signal(sig), nil, 0)
}

func (osSystem) Close(fd int) error { return unix.Close(fd) }

func (osSystem) ExeLink(tgid int) (string, error) {
	return os.Readlink("/proc/" + strconv.Itoa(tgid) + "/exe")
}

func (osSystem) Cmdline(tgid int, max int) ([]byte, bool, error) {
	f, err := os.Open("/proc/" + strconv.Itoa(tgid) + "/cmdline")
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	buf := make([]byte, max+1)
	n, err := io.ReadFull(f, buf)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return nil, false, err
	}
	if n > max {
		return buf[:max], true, nil
	}
	return buf[:n], false, nil
}

func (osSystem) BootNS() uint64 { return clock.BootNS() }
func (osSystem) Now() time.Time { return time.Now() }

// CheckSupport verifies that the pidfd system calls work, without signalling
// anything but the probe signal 0 on this very process. The kill feature
// refuses to start when it fails.
func CheckSupport() error {
	fd, err := unix.PidfdOpen(os.Getpid(), 0)
	if err != nil {
		return fmt.Errorf("pidfd_open is not available (needs Linux 5.3 or newer and no seccomp filter blocking it): %w", err)
	}
	defer unix.Close(fd)
	if err := unix.PidfdSendSignal(fd, 0, nil, 0); err != nil {
		return fmt.Errorf("pidfd_send_signal is not available (needs Linux 5.1 or newer): %w", err)
	}
	return nil
}
