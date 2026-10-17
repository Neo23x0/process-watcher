//go:build linux

// Package procfs holds the few /proc based helpers of the agent. /proc is
// never an event source: it only supplements data and every read of a process
// verifies that the pid still belongs to the expected instance.
package procfs

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/Neo23x0/process-watcher/internal/collector"
)

// userHZ is the unit of /proc/<pid>/stat start times. It is fixed at 100 for
// the user space ABI on amd64 and arm64.
const userHZ = 100

// BootID returns the kernel's boot id (UUID).
func BootID() (string, error) {
	b, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", fmt.Errorf("read boot_id: %w", err)
	}
	return strings.ToLower(strings.TrimSpace(string(b))), nil
}

// startTicks reads field 22 of /proc/<pid>/stat: the start time in clock
// ticks since boot. The value only has tick resolution; it is used to detect
// pid reuse, never to build an identity.
func startTicks(pid uint32) (uint64, error) {
	b, err := os.ReadFile("/proc/" + strconv.FormatUint(uint64(pid), 10) + "/stat")
	if err != nil {
		return 0, err
	}
	// comm (field 2) may contain spaces and parentheses: split after the last ')'.
	i := bytes.LastIndexByte(b, ')')
	if i < 0 {
		return 0, errors.New("malformed stat")
	}
	fields := strings.Fields(string(b[i+1:]))
	// fields[0] is field 3 (state); starttime is field 22.
	if len(fields) < 20 {
		return 0, errors.New("short stat")
	}
	return strconv.ParseUint(fields[19], 10, 64)
}

// sameInstance reports whether /proc/<key.TGID> currently shows the process
// with the given exact kernel start time. The kernel field has nanosecond
// resolution, /proc only 10 ms ticks: equality of the tick value is a
// necessary condition that rules out pid reuse in practice (a reused pid
// would have to start within the same tick).
func sameInstance(key collector.Key) (bool, error) {
	ticks, err := startTicks(key.TGID)
	if err != nil {
		return false, err
	}
	return ticks == key.StartNS/(1_000_000_000/userHZ), nil
}

// ReadArgs reads the arguments of a living process for a snapshot. The
// process identity is checked before and after the read, so a pid that was
// reused in between is never mixed in. Any problem results in ArgsFailed: the
// arguments are then reported as unavailable, not as empty.
func ReadArgs(key collector.Key) collector.Args {
	failed := collector.Args{State: collector.ArgsFailed}
	if ok, err := sameInstance(key); err != nil || !ok {
		return failed
	}
	f, err := os.Open("/proc/" + strconv.FormatUint(uint64(key.TGID), 10) + "/cmdline")
	if err != nil {
		return failed
	}
	buf := make([]byte, collector.MaxArgBytes+1)
	n, err := io.ReadFull(f, buf)
	f.Close()
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return failed
	}
	if ok, err := sameInstance(key); err != nil || !ok {
		return failed
	}
	if n == 0 {
		return failed // kernel thread, zombie or an emptied argv: nothing provable
	}
	cut := n > collector.MaxArgBytes
	if cut {
		n = collector.MaxArgBytes
	}
	return collector.ParseArgs(buf[:n], cut, 0)
}
