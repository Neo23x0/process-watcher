//go:build linux

package app

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/Neo23x0/process-watcher/internal/collector"
	"github.com/Neo23x0/process-watcher/internal/collector/ebpf"
	"github.com/Neo23x0/process-watcher/internal/config"
	"github.com/Neo23x0/process-watcher/internal/response"
)

// Linux capabilities that matter.
const (
	capKill     = 5
	capSysAdmin = 21
	capPerfmon  = 38
	capBPF      = 39
)

// Doctor checks the platform, the permissions and the kernel features the
// collector needs, loads the programs for real and observes a short-lived
// child process of its own. It never signals anything but its own probe.
func Doctor(r *config.Resolved, version string, w io.Writer) int {
	var checks []Check
	add := func(name string, st Status, format string, args ...any) {
		checks = append(checks, Check{name, st, fmt.Sprintf(format, args...)})
	}

	add("process-watcher", StatusOK, "%s (%s/%s, %s)", version, runtime.GOOS, runtime.GOARCH, runtime.Version())
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		add("architecture", StatusFail, "unsupported architecture %s; linux/amd64 and linux/arm64 are supported", runtime.GOARCH)
		return report(w, checks)
	}
	add("architecture", StatusOK, "%s", runtime.GOARCH)

	var uts unix.Utsname
	rel := ""
	if unix.Uname(&uts) == nil {
		rel = unix.ByteSliceToString(uts.Release[:])
	}
	major, minor := parseKernel(rel)
	switch {
	case major == 0:
		add("kernel", StatusWarn, "cannot parse the kernel release %q; the feature checks below decide", rel)
	case major < 5 || (major == 5 && minor < 15):
		add("kernel", StatusWarn, "%s is older than 5.15, the tested minimum; the feature checks below decide", rel)
	default:
		add("kernel", StatusOK, "%s", rel)
	}

	priv := privilegeChecks(r.Config.Kill.Enabled)
	checks = append(checks, priv...)
	for _, c := range priv {
		if c.Status == StatusFail {
			add("collector", StatusWarn, "not tried: fix the privileges first")
			return report(w, checks)
		}
	}

	if mode := ebpf.LockdownMode(); mode == "confidentiality" {
		add("kernel lockdown", StatusFail, "lockdown is in confidentiality mode: eBPF programs may not read kernel memory (see /sys/kernel/security/lockdown)")
	} else if mode != "" {
		add("kernel lockdown", StatusOK, "mode %s", mode)
	}
	if v, ok := sysctl("kernel/unprivileged_bpf_disabled"); ok {
		add("sysctl", StatusOK, "kernel.unprivileged_bpf_disabled=%s (root is used)", v)
	}

	// The collector itself: BTF, attach, a real observation.
	col, err := ebpf.New(collector.Options{RingBufferBytes: 1 << 20, CaptureArgs: r.Config.Capture.Argv, ArgLimits: collector.ArgLimits{MaxArgs: r.Config.Capture.ArgvMaxArgs, MaxBytes: r.Config.Capture.ArgvMaxBytes}, LiveTable: r.Config.Kill.Enabled})
	if err != nil {
		var pe *collector.PrerequisiteError
		if errors.As(err, &pe) {
			add(pe.Check, StatusFail, "%s", firstLines(pe.Error(), 12))
		} else {
			add("collector", StatusFail, "%v", err)
		}
		return report(w, checks)
	}
	defer col.Close()
	add("kernel BTF", StatusOK, "all required types and members found")
	add("collector", StatusOK, "programs loaded and attached (tp_btf fork/exec/exit, task iterator, ring buffer)")
	checks = append(checks, selfTest(col)...)

	if r.Config.Kill.Enabled {
		if err := response.CheckSupport(); err != nil {
			add("pidfd", StatusFail, "%v", err)
		} else {
			add("pidfd", StatusOK, "pidfd_open and pidfd_send_signal work (kill.enabled)")
		}
	} else {
		add("pidfd", StatusOK, "not needed (kill.enabled is false)")
	}
	return report(w, checks)
}

func selfTest(col *ebpf.Collector) []Check {
	var out []Check
	add := func(name string, st Status, format string, args ...any) {
		out = append(out, Check{name, st, fmt.Sprintf(format, args...)})
	}
	exe, err := os.Executable()
	if err != nil {
		return append(out, Check{"self test", StatusFail, fmt.Sprintf("cannot find the own binary: %v", err)})
	}
	cmd := exec.Command(exe, "--version")
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if err := cmd.Run(); err != nil {
		return append(out, Check{"self test", StatusFail, fmt.Sprintf("cannot start the probe child: %v", err)})
	}
	child := uint32(cmd.ProcessState.Pid())
	want := map[collector.Kind]bool{}
	var execImage, execPath string
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && len(want) < 3 {
		ev, err := col.Next(time.Now().Add(200 * time.Millisecond))
		if err != nil {
			continue
		}
		if ev.Proc.TGID != child {
			continue
		}
		want[ev.Kind] = true
		if ev.Kind == collector.KindExec {
			execImage, execPath = ev.Exec.Image, ev.Exec.Path.Value
		}
	}
	for _, k := range []collector.Kind{collector.KindFork, collector.KindExec, collector.KindExit} {
		if !want[k] {
			add("self test", StatusFail, "no %s record arrived for the probe child (pid %d)", k, child)
			return out
		}
	}
	real, _ := filepath.EvalSymlinks(exe)
	switch {
	case execImage == "" || execPath == "":
		add("image capture", StatusFail, "the kernel did not deliver the executed file name or path")
	case execImage != filepath.Base(real):
		add("image capture", StatusWarn, "kernel image %q differs from the expected %q", execImage, filepath.Base(real))
	default:
		add("image capture", StatusOK, "executed file %q at %s", execImage, execPath)
	}
	add("self test", StatusOK, "fork, exec and exit of a probe child were observed without /proc")

	snap, err := col.Snapshot()
	switch {
	case err != nil:
		add("snapshot", StatusFail, "task iterator failed: %v", err)
	default:
		self := uint32(os.Getpid())
		found := false
		for _, p := range snap.Procs {
			if p.Key.TGID == self {
				found = true
			}
		}
		if !found {
			add("snapshot", StatusFail, "the snapshot does not list this process (%d of %d processes read)", len(snap.Procs), len(snap.Procs))
		} else {
			add("snapshot", StatusOK, "task iterator lists %d living processes with kernel start times", len(snap.Procs))
		}
	}
	if st, err := col.Stats(); err == nil && st.Lost() > 0 {
		add("kernel counters", StatusWarn, "%d records were lost during the self test", st.Lost())
	}
	return out
}

// privilegeChecks inspects the effective capabilities.
func privilegeChecks(kill bool) []Check {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return []Check{{"privileges", StatusWarn, fmt.Sprintf("cannot read capabilities: %v", err)}}
	}
	has := func(c int) bool { return data[c/32].Effective&(1<<(uint(c)%32)) != 0 }
	return privilegeChecksFor(os.Geteuid(), has, kill)
}

// privilegeChecksFor judges the effective capability set. Root alone proves
// nothing: a restricted CapabilityBoundingSet or a container drops capabilities
// from root, and the kernel checks CAP_KILL even for root when a signal goes to
// a process of another user.
func privilegeChecksFor(euid int, has func(capability int) bool, kill bool) []Check {
	var out []Check
	switch {
	case has(capSysAdmin) || (has(capBPF) && has(capPerfmon)):
		out = append(out, Check{"privileges", StatusOK, fmt.Sprintf("euid %d with CAP_BPF/CAP_PERFMON or CAP_SYS_ADMIN", euid)})
	case euid == 0:
		out = append(out, Check{"privileges", StatusFail, "running as root but without CAP_BPF+CAP_PERFMON (or CAP_SYS_ADMIN): a restricted capability set or a container drops them"})
	default:
		out = append(out, Check{"privileges", StatusFail, "loading eBPF programs needs root (or CAP_BPF and CAP_PERFMON); run with sudo"})
	}
	if kill {
		if has(capKill) {
			out = append(out, Check{"CAP_KILL", StatusOK, "CAP_KILL is effective: signals to processes of other users are permitted"})
		} else {
			out = append(out, Check{"CAP_KILL", StatusWarn, "CAP_KILL is not in the effective capability set (root alone is not enough; a restricted CapabilityBoundingSet or a container drops it): the kill feature cannot signal processes of other users"})
		}
	}
	return out
}

func sysctl(name string) (string, bool) {
	b, err := os.ReadFile("/proc/sys/" + name)
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(b)), true
}

func parseKernel(rel string) (major, minor int) {
	parts := strings.SplitN(rel, ".", 3)
	if len(parts) < 2 {
		return 0, 0
	}
	major, _ = strconv.Atoi(parts[0])
	digits := parts[1]
	for i, c := range digits {
		if c < '0' || c > '9' {
			digits = digits[:i]
			break
		}
	}
	minor, _ = strconv.Atoi(digits)
	return major, minor
}

func firstLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = append(lines[:n], fmt.Sprintf("... (%d more lines)", len(lines)-n))
	}
	return strings.Join(lines, "\n                              ")
}
