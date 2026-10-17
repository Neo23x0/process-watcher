//go:build linux

package ebpf

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"golang.org/x/sys/unix"

	"github.com/Neo23x0/process-watcher/internal/collector"
)

// requiredFields lists the kernel BTF members the programs read through
// CO-RE. A missing member means the kernel is too different from the tested
// ones; the check turns an obscure relocation error into a concrete message.
var requiredFields = []struct {
	typ    string
	fields []string
}{
	{"task_struct", []string{"flags", "mm", "exit_code", "pid", "tgid", "real_parent", "group_leader", "start_boottime", "cred", "comm", "signal"}},
	{"signal_struct", []string{"live", "flags", "group_exit_code"}},
	{"mm_struct", []string{"arg_start", "arg_end", "exe_file"}},
	{"cred", []string{"uid", "gid", "euid"}},
	{"file", []string{"f_path"}},
	{"path", []string{"mnt", "dentry"}},
	{"dentry", []string{"d_hash", "d_parent", "d_name"}},
	{"qstr", []string{"len", "name"}},
	{"vfsmount", []string{"mnt_root"}},
	{"mount", []string{"mnt_parent", "mnt_mountpoint", "mnt"}},
	{"linux_binprm", []string{"file", "filename", "argc"}},
	{"bpf_iter__task", []string{"meta", "task"}},
}

// requiredTracepoints are the BTF typedefs of the raw tracepoints that tp_btf
// programs attach to.
var requiredTracepoints = []string{
	"btf_trace_sched_process_fork",
	"btf_trace_sched_process_exec",
	"btf_trace_sched_process_exit",
}

// checkEnvironment verifies platform properties that cannot be fixed by the
// kernel configuration: architecture and the initial PID namespace.
func checkEnvironment() error {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		return &collector.PrerequisiteError{
			Check:  "architecture",
			Detail: fmt.Sprintf("unsupported architecture %s; supported are linux/amd64 and linux/arm64", runtime.GOARCH),
		}
	}
	if err := checkPrivileges(); err != nil {
		return err
	}
	if LockdownMode() == "confidentiality" {
		return lockdownError()
	}
	nested, err := inNestedPIDNamespace()
	if err != nil {
		return &collector.PrerequisiteError{Check: "pid namespace", Detail: "cannot read /proc/self/status", Err: err}
	}
	if nested {
		return &collector.PrerequisiteError{
			Check: "pid namespace",
			Detail: "running inside a child PID namespace (container?); the agent must run in the initial PID namespace " +
				"so that every process id is a host id (for a container use --pid=host, but prefer running on the host)",
		}
	}
	return nil
}

// LockdownMode returns the kernel lockdown mode ("none", "integrity" or
// "confidentiality") or "" when the kernel has no lockdown.
func LockdownMode() string {
	b, err := os.ReadFile("/sys/kernel/security/lockdown")
	if err != nil {
		return ""
	}
	return parseLockdown(string(b))
}

// parseLockdown extracts the active mode, the bracketed word, from the
// content of /sys/kernel/security/lockdown ("none [integrity] confidentiality").
func parseLockdown(text string) string {
	if i := strings.Index(text, "["); i >= 0 {
		if j := strings.Index(text[i:], "]"); j > 0 {
			return text[i+1 : i+j]
		}
	}
	return ""
}

// lockdownError is the diagnosis for lockdown mode "confidentiality": the
// kernel then refuses the helpers that read kernel memory, which the kernel
// reports as an unknown function when the program is loaded.
func lockdownError() error {
	return &collector.PrerequisiteError{
		Check: "kernel lockdown",
		Detail: "the kernel is in lockdown mode confidentiality (/sys/kernel/security/lockdown): eBPF programs may not " +
			"read kernel memory, so process-watcher cannot observe processes; boot without lockdown=confidentiality " +
			"(or switch the Secure Boot lockdown policy to integrity) to run it",
	}
}

// Linux capabilities that allow loading and attaching the programs.
const (
	capSysAdmin = 21
	capPerfmon  = 38
	capBPF      = 39
)

// checkPrivileges verifies the effective capabilities up front: without them
// the kernel reports unrelated errors ("BTF not supported") that would hide
// the real cause.
func checkPrivileges() error {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return nil // cannot tell; loading will decide
	}
	has := func(c int) bool { return data[c/32].Effective&(1<<(uint(c)%32)) != 0 }
	if has(capSysAdmin) || (has(capBPF) && has(capPerfmon)) {
		return nil
	}
	return &collector.PrerequisiteError{
		Check: "privileges",
		Detail: "loading eBPF programs needs root, or CAP_BPF and CAP_PERFMON (CAP_SYS_ADMIN also works); " +
			"run process-watcher as root, for example with sudo, or from a service that grants these capabilities",
	}
}

// inNestedPIDNamespace reports whether the process lives in a PID namespace
// other than the initial one: NSpid then lists more than one id.
func inNestedPIDNamespace() (bool, error) {
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return false, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if rest, ok := strings.CutPrefix(sc.Text(), "NSpid:"); ok {
			return len(strings.Fields(rest)) > 1, nil
		}
	}
	return false, sc.Err() // kernels without NSpid have no PID namespaces either
}

// checkKernelBTF loads the kernel's BTF and verifies that every type, member
// and tracepoint the programs rely on exists.
func checkKernelBTF() error {
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		return &collector.PrerequisiteError{
			Check: "kernel BTF",
			Detail: "the kernel exposes no BTF (/sys/kernel/btf/vmlinux); CO-RE programs need " +
				"CONFIG_DEBUG_INFO_BTF=y (Linux 5.15 or newer with BTF)",
			Err: err,
		}
	}
	for _, rf := range requiredFields {
		var st *btf.Struct
		if err := spec.TypeByName(rf.typ, &st); err != nil {
			return &collector.PrerequisiteError{
				Check:  "kernel BTF",
				Detail: fmt.Sprintf("kernel type struct %s not found in BTF", rf.typ),
				Err:    err,
			}
		}
		for _, f := range rf.fields {
			if !hasMember(st, f) {
				return &collector.PrerequisiteError{
					Check:  "kernel BTF",
					Detail: fmt.Sprintf("kernel struct %s has no member %q; this kernel is not supported", rf.typ, f),
				}
			}
		}
	}
	for _, tp := range requiredTracepoints {
		var td *btf.Typedef
		if err := spec.TypeByName(tp, &td); err != nil {
			return &collector.PrerequisiteError{
				Check:  "tracepoint",
				Detail: fmt.Sprintf("raw tracepoint type %s not in BTF; tp_btf programs cannot attach", tp),
				Err:    err,
			}
		}
	}
	return nil
}

// hasMember looks for a member by name, descending into anonymous
// structs and unions like the kernel's CO-RE matching does.
func hasMember(t btf.Type, name string) bool {
	var members []btf.Member
	switch s := btf.UnderlyingType(t).(type) {
	case *btf.Struct:
		members = s.Members
	case *btf.Union:
		members = s.Members
	default:
		return false
	}
	for _, m := range members {
		if m.Name == name || (m.Name == "" && hasMember(m.Type, name)) {
			return true
		}
	}
	return false
}

// classifyLoadError turns low level load/attach errors into a diagnosis.
func classifyLoadError(err error) error {
	var verr *cebpf.VerifierError
	switch {
	case errors.As(err, &verr):
		if LockdownMode() == "confidentiality" {
			return lockdownError()
		}
		return &collector.PrerequisiteError{
			Check: "eBPF verifier",
			Detail: "the kernel verifier rejected the collector program; please report this kernel " +
				"version together with the log below\n" + fmt.Sprintf("%+v", verr),
			Err: err,
		}
	case errors.Is(err, unix.EPERM):
		return &collector.PrerequisiteError{
			Check: "permissions",
			Detail: "operation not permitted: loading eBPF needs root or CAP_BPF+CAP_PERFMON (CAP_SYS_ADMIN on " +
				"kernels before 5.8); also check kernel.unprivileged_bpf_disabled, an LSM or a lockdown mode " +
				"(/sys/kernel/security/lockdown) that forbids reading kernel memory from BPF",
			Err: err,
		}
	case errors.Is(err, unix.ENOSYS), errors.Is(err, cebpf.ErrNotSupported):
		return &collector.PrerequisiteError{
			Check:  "kernel features",
			Detail: "the kernel lacks a required eBPF feature (BPF syscall, ring buffer, tp_btf or task iterators)",
			Err:    err,
		}
	}
	return err
}
