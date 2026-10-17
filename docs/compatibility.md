# Compatibility note: tested kernels, architectures and functions

As of 2026-10-17. Everything below was actually executed; what was not executed is listed under
[Not tested](#not-tested).

## Summary

- The agent requires **Linux 5.15 or newer with BTF** (`/sys/kernel/btf/vmlinux`) on `amd64` or `arm64`, privileges
  for eBPF (root or `CAP_BPF` + `CAP_PERFMON`) and the **initial PID namespace**. Each of these requirements is
  checked at start; if one is missing, the agent exits with **exit code 3** and a concrete diagnosis. It never
  silently falls back to polling.
- The collector test suite (tests against the real kernel, no mocks) passes completely on **Linux 5.15, 6.8 and
  6.12**, each on **arm64 and amd64**, and on the **6.17 Azure kernel of the GitHub-hosted runners** (amd64 and arm64,
  see [acceptance.md](acceptance.md)). The kernels are unmodified distribution kernels.
- The systemd unit (`packaging/systemd/process-watcher.service`) passed its complete test (140 checks) under a real
  **systemd 249** as PID 1 on the same six kernel/architecture combinations; see [acceptance.md](acceptance.md). Other
  systemd versions were not tested.
- The finding that made this matrix necessary: the first version of the eBPF programs was **rejected** by the
  verifier of Linux 5.15, although it ran on 6.8 and 6.12. That is fixed (see
  [Verifier complexity](#verifier-complexity)); the suite has checked it on every kernel since.

## Tested environments

| ID | Kernel | Architecture | Environment | Role |
| --- | --- | --- | --- | --- |
| A | 6.12.54-linuxkit | arm64 | Docker Desktop VM on Apple silicon, privileged container with `--pid=host`; the kernel runs **natively** on the CPU | collector, agent end-to-end, load and latency measurements |
| B | Ubuntu 22.04 GA, `5.15.0-198.208` | arm64, amd64 | QEMU 10.0.13, **CPU emulation (TCG)**, real distribution kernel | minimum kernel |
| C | Ubuntu 24.04 GA, `6.8.0-147.147` | arm64, amd64 | QEMU TCG | middle kernel |
| D | Debian 13, `6.12.113-1` | arm64, amd64 | QEMU TCG | recent LTS kernel |
| E | Ubuntu 24.04 runner image, `6.17.0-1022-azure` | amd64, arm64 | GitHub-hosted runners (virtual machines on real CPUs, no emulation); the privileged tests run directly on the runner | newest kernel; the only runs on non-emulated amd64 |

The QEMU runs boot the kernel with an Ubuntu 22.04 userland and the `/init` of the test runner (`tests/vm/`); the
kernel decides about the verifier, CO-RE relocations against its BTF, tracepoint contexts and the JIT, only the CPU is
emulated. The kernel packages are pinned with version and SHA-256 in `tests/vm/kernels.txt`.

What the results mean: functional results (the verifier accepts the programs, events arrive, identities are right)
are real kernel behavior. **Timing, throughput and latency values from TCG runs are values of an emulated CPU** and
do not transfer to hardware; measurements therefore come from environment A only (see
[measurements.md](measurements.md)).

## Result of the collector test suite

Run with `make test-vm ARCH=<arm64|amd64> KERNEL=<ubuntu-5.15|ubuntu-6.8|debian-6.12>` or `make test-vm-matrix`; the
suite is `go test ./internal/collector/ebpf` as a static binary in the guest.

| Kernel | arm64 | amd64 |
| --- | --- | --- |
| Ubuntu 5.15.0-198 | 25 passed, 1 skipped (lockdown test) | 25 passed, 1 skipped (lockdown test) |
| Ubuntu 6.8.0-147 | 25 passed, 1 skipped (lockdown test) | 25 passed, 1 skipped (lockdown test) |
| Debian 6.12.113 | 25 passed, 1 skipped (lockdown test) | 25 passed, 1 skipped (lockdown test) |
| Docker VM 6.12.54 (native) | see [acceptance.md](acceptance.md) | not available |

What the suite checks against the real kernel (stage 1 of the build specification):

| Test | Checks |
| --- | --- |
| `TestSmokeSnapshot` | All programs load and attach; the BPF task iterator returns the own process with image, path and the same identity as the live table. |
| `TestShortLivedChild` | Fork, successful exec and exit of a child arrive **without any `/proc` access**: real image name, path, requested file name, parent image, arguments, exit status, times in order. |
| `TestArgsNotCapturedByDefault` | Without enabling it, the kernel side captures no arguments. |
| `TestForkWithoutExec` | `fork` and `clone3` without exec: own instance with a lifecycle. |
| `TestDoubleFork` | Orphaned grandchildren: the identity of the creator is kept. |
| `TestThreadsAreNotProcesses` | Fork from a worker thread, exec from a non-leader thread (identity stays), leader exits before the last thread: process end = last thread, no thread events as processes. |
| `TestRepeatedExecKeepsIdentity` | Repeated exec: the key stays, every message carries the new image. |
| `TestFailedExecIsNotReported` | A failed `execve` produces no exec event. |
| `TestImageIsTheExecutedFileNotArgv0` | Symlink and script with shebang: `image` is the executed file (interpreter), not `argv[0]`. |
| `TestDeletedAndFilelessExecutables` | Deleted programs and `memfd` programs are recognized as such. |
| `TestLongPathAndArgumentLimits` | Paths above the limit and more than 32 arguments or 4096 bytes are truncated and marked, never wrong. |
| `TestReusedPIDGetsANewIdentity` | Forced PID reuse (`ns_last_pid`): the keys differ through the start time. |
| `TestSnapshotAndLiveShareIdentity` | Snapshot identity and live identity of the same instance are equal. |
| `TestLossIsCountedInTheKernel` | Overflow of a tiny ring buffer: delivered plus kernel-counted lost records add up to the total. |
| `TestHookLatency` | Informational: time from the kernel event to `Next`. |
| `TestVerifierComplexity` | Loads every program in all four configurations and checks the number of instructions the verifier processed against a budget (see below). |
| `TestLockdownConfidentialityIsNamed`, `TestParseLockdown` | On a kernel with `lockdown=confidentiality` (`PW_VM_KARGS=lockdown=confidentiality`, see `tests/vm/README.md`) `Preflight` and `New` name the cause `kernel lockdown`; on all other kernels the test is skipped. Passed on Ubuntu 5.15/6.8 and Debian 6.12, each on arm64 and amd64. |
| `TestWireContract` and six `TestDecode*` | The wire format between C and Go matches the BTF of the object; broken records and snapshot streams are rejected. |

All tests that need processes start **their own test processes** (the test binary as a helper under `pwtest-*`
names); there are no shell helper processes in the measured path.

## Verifier complexity

Linux 5.15 has the least effective state pruning of the supported kernels. The first version of the programs failed
there on two things that went unnoticed on 6.8 and 6.12:

1. **Rejected pointer arithmetic.** The compiler turns `if (len > 255) len = 255;` into two comparisons; the 5.15
   verifier evaluates the impossible branch anyway and works there with a range `umin > umax`. A pointer plus such a
   scalar becomes an unknown scalar, and `bpf_probe_read_*` rejects it
   (`R1 type=inv expected=fp, pkt, ..., map_value`). The known bits of the contradictory range even survive masking
   with `&`.
2. **State explosion.** The path walk (32 unrolled iterations) was verified again for every state of the caller:
   817,206 processed instructions for the exec program at a kernel limit of 1,000,000.

Fixed by (1) `pw_bound()`/`pw_at()` for every length and every offset that enters pointer arithmetic or is used as a
helper size (a 4-byte round trip through the stack makes the verifier "forget" everything it knew; after that a plain
`[0, mask]` holds), and (2) the path walk as a **global function** (`pw_path_walk`) that the verifier checks once,
independent of its callers. Measured with `TestVerifierComplexity` (largest values per program over all four
configurations of `capture_args` and `live_table`):

| Program | Linux 5.15 | Linux 6.8 | Linux 6.12 | Kernel limit |
| --- | --- | --- | --- | --- |
| `sched_process_exec` | 20,968 (before: 817,206) | 8,237 | 8,175 | 1,000,000 |
| `iter/task` (snapshot) | 12,396 (before: 213,012) | 6,847 | 6,774 | 1,000,000 |
| `sched_process_fork` | 442 | 235 | 235 | 1,000,000 |
| `sched_process_exit` | 255 | 241 | 214 | 1,000,000 |

The values are the same on arm64 and amd64 because both load the same object. The test fails above 100,000
instructions per program, long before the kernel limit comes into view.

### Notes for changes to the eBPF programs

- Route every length/offset that enters pointer arithmetic or is used as a helper size through `pw_bound(x, mask)`
  or `pw_at(base, off, mask)`. A plain `& MASK` is not enough on 5.15, and the compiler removes it anyway when it
  considers the value bounded.
- Do not inline the path walk back into the programs, and put new heavy loops into a global function.
- After every change run `make generate` (reproducible in the container) and
  `make test-vm ARCH=arm64 KERNEL=ubuntu-5.15`; `TestVerifierComplexity` shows the instruction counts. A run on 6.x
  alone proves nothing for 5.15.

## What the agent checks at start

`process-watcher doctor` and every start check (sources: `internal/collector/ebpf/prereq_linux.go`,
`preflight_linux.go`):

| Check | On failure |
| --- | --- |
| Architecture `amd64`/`arm64` | exit code 3, `architecture` |
| Privileges: `CAP_SYS_ADMIN` or `CAP_BPF` + `CAP_PERFMON` | exit code 3, `privileges`, with a hint about sudo/service capabilities |
| Initial PID namespace (`NSpid`) | exit code 3, `pid namespace` (running in a container is refused) |
| Kernel BTF present | exit code 3, `kernel BTF` (`CONFIG_DEBUG_INFO_BTF=y` needed) |
| All types, fields and tracepoints used, in the BTF: `task_struct`, `signal_struct`, `mm_struct`, `cred`, `file`, `path`, `dentry`, `qstr`, `vfsmount`, `mount`, `linux_binprm`, `bpf_iter__task` and `btf_trace_sched_process_{fork,exec,exit}` | exit code 3, the concrete missing member |
| The verifier accepts the programs | exit code 3, `eBPF verifier`, with the verifier log |
| `RLIMIT_MEMLOCK` can be raised | exit code 3, `memlock` |
| Kernel lockdown `confidentiality` | exit code 3, `kernel lockdown` (BPF may not read kernel memory; without this check the kernel only says "unknown func bpf_probe_read"). Tested on all six combinations with `lockdown=confidentiality` (see above); `doctor` shows it as well |
| with `--kill-enabled`: `pidfd_open`, `pidfd_send_signal` | exit code 3 |

Kernel functions used and their minimum versions: `tp_btf` raw tracepoints and BPF-to-BPF calls with global
functions (5.5), `bpf_probe_read_kernel*` (5.5), ring buffer, `bpf_ktime_get_boot_ns`, task iterators,
`bpf_seq_write` and `CAP_BPF`/`CAP_PERFMON` (5.8), `pidfd_open` (5.3), `pidfd_send_signal` (5.1). The structure
offsets come from CO-RE relocations against the BTF of the running kernel, not from kernel headers.

## Not tested

- **Dedicated amd64 hardware.** Locally amd64 ran only under QEMU emulation (the Docker host is an arm64 Mac without
  KVM): a real amd64 kernel on an emulated CPU, so timing values are worthless there. The GitHub-hosted amd64 runners
  (virtual machines, kernel 6.17) ran the functional suites on real CPUs; no timing or load measurements were taken on
  them.
- **Other kernel versions and vendors** than 5.15.0-198 (Ubuntu), 6.8.0-147 (Ubuntu), 6.12.113 (Debian) and
  6.12.54-linuxkit. In particular not: RHEL/Alma/Rocky (4.18/5.14/6.x with backports), SLES, Amazon Linux, Android and
  all kernels between the tested versions. Kernels with other configurations (for example `PREEMPT_RT`, other
  lockdown modes) were not booted.
- **Other 5.15 stable releases.** Verifier behavior can change between backports; the test `TestVerifierComplexity`
  and its budget are meant to show that quickly on the target kernel: `make test-vm` or
  `go test -run TestVerifierComplexity -v ./internal/collector/ebpf` as root on the target.
- **systemd versions other than 249** (Ubuntu 22.04). Newer versions are expected to accept the unit, but that was not
  run; `systemd-analyze verify` and a start under the unit are the first checks there.
- Kernels without BTF, kernels older than 5.15, 32-bit systems, big-endian and other architectures (`riscv64`,
  `s390x`, `ppc64le`) are not supported and were not tested; the agent refuses them.
- Completeness under arbitrary load is not proven: when the ring buffer overflows the kernel loses records (counted,
  reported as `agent.gap`). The measured limit is in [measurements.md](measurements.md).
