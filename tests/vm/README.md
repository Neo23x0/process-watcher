# Running tests in a real Linux kernel (QEMU)

`tests/vm/run.sh` boots a real Linux kernel of a chosen version and architecture
in QEMU, runs a static test binary in it as root, streams the VM console to
stdout and exits with the exit status of the binary.

It exists because the eBPF collector's behaviour depends on the kernel: the BPF
verifier, CO-RE relocations against the kernel's BTF, the tracepoint context
layouts and the BPF JIT differ between versions and architectures. A Docker
Desktop VM offers exactly one kernel and one architecture, and a cross-build
does not run anything. Here the kernel is the unmodified distribution kernel;
only the CPU is emulated.

## Quick start

```sh
# 1. build the static test binary for the guest architecture
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go test -c -o /tmp/ebpf-arm64.test ./internal/collector/ebpf

# 2. run it in a VM (arguments after the binary go to the binary)
tests/vm/run.sh arm64 ubuntu-5.15 /tmp/ebpf-arm64.test -test.v -test.timeout 600s

# one test only, on the other architecture and a newer kernel
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c -o /tmp/ebpf-amd64.test ./internal/collector/ebpf
tests/vm/run.sh amd64 debian-6.12 /tmp/ebpf-amd64.test -test.v -test.run TestShortLivedChild
```

The only requirement on the Mac is Docker (Desktop). There is no QEMU on the
host: QEMU runs inside a container built from `tests/vm/Dockerfile`. The first
run builds the tool image and downloads the kernel and the Ubuntu root file
system (about 40 s with an Ubuntu kernel); later runs reuse the caches and a
VM boots, runs a trivial test and powers off in 3 to 7 s.

```
tests/vm/run.sh <arch> <kernel-id> <test-binary> [args for the binary...]
tests/vm/run.sh --list
```

`arch` is `arm64` or `amd64`. `kernel-id` is a row of `kernels.txt`. The test
binary must be an ELF executable of the guest architecture (checked before
anything is booted). The arguments are passed to the binary unchanged, whatever
characters they contain.

## Result and exit status

The VM console goes to **stdout**, the script's own messages (`PW-VM: ...`) to
stderr. The guest's `/init` prints `PW-VM-START` right before it starts the
binary and `PW-VM-EXIT=<status>` right after it ended, then powers the VM off;
the script parses the last `PW-VM-EXIT=` line from the console. The final
stderr line summarises the outcome and the time spent.

| exit status | meaning |
| --- | --- |
| 0-123, 126-255 | the exit status of the test binary (`go test` binaries: 0 ok, 1 test failure, 2 usage error or `-test.timeout` panic) |
| 124 | timeout: no result within `PW_VM_TIMEOUT` seconds (default 900); the VM was killed; message `TIMEOUT` |
| 125 | VM or tooling failure: kernel panic (message `KERNEL PANIC`), VM ended without an exit marker, download/checksum/build problem, Docker not running |
| 64 | usage error: unknown arch or kernel id, missing binary, binary of the wrong architecture |

A binary that itself exits with 124 or 125 is indistinguishable by status alone;
the `PW-VM:` messages on stderr tell the cases apart. The full console of the
last run of each combination is kept in `cache/logs/<arch>-<kernel-id>.log`
(`PW_VM_LOG` overrides the path).

## Kernels

`kernels.txt` is the table. Each row pins one kernel package by exact version,
URL and SHA-256; the download is refused if the checksum differs. The checksums
were taken from the signed archive indexes (the `InRelease` signature checked
against the distribution keyring) with `container/resolve-kernel.sh`.

| kernel-id | package (both architectures) | source | notes |
| --- | --- | --- | --- |
| `ubuntu-5.15` | `linux-image-5.15.0-198-generic` 5.15.0-198.208 | `archive.ubuntu.com` (amd64), `ports.ubuntu.com` (arm64), jammy | oldest supported kernel; GA kernel of Ubuntu 22.04 |
| `ubuntu-6.8` | `linux-image-6.8.0-147-generic` 6.8.0-147.147 | same mirrors, noble | GA kernel of Ubuntu 24.04 |
| `debian-6.12` | `linux-image-6.12.113+deb13-{amd64,arm64}` 6.12.113-1 | `snapshot.debian.org` (security archive), trixie | upstream long-term-support series 6.12 |

Only the kernel image is used (`/boot/vmlinuz-*` out of the `.deb`); no modules
are loaded. These kernels have the console drivers, initramfs, devtmpfs, tracefs,
BPF and BTF built in, so nothing else is needed. The Ubuntu arm64 image is a
gzip-compressed `Image`; it is decompressed once at fetch time.

Build configuration of the pinned kernels (from the matching `linux-buildinfo`
package, or `/boot/config-*` for Debian; the guest prints the same facts at the
top of every run, because none of these kernels exports `/proc/config.gz`):

| kernel (both architectures unless noted) | `CONFIG_HZ` | `BPF_JIT` | `BPF_JIT_ALWAYS_ON` | `DEBUG_INFO_BTF` | `BPF_EVENTS` | preemption | tick |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `ubuntu-5.15` | 250 | y | y | y | y | voluntary | `NO_HZ_IDLE` |
| `ubuntu-6.8` | 1000 | y | y | y | y | voluntary, dynamic | `NO_HZ_FULL` |
| `debian-6.12` | 250 | y | n (JIT on by default) | y | y | voluntary (dynamic on amd64 only) | `NO_HZ_FULL` |

`CONFIG_IKCONFIG` is not set in any of them. The arm64 kernels have 4 KiB pages
and `ARM64_PTR_AUTH_KERNEL=y`.

Every guest also shows: `/sys/kernel/btf/vmlinux` present (4.9 to 7.0 MB),
`net.core.bpf_jit_enable=1`, `net.core.bpf_jit_harden=0`,
`kernel.unprivileged_bpf_disabled=2`, `kernel.kptr_restrict=0`, and the
`sched_process_fork/exec/exit` tracepoints in tracefs.

To add or move a kernel: look up the package with
`docker run --rm -v "$PWD/tests/vm:/vm:ro" <tool-image> /vm/container/resolve-kernel.sh <ubuntu|debian> <suite> <arch> '<package-regex>'`
(it verifies the signature chain and prints version, size, SHA-256 and URL),
put the URL and SHA-256 into `kernels.txt` and run. A changed checksum
invalidates the cached entry by itself. Ubuntu keeps old kernel ABIs in its
pool for years; for Debian use a `snapshot.debian.org` URL as in the table.

## How it works

1. **Tool image** `pw-vm-qemu:<12 hex digits of the Dockerfile's SHA-256>`:
   Debian 13 (trixie) with QEMU 10.0.13 (`qemu-system-aarch64`,
   `qemu-system-x86_64`) and the tools that fetch kernels and pack initramfs
   archives. Base image pinned by digest, packages from a dated
   `snapshot.debian.org` over HTTPS, QEMU version pinned explicitly. Rebuilt
   only when the Dockerfile changes.
2. **Kernel** (`container/fetch-kernel.sh`): download over HTTPS, verify the
   SHA-256, extract only the kernel image (and the build config), cache under
   `cache/kernels/<arch>/<kernel-id>/`.
3. **Userland** (`container/build-rootfs.sh`): `docker export` of the official
   `ubuntu:22.04` image of the guest architecture (pinned by manifest digest)
   turned into a gzip-compressed cpio archive, once per architecture. This is
   a real distribution userland: GNU coreutils (`/bin/true` is the regular file
   `/usr/bin/true`), dash, bash, glibc, util-linux; `/bin` is a symlink to
   `usr/bin` as on a normal Ubuntu. Only `/dev/console` and `/dev/null` are
   added, which the kernel needs before it can run `/init`.
4. **Per-run overlay** (`container/boot.sh`): a tiny second cpio archive with
   `guest/init`, the test binary under `/pwtest/` and a generated
   `/pwtest/env.sh` that holds the quoted arguments. The kernel unpacks both
   archives into its initramfs; there is no disk image.
5. **Boot**: `qemu-system-<arch> -kernel vmlinuz -initrd ... -nodefaults
   -display none -serial stdio -no-reboot` with a kernel command line of
   `console=ttyAMA0|ttyS0 rdinit=/init panic=-1 oops=panic loglevel=4`. The
   serial console is the only device. A kernel panic or oops resets the
   machine, which `-no-reboot` turns into QEMU exiting, so a crashed guest does
   not hang until the timeout.
6. **`/init`** (`guest/init`, dash): mounts proc, sysfs, devtmpfs, devpts, tmpfs
   on `/dev/shm`, `/tmp` and `/run`, and debugfs, tracefs, bpffs, cgroup2 and
   securityfs where the kernel has them and brings the loopback interface up
   (127.0.0.1, ::1); prints kernel version, CPUs, memory, BTF presence, the
   lockdown mode, BPF sysctls and the kernel config facts; sets `ulimit -l
   unlimited`; runs the binary as root (PID namespace: the initial one, the
   binary is a child of PID 1); prints `PW-VM-EXIT=<status>`; powers off with
   the sysrq trigger (`o`, then `b`). After a failed run it also prints the
   kernel's warning-level messages.

Power off was verified to end QEMU on both architectures (ACPI on x86, PSCI on
arm64). If the guest ever failed to power off, the exit marker is still used
and the global timeout ends the VM.

## Kernel lockdown

A kernel in lockdown mode `confidentiality` refuses the BPF helpers that read
kernel memory, so the collector cannot load. `TestLockdownConfidentialityIsNamed`
checks that the agent then names the cause (`kernel lockdown`) instead of
blaming the verifier; it skips on every other kernel. Run it on a locked-down
guest with

```sh
PW_VM_KARGS=lockdown=confidentiality tests/vm/run.sh arm64 ubuntu-6.8 dist/vm/collector-arm64.test \
    -test.v -test.run 'TestLockdown|TestParseLockdown'
```

(all other collector tests fail on such a kernel by design).

## Environment variables

| variable | default | meaning |
| --- | --- | --- |
| `PW_VM_TIMEOUT` | `900` | seconds the whole VM may run (boot, tests, power off) |
| `PW_VM_SMP` | `4` | virtual CPUs |
| `PW_VM_MEM` | `2048` | guest RAM in MiB |
| `PW_VM_KARGS` | | extra kernel command line words (e.g. `loglevel=7`; `lockdown=confidentiality` boots a locked-down kernel, see below) |
| `PW_VM_ENV` | | blank-separated `NAME=value` pairs exported to the binary (no blanks in values) |
| `PW_VM_AGENT` | | path of a second binary (the `process-watcher` agent) staged as `/pwtest/process-watcher`, for end-to-end tests that start it; combine with `PW_VM_ENV=PW_AGENT_BIN=/pwtest/process-watcher` |
| `PW_VM_CPU` | arm64 `max,pauth=off`, amd64 `max` | QEMU `-cpu` (see Known limits for why not `cortex-a72`) |
| `PW_VM_QEMU_EXTRA` | | extra QEMU arguments, split at blanks |
| `PW_VM_KVM` | `auto` | `auto` uses `/dev/kvm` when the Docker VM has it and the guest has the host's architecture, `0` never, `1` required |
| `PW_VM_CACHE` | `tests/vm/cache` | cache directory (must be a path Docker can bind-mount) |
| `PW_VM_LOG` | `cache/logs/<arch>-<kernel-id>.log` | where the console log is written |

## Caches

Everything below `tests/vm/cache/` is ignored by git (`cache/.gitignore`).

| what | where | invalidated by |
| --- | --- | --- |
| tool image | Docker image `pw-vm-qemu:<hash>` | a change of `Dockerfile` |
| kernels | `cache/kernels/<arch>/<kernel-id>/{vmlinuz,config,stamp}` | a changed checksum in `kernels.txt` |
| root file systems | `cache/rootfs/ubuntu-22.04-<arch>-<digest>.cpio.gz` | a changed image digest in `run.sh` |
| console logs | `cache/logs/` | overwritten by the next run of the same combination |
| staged binary | `cache/stage.<pid>/` | removed when the run ends |

The Ubuntu base images stay in Docker's image store (`docker image ls ubuntu`).
Delete a cache entry to force a rebuild; old `pw-vm-qemu:*` tags can be removed
with `docker image rm`.

## Timing

Measured on an Apple M5 Pro Mac, Docker Desktop with 12 CPUs and 8 GB, VMs
with 4 vCPUs and 2 GiB, QEMU 10.0.13 under TCG, with the collector tests of
this repository (`./internal/collector/ebpf`: 24 tests and 24 subtests, of
which the 8 wire/decoder tests need no kernel). Wall-clock seconds, single
runs, expect a spread of about 15 percent. The full test runs were made three
VMs at a time (all arm64 kernels, then all amd64 kernels); the boot and
trivial-test columns were measured one VM at a time.

One-time costs: tool image build 20 s (no cache), kernel package download
7 to 18 s for the Ubuntu kernels and 45 s for the 100 MB Debian packages,
root file system 6 to 8 s per architecture (plus pulling the Ubuntu image).
A complete cold start with an Ubuntu kernel, tool image already built, took
17 s including the first VM.

| guest | kernel | reaches `/init` (guest uptime) | boot, trivial test, power off | complete test binary | `run.sh` total | result |
| --- | --- | --- | --- | --- | --- | --- |
| arm64 | `ubuntu-5.15` | 1.7 s | 4 s | 31 s | 38 s | 24 tests, 24 subtests pass |
| arm64 | `ubuntu-6.8` | 1.7 s | 4 s | 35 s | 43 s | pass |
| arm64 | `debian-6.12` | 1.4 s | 3 s | 31 s | 37 s | pass |
| amd64 | `ubuntu-5.15` | 4.1 s | 6 s | 32 s | 40 s | pass |
| amd64 | `ubuntu-6.8` | 4.5 s | 7 s | 36 s | 44 s | pass |
| amd64 | `debian-6.12` | 4.4 s | 6 s | 42 s | 50 s | pass |

A single test such as `TestSmokeSnapshot` (load the BPF programs, attach, take
a snapshot) takes 0.07 s on the native 6.12.54 kernel of the Docker VM and 0.9
to 1.4 s under TCG on all six guests; `-test.run` it for a quick check.

## systemd mode (`run-systemd.sh`)

`tests/vm/run-systemd.sh <arch> <kernel-id> <agent-binary> [scenario...]` (or
`make test-vm-systemd ARCH=arm64 KERNEL=ubuntu-5.15 [SCENARIOS="S3 S4"]`, which builds the
agent first) boots the same kernels with **systemd 249 as PID 1** and runs the unit
`packaging/systemd/process-watcher.service` in it exactly as a user installs it
(`packaging/install.sh`). The plain mode above is unchanged and does not use any of this.

- Guest: the pinned Ubuntu 22.04 image plus systemd 249.11-0ubuntu3.22, jq, kmod, procps,
  libcap2-bin from a dated `snapshot.ubuntu.com` snapshot over HTTPS (`Dockerfile.systemd`,
  built per architecture with `docker build --platform`, exported by `build-rootfs.sh`,
  cached as `cache/rootfs/ubuntu-22.04-systemd-<arch>-<hash>.cpio.gz`; the hash covers the
  Dockerfile and the base image). `guest/init-systemd` (dash) mounts /proc, /sys, /dev and
  `exec`s systemd; the initramfs is the root file system, and systemd's mount-namespace and
  seccomp sandboxing work on it (the test proves it). No dbus (so no `systemd-run`: the test
  writes probe units), no udev, no network, no getty.
- `guest/pw-vm-test.service` runs `guest/systemd-test.sh` after multi-user.target. It prints
  `PW-SYSTEMD: PASS|FAIL|INFO|WARN ...` lines (evidence lines start with `PW-SYSTEMD:   |`)
  and finally `PW-VM-EXIT=<number of failed checks>`; `run-systemd.sh` exits with that number
  (124 timeout, 125 VM failure, 64 usage as in `run.sh`). Log: `cache/logs/<arch>-<kernel>-systemd.log`.
- Scenarios: S1 `systemd-analyze verify` and `security`; S2 `install.sh`, modes, `doctor`;
  S3 start, capabilities, log directory; S4 observation under the hardened unit (root,
  descendants, other users, programs below /root, snapshot of pre-existing processes, no loss);
  S5 kill feature, then without CAP_KILL; S6 clean stop; S7a bad configuration, S7b log path
  outside `LogsDirectory`, S7c SIGKILL, S7d missing privileges; S8 every hardening directive
  in effect (probe units, `nsenter` into the agent's mount namespace) and compatible.
  S2 always runs. Under TCG a complete run takes about 3.5 minutes of wall time per kernel/architecture
  combination (196 to 222 s with three runs in parallel; S7 alone spends about 2 minutes on restart
  measurements).
- Environment variables are those of `run.sh`, except `PW_VM_TIMEOUT` defaults to 1800 s;
  `PW_VM_ENV=PW_TIME_SCALE=2` multiplies the guest's wait limits.
- Status: the complete suite (S1 to S8) passed on all six kernel/architecture combinations
  (`ubuntu-5.15`, `ubuntu-6.8`, `debian-6.12`; arm64 and amd64), 140 checks and 0 failures each.
  One warning per run is expected: `SystemCallArchitectures=native` cannot be tested because the
  guest cannot execute a binary of another ABI. Only systemd 249 was run.

## Known limits

- **No KVM.** The Docker Desktop VM on this Mac (Linux 6.12.54-linuxkit, built
  without `CONFIG_VIRTUALIZATION`) has no `/dev/kvm`, so every VM runs under
  QEMU's TCG instruction emulation, for arm64 guests as well. `run.sh` probes
  for `/dev/kvm` and would use it for a guest of the host's architecture; that
  path is untested here.
- **TCG is slow, and unevenly so.** Compute-bound kernel work such as the BPF
  verifier is hit hardest: a collector program that cost the 5.15 verifier
  about half a million steps needed 35 to 80 s per load in these VMs, while the
  programs of today (at most about 21,000 steps) load in well under a second.
  A test that is quick on real hardware can therefore need minutes if it does
  something verifier- or CPU-heavy. Choose `-test.timeout` and `PW_VM_TIMEOUT`
  accordingly; the default of 15 minutes is ample for the current test binary
  (under one minute per kernel) but not for a suite that loads a program
  many times and loads it slowly.
- **Timing and throughput results are emulated-CPU results.** Latency
  measurements (`TestHookLatency`) and load tests say nothing about real
  hardware. Functional results (verifier acceptance, events seen, identities)
  are real kernel behaviour.
- **x86 guests are slower than arm64 guests** on this arm64 host (both CPUs are
  emulated, but x86 needs more translation work): boot to `/init` takes about
  4 to 5 s against 1.4 to 1.7 s, and CPU-bound work took about 1.4 to 1.8x as
  long in the measurements made while tuning. The current test binary needs 32
  to 42 s on amd64 against 31 to 35 s on arm64.
- **CPU model of the arm64 guest.** The complete test binary on `ubuntu-5.15`
  took 25 s with `-cpu max,pauth=off` (the default), 28 s with
  `-cpu max,pauth-impdef=on` (emulated pointer authentication) and 58 s with
  `-cpu cortex-a72` (probably because that model has no LSE atomics); on
  verifier-heavy work the pointer authentication cost much more (48 s against
  79 s). Hence the default: the guest has no pointer authentication, but LSE,
  BTI, SVE and the other `max` features. Override with `PW_VM_CPU`.
- **One userland for all kernels** (Ubuntu 22.04, glibc 2.35). Use
  `CGO_ENABLED=0` for the binary. The guest of the plain mode has no systemd, no
  network except loopback, no disk, no modules and a single flat cgroup2 mount
  (systemd mode: see above).
- **Concurrent runs** are fine (staging directory and container name are per
  process; four VMs ran side by side on the 12 CPU Docker VM) but each VM keeps
  one to four host cores busy and can use its full guest RAM. Use `PW_VM_LOG`
  when running the same combination twice at once.
- Interrupted runs (SIGINT, SIGTERM; both tested) stop the container, remove
  the staging directory and exit with 130. After `kill -9` a
  `cache/stage.<pid>` directory and a container named `pw-vm-*` may be left
  behind; delete them by hand.
