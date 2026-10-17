<p align="center">
  <img src="docs/logo/process-watcher-logo.png" alt="process-watcher logo" width="320">
</p>

# process-watcher
A process monitoring tool that tries to detect exploitation

A Linux agent (Go + eBPF) that finds processes by a substring of the name of their **executable image**, follows their
**process trees** and logs process creation, successful program changes (exec) and process end as JSONL. Events go to
a local log and, at the same time if you want, over TCP, UDP and an HTTP webhook. Building a baseline or judging what
is an attack is left to the receiving system. Optionally the agent **reacts** to specific child processes with a
targeted `SIGKILL` (see [Kill rules](#kill-rules)).

- Event based (eBPF: fork, successful exec, exit); `/proc` only adds metadata.
- Recursive: all generations, also after reparenting, double forks and the end of the root.
- One static binary per architecture (`linux/amd64`, `linux/arm64`); no compiler is needed on the target host.
- YAML configuration with equivalent command line flags.
- The event format is a contract: [schema/event.schema.json](schema/event.schema.json).

## Requirements

| Requirement | Value |
| --- | --- |
| Operating system | Linux, `amd64` or `arm64` |
| Kernel | 5.15 or newer **with BTF** (`/sys/kernel/btf/vmlinux`, `CONFIG_DEBUG_INFO_BTF=y`). The version number alone is no guarantee: at start the agent checks the functions and kernel structure fields it needs. |
| Privileges | root, or `CAP_BPF` + `CAP_PERFMON` (+ `CAP_SYS_PTRACE` to read `/proc/<pid>/exe` of other users' processes, `CAP_KILL` for the kill feature, `CAP_SYS_RESOURCE` before kernel 5.11). Kernel lockdown mode `confidentiality` prevents operation. |
| PID namespace | the **initial** PID namespace of the host (all PIDs are host PIDs). Running inside a container is not supported and refused. |

If a requirement is missing, the agent stops with a concrete diagnosis and **exit code 3**. It never falls back to
polling `/proc`, which would miss short-lived processes. `sudo ./process-watcher doctor` checks everything, loads the
programs and verifies with a probe process of its own that fork, exec and exit arrive without `/proc`. Tested kernels
and architectures: [docs/compatibility.md](docs/compatibility.md).

## Installation

### From a release

Every [release](https://github.com/Neo23x0/process-watcher/releases) has one archive per architecture
(`process-watcher_<version>_linux_<arch>.tar.gz`, `amd64` and `arm64`) with exactly three files: the **single static
binary** `process-watcher` (eBPF programs embedded; no libraries, other files or compiler needed at run time), the
commented example configuration `process-watcher.yaml` and the `LICENSE`. `SHA256SUMS` lists the archives.

```bash
ARCH=amd64     # or arm64
VERSION=v0.1.0
curl -fsSLO https://github.com/Neo23x0/process-watcher/releases/download/$VERSION/process-watcher_${VERSION}_linux_${ARCH}.tar.gz
curl -fsSLO https://github.com/Neo23x0/process-watcher/releases/download/$VERSION/SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS
tar xzf process-watcher_${VERSION}_linux_${ARCH}.tar.gz && cd process-watcher_${VERSION}_linux_${ARCH}
sudo ./process-watcher doctor          # kernel, BTF, privileges
sudoedit process-watcher.yaml          # adjust watch.image_contains
sudo ./process-watcher                 # finds process-watcher.yaml next to the binary
```

`gh attestation verify <archive> --repo Neo23x0/process-watcher` shows that GitHub built an archive. Only `amd64` and
`arm64` are provided: the eBPF collector assumes 64-bit kernel pointers, so 32-bit kernels (x86, ARM) are not
supported (exit code 3).

### As a systemd service

```bash
sudo ./packaging/install.sh ./process-watcher    # the binary from the archive, or ./dist/process-watcher-linux-<arch>
sudoedit /etc/process-watcher/config.yaml        # adjust the watch list
sudo process-watcher doctor
sudo systemctl enable --now process-watcher
```

`install.sh` and the unit are in `packaging/`; details and the reasons for the unit's settings:
[packaging/INSTALL.md](packaging/INSTALL.md). Without systemd, copy the binary and start it with root privileges.
Maintainers: pushing a `vX.Y.Z` tag builds and publishes a release ([release workflow](.github/workflows/release.yml));
`make release-archives VERSION=v0.1.0` builds the same archives locally.

## Quick start

```bash
# Local observation only
sudo ./process-watcher --watch-image-contains nginx --log-file /var/log/process-watcher/events.jsonl

# Local log plus remote outputs, with an exclusion
sudo ./process-watcher --watch-image-contains nginx --exclude-image-contains legitimate-helper \
  --log-file /var/log/process-watcher/events.jsonl \
  --tcp-address collector.example.net:9000 --udp-address 192.0.2.20:9001 \
  --webhook-url https://collector.example.net/hooks/processes

# YAML plus overriding single values
sudo ./process-watcher --config /etc/process-watcher/config.yaml \
  --watch-image-contains nginx --watch-image-contains apache2 --capture-argv=true

# Without root, without observation or network access
./process-watcher check-config --config ./process-watcher.yaml
./process-watcher print-config --config ./process-watcher.yaml

# Reaction to child processes (see Kill rules)
sudo ./process-watcher --watch-image-contains nginx --capture-argv=true --kill-enabled=true \
  --kill-field image --kill-field argv --kill-string demo-long-running-helper \
  --kill-regex '^(useradd|usermod)$'
```

Example configurations are in [examples/](examples/); each one is checked by the strict loader in a test. Simple
receivers for trying things out (Python 3 standard library only) are in [examples/receivers/](examples/receivers/);
`nc -lk 9000` (TCP) and `nc -lu 9001` (UDP) are enough for a first look.

## Commands and exit codes

| Command | Effect |
| --- | --- |
| `run` (default) | Start observing. Waits even if no matching process is running yet. |
| `check-config` | Validate the configuration (with `tcp.tls` and `ca_file` it also reads the CA bundle). Attaches no BPF programs, creates no files, contacts no endpoints and **never sends signals**, not even with active kill rules. |
| `print-config` | The resolved configuration (YAML) and its source file. No secrets: of the bearer token only the variable name, of the webhook URL only scheme and host. |
| `doctor` | Check requirements and privileges (see above). |
| `--help`, `--version` | Help with all flags, defaults and YAML keys; version. |

| Exit code | Meaning |
| --- | --- |
| `0` | Success, also on SIGINT/SIGTERM |
| `1` | Runtime error, also an unwritable local log |
| `2` | Configuration or usage error |
| `3` | Unsupported platform or missing collector requirements |

Operational diagnostics go to stderr; stdout stays empty for `run`.

## Configuration

Exactly one YAML file is loaded (files are never merged). Search order: `--config <path>` (must exist and be
readable), `process-watcher.yaml` in the working directory, `process-watcher.yaml` next to the real binary (symlinks
resolved), the built-in defaults. A file that is found but invalid is an error and never skipped. Precedence:
**defaults < YAML < explicitly set flags**; environment variables are not a configuration layer (only the variable
named by `token_env` is read). Relative file paths refer to the working directory of the invocation, also when they
come from YAML. Loading is strict: unknown or duplicate keys, wrong types, empty values, aliases and multiple
documents are rejected, `config_version: 1` is mandatory, and errors name the file, line and key path (for example
`kill.regex[2]`).

```yaml
config_version: 1
watch:
  image_contains: ["nginx"]   # no default: a run needs at least one pattern
  ignore_case: false
  max_depth: 0                # 0 = unlimited; limits the emitted events only, never the tracking
exclude:
  image_contains: []
  scope: remote
capture:
  argv: false                 # arguments may contain credentials
kill:
  enabled: false
outputs:
  file:
    path: ./process-watcher.jsonl
    rotate_size_mb: 100
  tcp:
    address: ""               # empty = off; the same for udp.address and webhook.url
```

Every key and its default: [examples/process-watcher.full.yaml](examples/process-watcher.full.yaml) (shipped as
`process-watcher.yaml` in the release archives). Every leaf has an equivalent flag (`watch.image_contains` →
`--watch-image-contains`; the complete mapping is in `--help`). List flags are repeatable and **replace** the YAML list
once set; a single empty value (`--exclude-image-contains=`) clears it. Boolean flags override YAML with
`--capture-argv=false`. Commas are literal characters. Sizes ending in `_mb` are MiB, durations use Go syntax (`5s`,
`1m30s`), `runtime.ring_buffer_mb` must be a power of two.

## Image matching

`image` is the **file name of the program that was actually executed** (the base name of the file the kernel runs at
exec), not `comm` (changeable, limited to 15 bytes) and not `argv[0]`. The complete resolved path is kept in
`image_path`. All `watch.image_contains` entries are OR-combined and case-sensitive; with `watch.ignore_case: true`
the same ASCII folding (`A`–`Z`) applies to watch and exclusion strings, independent of locale: `É` and `é` stay
different.

- `nginx` matches `nginx` and `nginx-debug`, but not `python` with `nginx` appearing in an argument.
- **Symlinks:** if the shell is called as `sh` and `sh` is a symlink to `/usr/bin/dash`, then `image` = `dash`,
  `image_path` = `/usr/bin/dash`, `process.comm` = `sh` and `argv[0]` = `sh`
  (see [testdata/golden/process_exec_descendant.jsonl](testdata/golden/process_exec_descendant.jsonl)).
- **Scripts:** the image of a script is its **interpreter**: `./deploy.sh` with `#!/bin/sh` has `image` = `dash` (or
  `bash`). The requested file name is in `details.exec_filename`. To watch a script, use the interpreter as pattern.
- Deleted or anonymous programs (`memfd`) are recognized (`process.image_deleted: true`).
- The image name is captured **in the kernel at exec time**, so no later `/proc` access can come up empty for
  short-lived processes.

## Process trees and events

A matching process becomes a **root**, unless it already descends from an observed root. Every child inherits the
assignment to the root regardless of its image, across all generations; it survives exec, reparenting, double forks
and the end of the root (the historical parent is never replaced by PPID 1). If an NGINX master and its workers
match, the worker is a descendant of the master, so no event is sent twice. `watch.max_depth` limits only the
**emitted** events, never the tracking.

| Event | Meaning |
| --- | --- |
| `process.discovered` | An instance that was already alive is assigned to a tree for the first time (`details.discovery`: `startup` or `reconcile`). No invented fork. |
| `process.fork` | New process instance, also without a following exec. It first inherits the creator's image (`image_state: inherited`). |
| `process.exec` | Successful program change (`image_state: executed`, `details.exec_index` counts from 1). Failed `execve` calls produce no event. |
| `process.exit` | End of a process, at most one event per instance, with `exit_code`, `signal`, `duration_ns`. |
| `agent.started` / `agent.ready` / `agent.health` / `agent.gap` / `agent.stopped` | Run begins / hooks active / counters / loss or observation gap / orderly end with the final counters. |
| `response.kill_requested` / `response.kill_result` | Audit of the kill feature. |

Threads are not processes: the process ends with its last thread. A PID alone is no key: `process_id` is
`boot_id:tgid:start_boot_ns` (start time from `CLOCK_BOOTTIME`). Nothing from before the hooks were active is known,
and `agent.started` says so (`complete_capture: false`). Living processes are compared again at start, periodically
and after losses; newly found instances appear as `process.discovered`, and a process that vanished unnoticed is
closed as `process.exit` with `exit_source: inferred` and **no invented exit code**. `lineage.complete: false` marks an
unknown lineage; no historical relation is invented. Details: [docs/events.md](docs/events.md).

## Event format

Every output is UTF-8 JSON, exactly one object per line. Control characters and quotes in process data are escaped,
invalid UTF-8 is replaced by U+FFFD and noted in `data_quality.sanitized_fields`. The binding contract is
[schema/event.schema.json](schema/event.schema.json) (JSON Schema 2020-12); all test events and the golden examples in
[testdata/golden/](testdata/golden/) are checked against it.

Common fields: `schema_version`, `event_id` (UUID, identical for all outputs and retries), `agent_instance_id`,
`sequence` (strictly increasing per run), `event_type`, `timestamp`, `observed_at`, `boot_time_ns` (kernel event time,
`CLOCK_BOOTTIME`, defines the order), `host`, `source`, `process`, `parent`, `root`, `lineage`, `filter`,
`data_quality`, `details`. Values that could not be determined are `null` with a machine-readable reason in
`data_quality.missing_fields`; truncated values are listed in `truncated_fields`.

Example, abbreviated (a shell descendant of an NGINX root, argument capture on):

```json
{"event_type": "process.exec", "timestamp": "2026-10-17T12:00:00.123456789Z", "sequence": 42,
 "process": {"pid": 1235, "image": "dash", "image_path": "/usr/bin/dash", "comm": "sh", "uid": 33,
             "argv": ["sh", "-c", "id"], "argv_state": "executed"},
 "parent": {"pid": 1200, "image": "nginx", "relationship_source": "fork"},
 "root": {"pid": 1200, "image": "nginx"},
 "lineage": {"role": "descendant", "depth": 1, "complete": true},
 "details": {"exec_index": 1, "exec_filename": "/bin/sh", "previous_image": "nginx"}}
```

The shell was called as `sh`, the program that actually ran is `dash`. The complete event with all fields is in
[docs/events.md](docs/events.md).

## Exclusions

`exclude.image_contains` checks substrings of the **current** `process.image`, `exclude.argv_contains` substrings of
**one** argument at a time (it requires `capture.argv: true`). Missing or truncated arguments never match: in doubt the
event is passed on and marked in its data quality.

- `scope: remote` (default): matching process events stay **in the local log** with `filter.excluded: true` and
  `filter.matches`; TCP, UDP and webhook do not receive them. A local baseline stays possible.
- `scope: all`: suppressed for all outputs; the counters in `agent.health` keep the number.

Exclusions are re-evaluated for **every event** against its own image and never remove a process or subtree from the
observation: with `nginx → legitimate-helper → sh → curl` and the helper excluded, only the helper's own events are
marked, `sh` and `curl` stay visible and keep the root. Agent messages and the kill audit are never excluded.
Exclusions are user filters, no proof of harmlessness; a very short string such as `sh` matches more than intended.

## Argument capture

**Off** by default (`capture.argv: false`) because arguments can contain credentials (`curl -u user:pass ...`); enable
it only if the receivers and the local log are prepared for that. When enabled, arguments are captured at exec **in the
kernel**, not later from `/proc`: at most **32 arguments** and **4096 raw bytes** per event, as an array and never as a
joined command line. An overflow is listed in `data_quality.truncated_fields`; a last argument that was only partly
captured never enters the list. Forks carry the creator's arguments (`argv_state: inherited`); processes that were
already running at start get theirs from `/proc/<pid>/cmdline` (`snapshot`), verified against the kernel start time of
the instance so that a reused PID is never mixed up (if that fails, `argv` is `null` with a reason). Environment
variables are never captured.

## Outputs

An event is **serialized once**; all outputs get the same bytes and the same `event_id`. The **local JSONL log** is
mandatory and written first. TCP, UDP and webhook are optional and independent, each with its own worker and bounded
queue (`delivery.queue_size`): a slow target blocks neither the local log nor the others, and when a queue is full only
the new event is dropped **for that output** and counted.

| Output | Behavior and limits |
| --- | --- |
| Local log | Append mode, files `0600`; symlinks and a second writer (`<path>.lock`) are refused. Rotation (`rotate_size_mb`, `keep_files`) happens between complete lines; external rename/copytruncate rotation is not supported. `fsync` at least every `sync_interval` and at exit, so a crash can cost the last interval. An incomplete last line is saved to `<file>.corrupt-<UTC>` at start. A permanently unwritable log or a full disk ends the agent with exit code 1. |
| TCP | Persistent connection, newline-delimited JSON; timeouts, reconnect after errors (DNS is resolved again) and retry of the **whole** line. Optional TLS with certificate and host name verification (`tls`, `ca_file`, `server_name`), never a plaintext fallback. |
| UDP | One complete event per datagram, never split; events above `udp.max_bytes` are dropped for UDP only (`dropped_too_large`). No acknowledgement, no retry. |
| Webhook | `POST` with one JSONL line (`application/x-ndjson`, `X-Event-ID`, optional `Authorization: Bearer` from the variable named by `token_env`). Every `2xx` is accepted; network errors, timeouts, `408`, `429` and `5xx` are retried (`Retry-After` up to 60 s), everything else is final, redirects are not followed. The URL is redacted in diagnostics because it may contain secrets. |

Retries: at most `delivery.max_retries` + 1 attempts with backoff from 1 s to 30 s (±20 % jitter), then the event is
dropped for that output and counted. **There is no guaranteed or exactly-once delivery**: after unclear transfers
duplicates and incomplete lines are possible (deduplicate by `event_id`), there is no replay across a restart, and the
TCP and UDP counters mean "handed to the transport", not "acknowledged". Details:
[docs/outputs.md](docs/outputs.md) and [internal/output/DELIVERY.md](internal/output/DELIVERY.md).

## Kill rules

> **Reaction, not blocking.** The feature reacts **after** detection. It prevents neither the execution of a program
> nor its side effects: a short-lived process such as `useradd` can be long finished before the agent reacts, and an
> already vanished process is an expected outcome. A signal accepted by the kernel (`signal_sent`) proves neither that
> the process died nor that side effects were prevented.

**Scope.** Off by default (`kill.enabled: false`). When on, the rules apply only to **confirmed descendants** of the
observed roots (all generations), never to a root, PID 1 or the agent; there is no system-wide search. A match leads
directly to a `SIGKILL` attempt (no grace period) on exactly that process instance including its threads, not on its
descendants or process group. Children that already exist at start or are found later (`process.discovered`) are
checked too, so they can be killed as well. `kill.dry_run: true` evaluates and audits the same way but sends no
signal.

```yaml
kill:
  enabled: true
  dry_run: false
  fields: [image, argv]      # image (default), image_path, argv
  strings:
    - demo-long-running-helper
  regex:
    - '^(useradd|usermod)$'
```

**Matching.** Strings are literal, case-sensitive substrings (independent of `watch.ignore_case`); regexes are Go RE2
and search within the value (anchor with `^` and `$`, `(?i)` ignores case). Strings, regexes and fields are
OR-combined, and several hits give **one** action. Fields: `image` (file name of the executed program, default),
`image_path` (complete path) and `argv` (**every argument individually**, including `argv[0]`, never joined; needs
`capture.argv: true`). `useradd` in `argv` also matches `sh -c 'useradd ...'`; to match only the program that was
started, use `fields: [image]` with `^useradd$`. Only **demonstrably complete** values count: missing, presumed or
truncated values are no basis for a match.

**Inherited image.** A new process carries its creator's image until its own exec, so a rule matching the image of an
observed root (or an intermediate process) also matches every direct child already at `process.fork`. Aim rules at the
image of the **unwanted** program.

**Evaluation** happens at `process.exec`, `process.discovered` and `process.fork` (inherited image and path only),
**before** the output exclusions: `exclude.*` and `watch.max_depth` do not shield a target. If the assignment to a root
is unclear after collection losses (`lineage.complete: false`), **no action is taken on suspicion** (`skipped`,
`lineage_unconfirmed`): whoever causes a ring buffer overflow on purpose can withdraw processes from the rules, so
monitor `agent.gap` and `collector.lost_total`.

**Sequence and identity.** A PID alone is no identity. One worker handles at most 256 waiting actions; network
delivery never delays a kill attempt.

1. The decision (`response.kill_requested`, `outcome: pending`) is written locally **before** anything is signalled.
2. `pidfd_open` for the host TGID; then TGID and **exact** start time are checked against the kernel's table. On a
   mismatch, or if unprovable, the action is skipped (`identity_mismatch`, `identity_unverified`). There is no
   fallback to `kill(pid, SIGKILL)`.
3. Right before the signal the match fields are checked again (`/proc/<pid>/exe`, `cmdline`); if the match can no
   longer be proven the action is skipped (`match_no_longer_verified`).
4. `SIGKILL` goes only through the verified pidfd, so a reused PID is never hit.

Identity check and signal are not atomic: the same instance can still exec in between. At most one attempt is made per
`(process_id, exec_index)` and a failed attempt is never repeated in a loop.

**Audit.** `response.kill_requested` and exactly one `response.kill_result` share `details.action_id`
(`details.trigger_event_id` names the trigger). Outcomes: `dry_run`, `signal_sent`, `already_exited`,
`permission_denied`, `error`, `skipped` (with a reason). The later `process.exit` carries `details.response_action_id`
(a correlation, no causal claim). A crash can leave an open `pending`.

**Privileges.** root, or `CAP_BPF`, `CAP_PERFMON`, `CAP_KILL` (other users' processes) and `CAP_SYS_PTRACE` (the
re-check). Without permission the agent reports `permission_denied` and keeps observing; without
`pidfd_open`/`pidfd_send_signal` it refuses to start with the feature enabled (exit code 3).

**Reaction time (measured).** On a native arm64 kernel 6.12.54 (100 own target processes, 20 ms apart) the decision was
written locally after **0.13 ms** and `pidfd_send_signal` returned after **0.27 ms** on average (p95 0.47 ms, maximum
1.4 ms); the target keeps running until the signal takes effect. Values from emulated CPUs say nothing about hardware.
Full reference: [docs/kill-rules.md](docs/kill-rules.md); measurements: [docs/measurements.md](docs/measurements.md).

## Operation

`agent.health` (every `runtime.health_interval`) reports roots, tracked instances, kernel-counted losses by cause,
exclusion and depth counters, queue lengths and per-output counters for the current run. Ring buffer losses, a full
process limit (`runtime.max_processes`) or a failed reconciliation produce `agent.gap`; afterwards the living processes
are compared again and what is found is marked `lineage.complete: false` and `data_quality.collection_gap: true`. A
snapshot cannot restore lost short-lived processes. A restart begins a new run (new `agent_instance_id`).

Memory is bounded by `runtime.max_processes`, all queues are bounded, and the RSS is about `2 × ring_buffer_mb +
15 MiB`; with argument capture every tracked instance holds up to 4 KiB of arguments
([measurements](docs/measurements.md)). On **shutdown** (SIGINT/SIGTERM) waiting kill actions complete, captured events
are processed, remote queues drain until `runtime.shutdown_timeout` and `agent.stopped` is stored **locally**; no
artificial exit events are created. A failing final write (full disk) ends the agent with exit code 1. More:
[docs/operation.md](docs/operation.md).

## Limits

- Linux only, `amd64`/`arm64`; no operation in a container (the initial PID namespace is required).
- No history from before the hooks were activated; after collection losses the lineage of affected processes is
  unconfirmed. Processes that were already orphaned before the start cannot be assigned to an earlier root.
- One target per remote transport; no persistent remote queue; no guaranteed delivery.
- Every root that is newly admitted at run time triggers a reconciliation (at most once per second); with very broad
  patterns such as `sh` it runs continuously ([cost](docs/measurements.md)).
- No monitoring of CPU, RAM, files or network of the observed processes; no automatic attack detection; no user
  interface; no Kubernetes integration.
- The kill feature reacts afterwards and is no preventive protection.

The full list is in [docs/operation.md](docs/operation.md#limits).

## Building and testing

```bash
make build-linux                       # static binaries dist/process-watcher-linux-{amd64,arm64}
make release-archives VERSION=v0.1.0   # the release archives, exactly as the release workflow builds them
make test                              # unit tests (macOS or Linux)
make test-docker                       # collector, response and agent end-to-end tests in a privileged container (--pid=host)
make test-vm ARCH=amd64 KERNEL=ubuntu-5.15   # collector tests in a real kernel under QEMU (tests/vm/README.md)
make test-vm-matrix                    # the same for all kernels and both architectures
make bench-docker                      # CPU, RSS, throughput, latency, kill reaction time
```

The eBPF objects are **not** built by the normal Go build: `internal/collector/ebpf/pw_bpfel.{go,o}` are checked in and
embedded, and one object serves `amd64` and `arm64` (CO-RE, `tp_btf`). `make generate` regenerates them reproducibly in
a container ([build/ebpf/Dockerfile](build/ebpf/Dockerfile), pinned toolchain). Tests with a real kernel need root, the
initial PID namespace and BPF; there are no mocks for the collector. Which runs actually took place is recorded in
[docs/acceptance.md](docs/acceptance.md), the tested kernels in [docs/compatibility.md](docs/compatibility.md).

## Documentation

- [docs/events.md](docs/events.md): process trees, identity, reconciliation, the complete event format, exclusions and
  argument capture
- [docs/kill-rules.md](docs/kill-rules.md): the complete kill-rule reference
- [docs/outputs.md](docs/outputs.md): outputs and delivery limits
- [docs/operation.md](docs/operation.md): health, gaps, shutdown and limits
- [docs/compatibility.md](docs/compatibility.md), [docs/measurements.md](docs/measurements.md),
  [docs/acceptance.md](docs/acceptance.md): tested kernels, measured numbers, runs that took place
- [packaging/INSTALL.md](packaging/INSTALL.md): the systemd service

License: GPL-3.0, see [LICENSE](LICENSE). The sources of the eBPF programs carry `GPL-2.0-or-later` (compatible with
GPL-3.0); the object carries the license `GPL`, which the kernel requires for GPL-only helpers.
