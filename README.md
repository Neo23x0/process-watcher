<p align="center">
  <img src="docs/logo/process-watcher-logo.png" alt="process-watcher logo" width="320">
</p>

# process-watcher
A process monitoring tool that tries to detect exploitation

A Linux tool written in Go that finds processes by a substring of the name of their **executable image** and
observes their **process trees**. It logs process creation, successful program changes (exec) and process end as
JSONL. Events are stored locally and can be sent at the same time over TCP, UDP and an HTTP webhook. Building a
baseline or judging what is an attack is left to the receiving system. Optionally the agent can **react** to
specific child processes with a targeted `SIGKILL` (see [Reaction: kill rules](#reaction-kill-rules)).

- Event based, using **eBPF** (fork, successful exec, exit); `/proc` only adds metadata.
- Recursive: all generations, also after reparenting, double forks and the end of the root.
- The local JSONL log is mandatory; TCP, UDP and webhook are independent and can be enabled together.
- Configuration through YAML and equivalent command line flags. One static binary per architecture
  (`linux/amd64`, `linux/arm64`); no compiler is needed on the target host.

The event format is a contract: [schema/event.schema.json](schema/event.schema.json).

## Contents

1. [Requirements](#requirements)
2. [Installation](#installation)
3. [Quick start](#quick-start)
4. [Commands and exit codes](#commands-and-exit-codes)
5. [Configuration](#configuration)
6. [Image matching](#image-matching)
7. [Process trees and event types](#process-trees-and-event-types)
8. [Event format](#event-format)
9. [Exclusions](#exclusions)
10. [Argument capture](#argument-capture)
11. [Outputs and delivery limits](#outputs-and-delivery-limits)
12. [Reaction: kill rules](#reaction-kill-rules)
13. [Operation: health, gaps, shutdown](#operation-health-gaps-shutdown)
14. [Limits](#limits)
15. [Building and testing](#building-and-testing)

## Requirements

| Requirement | Value |
| --- | --- |
| Operating system | Linux, `amd64` or `arm64` |
| Kernel | 5.15 or newer **with BTF** (`/sys/kernel/btf/vmlinux`, `CONFIG_DEBUG_INFO_BTF=y`). The version number alone is no guarantee: at start the agent checks the functions it needs (BPF ring buffer, `tp_btf`, task iterators, the kernel structure fields it reads). |
| Privileges | root, or `CAP_BPF` + `CAP_PERFMON` (+ `CAP_SYS_PTRACE` to read `/proc/<pid>/exe` of other users' processes, `CAP_KILL` for the kill feature, `CAP_SYS_RESOURCE` before kernel 5.11). Kernel lockdown in mode `confidentiality` forbids reading kernel memory from BPF and prevents operation. |
| PID namespace | the **initial** PID namespace of the host. All PIDs in the event stream are host PIDs. Running inside a container (child PID namespace) is not supported and refused by the agent. |

If a requirement is missing, the agent stops with a concrete diagnosis and **exit code 3**. It never silently
falls back to polling: a plain `/proc` scan would miss short-lived processes between two scans.

```bash
sudo ./process-watcher doctor
```

`doctor` checks the architecture, kernel, privileges, lockdown and BTF fields, really loads the programs, starts a
short-lived probe process of its own and verifies that fork, exec (with image name and path) and exit, together with
the snapshot, arrive without `/proc`. With `--kill-enabled` it also checks `pidfd_open`/`pidfd_send_signal`. The
kernels and architectures that were actually tested are listed in [docs/compatibility.md](docs/compatibility.md).

## Installation

### From a release

Every [release](https://github.com/Neo23x0/process-watcher/releases) contains, for each architecture
(`linux/amd64` and `linux/arm64`), an archive `process-watcher_<version>_linux_<arch>.tar.gz` with exactly three
files: the **single static binary** `process-watcher` (the eBPF programs are embedded; at run time no libraries, no
other files and no compiler are needed), the commented example configuration `process-watcher.yaml` and the
`LICENSE`. `SHA256SUMS` lists the archives.

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

The configuration next to the binary is found automatically (search order: see [Configuration](#configuration));
relative paths in it refer to the working directory. For public repositories
`gh attestation verify process-watcher_<version>_linux_<arch>.tar.gz --repo Neo23x0/process-watcher` shows that
GitHub built the archive. Only `amd64` and `arm64` are provided: the eBPF collector works with 64-bit kernel
pointers and is not supported on 32-bit kernels (x86, ARM), where the binary refuses to start with exit code 3.

### As a systemd service

```bash
sudo ./packaging/install.sh ./process-watcher                    # the binary from the archive, or ./dist/process-watcher-linux-<arch>
sudoedit /etc/process-watcher/config.yaml                        # adjust the watch list
sudo process-watcher doctor
sudo systemctl enable --now process-watcher
```

`install.sh` and the unit are in the repository under `packaging/`. Details and the reasons for the service
settings: [packaging/INSTALL.md](packaging/INSTALL.md). Without systemd it is enough to copy the binary and start it
with root privileges.

### Publishing a release

A release is created automatically when a version tag is pushed that points at a commit of `main`
([.github/workflows/release.yml](.github/workflows/release.yml)):

```bash
git tag v0.1.0
git push origin v0.1.0        # vMAJOR.MINOR.PATCH is a release, vMAJOR.MINOR.PATCH-rc.1 a pre-release
```

The workflow verifies the tag and the sources (format, commit on `main`, `go vet`, `go test`, embedded eBPF object
reproducible byte for byte from the C source), builds both archives with `tools/release` (every binary is checked to
be a **single static file**: no loader, no libraries), runs the shipped binary with the shipped configuration on one
runner per architecture and only then publishes the archives, `SHA256SUMS`, the build provenance attestation and
the release notes. `make release-archives VERSION=v0.1.0` builds the same archives locally, byte-identical for the
same source and Go version.

## Quick start

```bash
# Local observation only
sudo ./process-watcher --watch-image-contains nginx --log-file /var/log/process-watcher/events.jsonl

# Local and remote output at the same time
sudo ./process-watcher --watch-image-contains nginx --exclude-image-contains legitimate-helper \
  --log-file /var/log/process-watcher/events.jsonl \
  --tcp-address collector.example.net:9000 --udp-address 192.0.2.20:9001 \
  --webhook-url https://collector.example.net/hooks/processes

# YAML plus overriding single values
sudo ./process-watcher --config /etc/process-watcher/config.yaml \
  --watch-image-contains nginx --watch-image-contains apache2 --capture-argv=true

# Without root and without observation or network access
./process-watcher check-config --config ./process-watcher.yaml
./process-watcher print-config --config ./process-watcher.yaml

# Reaction to child processes (see the kill rules section)
sudo ./process-watcher --watch-image-contains nginx --capture-argv=true --kill-enabled=true \
  --kill-field image --kill-field argv --kill-string demo-long-running-helper \
  --kill-regex '^(useradd|usermod)$'
```

Example configurations are in [examples/](examples/); each one is checked by the strict loader in a test. Simple
receivers to try things out (Python 3 standard library only): [examples/receivers/](examples/receivers/). For a quick
look `nc -lk 9000` (TCP) and `nc -lu 9001` (UDP) are enough.

## Commands and exit codes

| Command | Effect |
| --- | --- |
| `run` (default) | Start observing. Waits even if no matching process is running yet. |
| `check-config` | Load and validate the configuration; with `tcp.tls` and `ca_file` it also reads the CA bundle to check that it is readable and holds a certificate. Attaches no BPF programs, creates no files, contacts no endpoints and **never sends signals**, not even with active kill rules. |
| `print-config` | The resolved configuration (YAML) and the chosen source file. No secrets: of the bearer token only the variable name; of the webhook URL only scheme and host, its path (chat services keep the secret there) and query values are replaced, as are credentials and the fragment. |
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

Exactly one YAML file is loaded (files are never merged). Search order:

1. `--config /path/process-watcher.yaml` (must exist and be readable),
2. `process-watcher.yaml` in the current working directory,
3. `process-watcher.yaml` next to the real binary (after resolving symlinks),
4. the built-in defaults.

A file that is found but invalid is an error and is never skipped. Precedence:
**defaults < YAML < explicitly set flags**. Environment variables are not a configuration layer; only the variable
named by `token_env` is read. **Relative file paths refer to the working directory of the invocation**, also when
they come from YAML.

Loading is strict: unknown or duplicate keys, wrong types, empty list items, empty values, aliases and multiple
documents are rejected; `config_version: 1` is mandatory. Error messages name the file, the line and the
configuration path including the list index (for example `kill.regex[2]`).

```yaml
config_version: 1
watch:
  image_contains: ["nginx"]   # no built-in default: a run without an entry is invalid
  ignore_case: false
  max_depth: 0
exclude:
  image_contains: []
  argv_contains: []
  scope: remote
capture:
  argv: false
kill:
  enabled: false
  dry_run: false
  fields: [image]
  strings: []
  regex: []
outputs:
  file:
    path: ./process-watcher.jsonl
    rotate_size_mb: 100
    keep_files: 5
    sync_interval: 1s
  tcp:
    address: ""
    tls: false
    ca_file: ""
    server_name: ""
  udp:
    address: ""
    max_bytes: 8192
  webhook:
    url: ""
    token_env: ""
    timeout: 10s
delivery:
  queue_size: 10000
  connect_timeout: 5s
  write_timeout: 5s
  max_retries: 5
runtime:
  ring_buffer_mb: 16
  max_processes: 65536
  health_interval: 60s
  reconcile_interval: 30s
  shutdown_timeout: 10s
```

Every leaf has an equivalent flag (`watch.image_contains` → `--watch-image-contains`, …; the complete mapping is in
`--help`). List flags are repeatable and **replace** the YAML list as soon as they are set once; a single empty value
(`--exclude-image-contains=`) clears the list. Boolean flags override YAML with `--capture-argv=false`. Commas are
literal characters. Sizes ending in `_mb` are **MiB** (1,048,576 bytes), durations use Go syntax (`5s`, `1m30s`).
`runtime.ring_buffer_mb` must be a power of two. Remote addresses: `192.0.2.10:9000`,
`collector.example.net:9000`, `[2001:db8::10]:9000`.

## Image matching

`image` is the **file name of the program that was actually executed** (the base name of the file entry the kernel
runs at exec), not `comm` (changeable, limited to 15 bytes) and not `argv[0]` (no reliable proof of the program).
The complete resolved path is kept separately in `image_path`. All entries of `watch.image_contains` are OR-combined;
matching is case-sensitive by default. With `watch.ignore_case: true` the same ASCII folding (`A`–`Z`) applies to
watch and exclusion strings, independent of locale and Unicode tables: `É` and `é` stay different.

- `nginx` matches `nginx` and `nginx-debug`, but not `python` with `nginx` appearing in an argument.
- **Symlinks:** if the shell is called as `sh` and `sh` is a symlink to `/usr/bin/dash`, then `image` = `dash`,
  `image_path` = `/usr/bin/dash`, `process.comm` = `sh` and `argv[0]` = `sh`
  (see [testdata/golden/process_exec_descendant.jsonl](testdata/golden/process_exec_descendant.jsonl)).
- **Scripts:** the executable image of a script is its **interpreter**. `./deploy.sh` with shebang `#!/bin/sh` has
  `image` = `dash` (or `bash`), not `deploy.sh`. The requested file name is in `details.exec_filename` (here
  `./deploy.sh`) and, with argument capture enabled, in `argv`. To watch a specific script, use the interpreter as
  the watch pattern.
- Deleted or anonymous programs (`memfd`) are recognized: `process.image_deleted: true`; `image_path` shows the path
  without the ambiguous ` (deleted)` suffix of `/proc`.
- The image name is captured **in the kernel at exec time**. There is no later `/proc` access that would come up
  empty for short-lived processes.

## Process trees and event types

A matching process instance becomes a **root**, unless it already is a descendant of an observed root. Every new
child process inherits the assignment to the root, regardless of its image and across all generations. If an NGINX
master and its workers match, the worker is a descendant of the master (an event is never sent twice); independent
matching process trees have their own roots. The assignment survives exec, reparenting, double forks and the end of
the root; the historical parent relation is never replaced by the later PPID 1. `watch.max_depth` (0 = unlimited,
the root has depth 0) limits only the **emitted** process events, never the internal tracking.

| Event | Meaning |
| --- | --- |
| `process.discovered` | An instance that was already alive is assigned to a tree for the first time (at start or later). No invented fork; `timestamp` is the time of the discovery, `details.discovery` is `startup` or `reconcile`. |
| `process.fork` | New process instance, also without a following exec. It first inherits the image of its creator (`image_state: inherited`). |
| `process.exec` | Successful program change (`image_state: executed`, `details.exec_index` counts from 1). A new, so far unobserved process that matches for the first time through the exec appears here with `role: root`. Failed `execve` calls produce no event. |
| `process.exit` | End of a process, at most one event per instance, with `exit_code`, `signal`, `duration_ns`. |
| `agent.started` / `agent.ready` | Run begins (startup reconciliation in progress) / hooks active, snapshot and buffered live events reconciled. |
| `agent.health` / `agent.gap` / `agent.stopped` | Counters and operating state / loss or observation gap / orderly end with the final values of all counters (including the exclusion and depth counters). |
| `response.kill_requested` / `response.kill_result` | Audit of the kill feature. |

**Threads are not processes.** A `clone(CLONE_THREAD)` produces no event; the end of a single thread is not the
end of the process. A process ends when its last thread ends, even if the leader had ended earlier. An exec from a
non-leader thread takes over the identity and start time of the leader (`details.thread_exec: true`). `vfork`,
`clone` and `clone3` are handled according to their actual effect; with `CLONE_PARENT` the **creating** thread group
counts as the parent.

**Identity.** A PID alone is no key: `process_id = boot_id:tgid:start_boot_ns`. The start time is the
`start_boottime` of the thread group leader in nanoseconds (`CLOCK_BOOTTIME`, including suspend) and comes from the
same kernel field in the live hooks and in the BPF task iterator. Nanosecond values appear in the JSON as decimal
strings.

**Startup reconciliation.** First the hooks are activated, then a snapshot (BPF task iterator) is taken; live events
that arrive in the meantime are applied afterwards. A process whose fork is in the buffer is not additionally
"discovered"; events older than the snapshot entry of the same instance are already reflected in it. History from
before the hooks were active and parents that had already vanished stay unknown: `agent.started` says so explicitly
(`complete_capture: false`, `history_before_hooks: unknown`) and `agent.ready` names the start of the observation.

**Periodic reconciliation.** Every `runtime.reconcile_interval`, after a detected loss and after a new root was
admitted at run time (no fork event knows its already living children) the living processes are compared again. Newly
found instances appear as `process.discovered`. An observed process that the snapshot no longer shows although it
was known before the snapshot is closed as `process.exit` with `exit_source: inferred`: **without an invented exit
code** (`exit_code`, `signal`, `duration_ns` are `null`).

**Lineage** (`lineage`): `ancestors` lists the `process_id`s from the root to the direct parent (at most 64; when
truncated the root and the nearest parents stay, `ancestors_truncated: true`, the real `depth` stays).
`complete: false` marks an **unknown lineage**: instances that a reconciliation found after a loss, processes whose
fork event was missing, or a root whose parent was unknown. No historical relation is invented.
`parent.relationship_source` names where the relation comes from: `fork` (creator according to the fork hook),
`snapshot_ppid` (current PPID at snapshot time) or `exec_real_parent` (real parent at the exec of an unobserved
process).

## Event format

Every output is UTF-8 JSON, exactly one object per line, terminated with `\n`. Line breaks, control characters and
quotation marks in process data are escaped by the JSON encoder; invalid UTF-8 bytes are replaced by U+FFFD (byte by
byte) and noted in `data_quality.sanitized_fields`. The binding contract is
[schema/event.schema.json](schema/event.schema.json) (JSON Schema 2020-12); all events of the tests and the golden
examples in [testdata/golden/](testdata/golden/) are checked against it.

Common fields: `schema_version` (1), `event_id` (UUID, identical for all outputs and retries), `agent_instance_id`
(UUID of the run), `sequence` (strictly increasing per run in output order; gaps are possible, for example through
exclusions with `scope: all` or undelivered events), `event_type`, `timestamp`, `observed_at`, `boot_time_ns`, `host`
(`hostname`, `boot_id`), `source` (`ebpf`, `snapshot`, `agent`), `process`, `parent`, `root`, `lineage`, `filter`,
`data_quality`, `details`.

**Time.** `boot_time_ns` is the kernel event time (`CLOCK_BOOTTIME`) and defines the order; for pure agent messages
it is `null`. The wall clock can jump, so `timestamp` is computed during processing:
`utc = wall_now − (boottime_now − boot_time_ns)` with both clocks read right after each other; no offset is cached.
`observed_at` is the processing time. Start times, event times and run times share the same BOOTTIME time base. For
`process.discovered`, `timestamp` is the time of the discovery.

`process`: `process_id`, `pid` (host TGID), `start_boot_ns`, `image`, `image_state`, `image_path`, `image_deleted`
(only when `true`), `comm`, `uid`, `euid`, `gid`, `argv`, `argv_state`. Values that could not be determined are
`null` and appear with a machine-readable reason in `data_quality.missing_fields`; truncated values in
`truncated_fields`. A failed access never deletes the kernel event and never pretends empty strings.

Example (a shell descendant of an NGINX root with argument capture enabled, stored as one line):

```json
{"schema_version":1,"event_id":"72c89dca-44f1-4224-9ab6-9cb77081a756","agent_instance_id":"8f733e92-0ef0-4a3b-829c-0c90e056bdf6","sequence":42,"event_type":"process.exec","timestamp":"2026-10-17T12:00:00.123456789Z","observed_at":"2026-10-17T12:00:00.124000000Z","boot_time_ns":"9000123456789","host":{"hostname":"web01","boot_id":"b53c175a-2d90-4d0c-8c94-dfc2c15eb199"},"source":"ebpf","process":{"process_id":"b53c175a-2d90-4d0c-8c94-dfc2c15eb199:1235:9000000000000","pid":1235,"start_boot_ns":"9000000000000","image":"dash","image_state":"executed","image_path":"/usr/bin/dash","comm":"sh","uid":33,"euid":33,"gid":33,"argv":["sh","-c","id"],"argv_state":"executed"},"parent":{"process_id":"b53c175a-2d90-4d0c-8c94-dfc2c15eb199:1200:8000000000000","pid":1200,"image":"nginx","image_path":"/usr/sbin/nginx","relationship_source":"fork"},"root":{"process_id":"b53c175a-2d90-4d0c-8c94-dfc2c15eb199:1200:8000000000000","pid":1200,"image":"nginx"},"lineage":{"role":"descendant","depth":1,"ancestors":["b53c175a-2d90-4d0c-8c94-dfc2c15eb199:1200:8000000000000"],"ancestors_truncated":false,"complete":true},"filter":{"excluded":false,"matches":[],"suppressed_outputs":[]},"data_quality":{"missing_fields":[],"truncated_fields":[],"sanitized_fields":[],"collection_gap":false},"details":{"exec_index":1,"exec_filename":"/bin/sh","previous_image":"nginx","thread_exec":false}}
```

The shell was called as `sh`, the program that actually ran is `dash`. The contract adds `process.argv_state`,
`parent.image_path`, `data_quality.sanitized_fields` and `details.exec_filename`, `previous_image` and `thread_exec`
as **additive** fields.

## Exclusions

`exclude.image_contains` checks substrings in the **current** `process.image`, `exclude.argv_contains` checks
substrings in **one** argument at a time (never in the joined command and never in the event text).
`exclude.argv_contains` requires `capture.argv: true`. Missing or truncated arguments do not count as a match: when
in doubt the event is passed on and marked in its data quality.

- `scope: remote` (default): matching process events are **in the local log**, with `filter.excluded: true`,
  `filter.matches` (field, configured string, the index for arguments) and `filter.suppressed_outputs`; TCP, UDP and
  webhook do not receive them. That keeps a local baseline possible.
- `scope: all`: they are suppressed for all outputs; counters (`agent.health`) keep the number.
- Agent messages and the kill audit are not subject to exclusions.

Exclusions are re-evaluated for **every event** against its own image and never remove a process or subtree from the
observation. Example `nginx → legitimate-helper → sh → curl` with the helper excluded: its exec and the fork of its
child (inherited image) are marked, `sh` and `curl` stay visible and keep the root. Exclusions are user filters, no
proof of harmlessness; a very short string such as `sh` matches more programs than intended.

## Argument capture

**Off** by default (`capture.argv: false`), because arguments can contain credentials (`curl -u user:pass ...`).
When enabled, the arguments are captured at exec **in the kernel**, not later from `/proc`: at most **32 arguments**
and **4096 raw bytes** per event. An overflow is listed in `data_quality.truncated_fields`; a last argument that was
only partly captured never enters the list. It is an array, not a joined shell command. Forks carry the inherited
arguments of the creator, marked `argv_state: inherited`. Processes that were already running at start get their
arguments (`snapshot`) from `/proc/<pid>/cmdline`, after the start tick was compared **before and after** reading
with the kernel start time of the instance, so a reused PID is never mixed up; if that fails, `argv` is `null` with a
reason. Environment variables are not captured. Enable the capture only if the receivers and the local log are
prepared for it.

## Outputs and delivery limits

An event is **serialized once**; all outputs receive the same bytes and the same `event_id`. An event that is
admitted for the file is written locally first and then put into the bounded queues of the enabled remote outputs.
Every transport has its own worker and its own queue (`delivery.queue_size`); a slow target blocks neither the local
log nor the other outputs. When a queue is full only the new event is dropped **for that output** and counted.

**Local log.** Append mode, files and archives `0600`, new directories `0700`, existing permissions are never
widened. Symlinks as the log file are refused (`O_NOFOLLOW`); a second writer is prevented by a lock
(`<path>.lock`). Rotation happens before writing a line that would take the file over `rotate_size_mb`, only between
complete lines, numbered archives `.1` (newest) to `.<keep_files>`. External rename/copytruncate rotation is not
supported. `fsync` at least every `sync_interval` and at exit: a crash can cost the last interval. An incomplete
last line of an existing file is saved to `<file>.corrupt-<UTC>` at start and cut off; `agent.started` reports this
(`details.log_repair`). A permanently unwritable log or a full disk ends the agent in a controlled way with exit
code 1: it never keeps running as if successful without its mandatory log.

**TCP.** Persistent connection, newline-delimited JSON objects; the receiver splits the byte stream itself.
Connect and write timeouts, complete writes, reconnect after an error (DNS is resolved again) and retry of the
**whole** line with the same ID. Optional TLS with regular certificate and host name verification (`tls`, `ca_file`,
`server_name`), never `InsecureSkipVerify`, never a plaintext fallback.

**UDP.** One complete event (with newline) per datagram, never split or shortened. If it exceeds `udp.max_bytes` it
is dropped for UDP only and counted (`dropped_too_large`). No acknowledgement, no retry; larger datagrams can be
fragmented and additionally get lost.

**Webhook.** `POST` with one JSONL line as the body, `Content-Type: application/x-ndjson`,
`User-Agent: process-watcher/<version>`, `X-Event-ID` and optionally `Authorization: Bearer <token>` (the value of
the variable named by `token_env`; if it is set but empty or missing, that is a configuration error at start).
`http://` and `https://`, no credentials and no fragments in the URL, no automatic redirects (a 3xx is a final
failure). Every `2xx` counts as accepted; network errors, timeouts, `408`, `429` and `5xx` are retried
(`Retry-After` up to 60 s), everything else is final. The URL is redacted in all diagnostics because it may contain
secrets. For Slack, Teams and similar services an adapter for this generic format is needed.

**Retries.** `delivery.max_retries: 5` means at most six attempts per event (TCP, webhook) with exponential backoff
from 1 s to 30 s and about ±20 % jitter; after that the event is dropped for this output and counted, and the next
one may be processed. UDP is not retried; after socket or DNS errors it reconnects with backoff (events in between
are dropped and counted).

**Guarantees and their limits.** There is **no guaranteed or exactly-once delivery**: TCP writes do not confirm
processing, after unclear partial transfers duplicates and incomplete lines on the old connection are possible, a
webhook timeout after processing can produce duplicates. Deduplicate by `event_id`. There is no remote replay across
a restart and no shared transaction with the local log; the log serves for manual redelivery. Counters for TCP and
UDP mean "handed to the transport", not "acknowledged by the receiver". See also
[internal/output/DELIVERY.md](internal/output/DELIVERY.md).

## Reaction: kill rules

> **Reaction, not blocking.** The feature reacts **after** detection. It prevents neither the execution of a program
> nor its side effects. A short-lived process such as `useradd` can be long finished before the agent reacts; an
> already vanished process is an expected outcome and does not end the monitoring. A signal accepted by the kernel
> (`signal_sent`) proves neither that the process died nor that side effects were prevented.

**Scope.** **Off** by default (`kill.enabled: false`). When on, the rules apply only to **confirmed descendants** of
the observed roots (grandchildren and all further generations too), never to the root itself, PID 1 or the agent, and
there is no system-wide search. A match leads directly to a `SIGKILL` attempt (no SIGTERM grace period) on exactly that
process instance including its threads, not on descendants or the process group (no `kill(-pgid)`, no negative PIDs).
Further descendants are judged by their own rules and stay observed after their parent ended. **Children that already
exist at start** (`process.discovered`) and those found by a later reconciliation are checked as well: with the
feature enabled, children that exist when the agent starts can therefore be killed. `kill.dry_run: true` performs the
same evaluation and audit logging but sends no signal (and opens no pidfd).

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

| YAML | Flag |
| --- | --- |
| `kill.enabled` | `--kill-enabled` |
| `kill.dry_run` | `--kill-dry-run` |
| `kill.fields` | `--kill-field` (repeatable) |
| `kill.strings` | `--kill-string` (repeatable) |
| `kill.regex` | `--kill-regex` (repeatable) |

**Matching.** Every string is a literal, case-sensitive substring (`strings.Contains`, independent of
`watch.ignore_case`). Regexes are Go `regexp` (RE2; no PCRE), compiled once at load and checked with `MatchString`:
by default a **search within** the field value; for the complete value use `^` and `$`, for case-insensitivity
`(?i)`. All strings, regexes and selected fields are OR-combined; several hits lead to **one** shared action and are
logged together.

| Field | Checked content |
| --- | --- |
| `image` | File name of the program that was actually executed (as in `process.image`); default |
| `image_path` | Complete path of the executed program, if determined unambiguously and completely |
| `argv` | **Every argument individually**, including `argv[0]`; no joining into a shell command |

A string `useradd` in the field `argv` also matches `sh -c 'useradd ...'`, because that argument contains the
string. To match only the program that was actually started, choose `fields: [image]` and for example the regex
`^useradd$`. Neither parent arguments nor the event text are checked.

**Inherited image.** A new process carries the image of its creator until its exec. If a rule matches the image of an
observed root (or an intermediate process), it therefore matches every direct child already at `process.fork`, before
the child starts its own program; the root itself is never killed. Rules should aim at the image of the **unwanted**
program.

**Validation.** Rejected are empty strings and regexes, syntactically invalid regexes, unknown fields and an empty
field list (error messages name the path and the list index). When the feature is enabled at least one rule is
required, and the field `argv` explicitly requires `capture.argv: true`; the capture is never enabled silently.
**Only demonstrably complete values** count: missing values, merely presumed ones (arguments cached from the parent
at a fork) or truncated values are no basis for a match (important for regexes with an end anchor). Other fully
available fields can still match.

**Evaluation** happens at `process.exec`, `process.discovered` and at new process instances from `process.fork`
(there only with inherited image/path), as soon as the assignment to the tree is established; `process.exit` and failed
execs trigger nothing. It happens **before** the output exclusions: `exclude.*`, `watch.max_depth` and the limit of
the ancestor array restrict only the normal messages, not the kill rules. If the assignment to the root is unclear
after collection losses (`lineage.complete: false`), **no action is taken on suspicion** (`skipped`,
`lineage_unconfirmed`). The marking applies to the affected instance and all descendants that later derive from it,
as long as they live. This is deliberately the safe side but has a consequence: whoever creates a ring buffer
overflow on purpose (fork storm) can withdraw the processes created during it, and their descendants, from the kill
rules. `agent.gap` and `collector.lost_total` in `agent.health` show this and should be monitored; the kill feature
does not replace prevention.

**Sequence and process identity.** A PID alone is no identity. The action path is a single worker with at most **256
waiting actions**; network delivery and remote retries cannot delay a kill attempt, and event capture never waits for
the end of a target process.

1. Tree membership, permitted target and match are checked from the capture event; the decision
   (`response.kill_requested`, `outcome: pending`) is **written locally before** anything is signalled.
2. `pidfd_open` for the host TGID (no thread handles, no external programs such as `kill`/`pkill`).
3. The identity is verified exactly **after** opening: the kernel keeps a table `tgid → start_boottime` with the same
   field that the fork hooks and the snapshot iterator deliver; if TGID and **exact** start time do not match the
   decision, the action is skipped (`identity_mismatch`), and if they cannot be proven, also (`identity_unverified`).
   There is no fallback to an unsafe `kill(pid, SIGKILL)`.
4. Right before the signal the match fields are checked again (`/proc/<pid>/exe`, `/proc/<pid>/cmdline`) and program
   changes observed in the event stream are taken into account; if the original match can no longer be proven, the
   action is skipped (`match_no_longer_verified`). A new exec is a new event with its own evaluation.
5. `SIGKILL` goes exclusively through the verified pidfd; the handle is closed on every path. A pidfd binds the
   signal to the concrete process instance: if it ends and the PID is reused, the signal never reaches the
   replacement process.

**Remaining time window.** The identity check and the signal are not an atomic lock: between the last check and the
signal the same instance can still execute another exec or change its arguments. A pidfd also does not prevent a mix-up
that already existed before it was opened because of a reused PID; the exact start time check after opening serves
that.

Per `(process_id, exec_index)` there is **at most one signal attempt** (`exec_index` is 0 for a snapshot and for a
fork before the first observed exec); duplicate actions from repeated events, several hits or snapshots are
suppressed, a later successful exec is evaluated anew. A failed attempt is never repeated in a loop; remote retries
repeat only audit events. If the queue is full, the action is logged as `skipped` / `action_queue_full`; during an
orderly shutdown no new actions arise, waiting ones become `skipped` / `shutdown`. A local write error ends the agent
in a controlled way and starts no further actions. If `pidfd_open`/`pidfd_send_signal` is missing, the agent refuses
to start when the feature is enabled (exit code 3).

**Audit.** `response.kill_requested` (intended action, `outcome: pending`) and exactly one `response.kill_result`
share `details.action_id`; `details.trigger_event_id` refers to the triggering process event (even if that event was
removed from the output by exclusions or the depth limit). The events have `source: agent`, the target under
`process`, `parent`, `root`, `lineage`, `data_quality`, and are stored locally and passed to the remote outputs
independent of exclusions and output depth. `details` contains among others `action: kill`, `signal: SIGKILL`,
`dry_run`, `exec_index`, all matching rules (`ref` like `kill.regex[0]`, `type`, `pattern`, `field`, for arguments
`arg_index`), `outcome`, `reason`, the system error (`error.errno`), `decided_at`, `signal_attempted_at` and the
distances to the triggering kernel event (`decision_latency_ns`, `attempt_latency_ns`). Outcomes: `dry_run`,
`signal_sent`, `already_exited`, `permission_denied`, `error`, `skipped` with a reason (`identity_unverified`,
`identity_mismatch`, `match_no_longer_verified`, `action_queue_full`, `shutdown`, `lineage_unconfirmed`,
`actions_stopped`). A `response.kill_result` without a preceding `kill_requested` exists only for
`lineage_unconfirmed`. The later `process.exit` of the instance carries `details.response_action_id` (a correlation,
no causal claim) and only exit/signal data that were actually captured. An agent crash can leave an open `pending`.
`agent.health` contains the counters: rule hits, signal attempts, signals accepted by the kernel, targets already
gone, skipped actions by reason, errors, dry-run actions, queue length and latency.

**Privileges.** Besides root, `CAP_BPF`, `CAP_PERFMON`, `CAP_KILL` (signals to other users' processes) and
`CAP_SYS_PTRACE` (`/proc/<pid>/exe` of other users' processes for the re-check) are needed. Without permission the
agent reports `permission_denied` with `error.errno` and keeps observing.

**Reaction time (measured).** On a native arm64 kernel 6.12.54 (100 own target processes, 20 ms apart) the time from
the kernel's exec record to the locally written decision was **0.13 ms** on average (p95 0.19 ms, maximum 1.2 ms) and
to the return of `pidfd_send_signal` **0.27 ms** on average (p95 0.47 ms, maximum 1.4 ms); measured from outside,
from the start of the target process to its end, 0.47 ms on average (maximum 2.2 ms). Under heavy CPU load the values
grow to 1 to 3 ms; values from emulated CPUs are no measurement of the hardware. This is the time until the
**signal**: the target process keeps running until then and, until the signal takes effect, afterwards as well.
Details and spread: [docs/measurements.md](docs/measurements.md).

## Operation: health, gaps, shutdown

`agent.health` (every `runtime.health_interval`) contains among others the number of roots and tracked instances
(`tracked`), collection losses by cause (`collector.lost.fork|exec|exit`, counted by the kernel, independent of the
delivery of a ring buffer event), exclusion and depth counters, queue lengths and, per output, the counters
handed over/dropped/failed/retries; counters apply to the current run. A healthy remote target sees the failures of
another one in it. Health and gap messages are stored locally and delivered to the active remote outputs; transport
errors produce no events of their own (no feedback loop).

**Gaps.** Ring buffer losses, a full process limit (`runtime.max_processes`) or a failed reconciliation produce
`agent.gap`. Afterwards the living processes are compared again (at most once per second); what is found is marked
with `lineage.complete: false` and `data_quality.collection_gap: true`. A snapshot cannot restore lost short-lived
processes. Losses are counted from the moment the hooks are attached: an overflow in the start window, while the
first snapshot is taken and applied, also produces an `agent.gap` and marks the processes discovered then. A restart
begins a new run with a new `agent_instance_id` and a recognizable start window. If the agent cannot read the
kernel's loss counters ten times in a row, it exits with code 1 instead of continuing without loss detection.

**Resources.** The process memory is bounded by `runtime.max_processes` (living instances plus ancestors still
needed); finished entries that are no longer referenced are released. The ring buffer is mapped twice: the RSS is
about `2 × ring_buffer_mb + 15 MiB`. All queues are bounded. With argument capture enabled every tracked instance
holds up to 4 KiB of arguments (upper bound of the process memory: `max_processes × 4 KiB` additionally).
Measurements: [docs/measurements.md](docs/measurements.md).

**Shutdown** (SIGINT/SIGTERM): no new kill actions, complete the waiting actions, stop the capture, process the
events already captured, drain the remote queues until `runtime.shutdown_timeout`, count the remaining entries
(`agent.stopped.details.undelivered_at_shutdown`), store `agent.stopped` **locally**, sync the file. No artificial
exit events are created for observed processes that are still running. If writing `agent.stopped`, the final `fsync`
or closing the file fails (full disk), the agent exits with code 1, even if it was ended by a signal.

## Limits

- Linux only, `amd64`/`arm64`; no operation in a container (the initial PID namespace is required).
- No history from before the hooks were activated; after collection losses the lineage of affected processes is
  unconfirmed. Processes that were already orphaned before the start cannot be assigned to an earlier root.
- A process whose thread group leader has ended and whose image is no longer readable at snapshot time is only
  recognized at its next exec.
- One target per remote transport; no persistent remote queue; no guaranteed delivery.
- Every root that is newly admitted at run time triggers a reconciliation (at most once per second), because only the
  snapshot knows its already living children. With very broad patterns such as `sh` this reconciliation therefore runs
  continuously; cost: [docs/measurements.md](docs/measurements.md).
- No monitoring of CPU, RAM, files or network of the observed processes; no automatic attack detection; no user
  interface; no Kubernetes integration.
- The kill feature reacts afterwards and is no preventive protection (see above).
- The path of the executed program is determined relative to the mount namespace of the process and limited to 1024
  bytes (truncated: suffix, marked in `truncated_fields`).

## Building and testing

```bash
make build-linux            # static binaries dist/process-watcher-linux-{amd64,arm64}
make release-archives VERSION=v0.1.0   # the release archives (binary, config, license) exactly as the release workflow builds them
make test                   # unit tests (macOS or Linux), including schema and golden checks
make generate               # regenerate the eBPF objects (Docker, see below)
```

The eBPF objects are **not** generated by the normal Go build: `internal/collector/ebpf/pw_bpfel.{go,o}` are
checked in and embedded; one object (`bpfel`) serves `amd64` and `arm64` because the programs use CO-RE and `tp_btf`.
`make generate` regenerates them reproducibly in the container from [build/ebpf/Dockerfile](build/ebpf/Dockerfile)
(base image pinned by digest, Debian packages from the snapshot of the build date of the base image: clang 19.1.7,
libbpf 1.5.0). The libbpf headers are under `internal/collector/ebpf/bpf/headers/`, the kernel types are a minimal
CO-RE definition in `internal/collector/ebpf/bpf/vmlinux_min.h` (no generated `vmlinux.h`).

Tests with a real kernel (they need root, the initial PID namespace and BPF; **no mocks for the collector**):

```bash
make test-docker            # collector, response and agent end-to-end in a privileged container (--pid=host)
make test-race-docker       # race detector over the Go pipeline on Linux
make bench-docker           # CPU, RSS, throughput, latency, kill reaction time (docs/measurements.md)
make test-vm ARCH=amd64 KERNEL=ubuntu-5.15    # collector tests in a real kernel under QEMU, see tests/vm/README.md
make test-vm-matrix         # the same for all kernels and both architectures
make test-vm-e2e ARCH=arm64 KERNEL=ubuntu-5.15   # agent end-to-end tests in the QEMU guest
```

Which runs actually took place and with what result is recorded in [docs/acceptance.md](docs/acceptance.md), the
tested kernels in [docs/compatibility.md](docs/compatibility.md). A cross build is no substitute for a run: `amd64`
was only executed in an emulated guest.

Structure: `internal/collector/ebpf` (programs, loader, wire format), `internal/proctree` (process model),
`internal/filter`, `internal/killrule`, `internal/response` (pidfd worker), `internal/event` (contract),
`internal/output` (file, TCP, UDP, webhook), `internal/config`, `internal/app` (main loop), `tests/integration`
(agent against real processes), `tests/vm` (kernel matrix), `tools/release` (release archives), `testdata/golden`,
`schema`, `examples`, `packaging`, `.github/workflows` (CI and release).

License: GPL-3.0, see [LICENSE](LICENSE). The sources of the eBPF programs carry `GPL-2.0-or-later` (compatible with
GPL-3.0); the object carries the license `GPL`, which the kernel requires for GPL-only helpers.
