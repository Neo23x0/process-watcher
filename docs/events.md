# Events, process trees, exclusions and argument capture

How the agent follows process trees and what its events contain. The [README](../README.md) has the short version; the binding format contract is [schema/event.schema.json](../schema/event.schema.json).

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
[schema/event.schema.json](../schema/event.schema.json) (JSON Schema 2020-12); all events of the tests and the golden
examples in [testdata/golden/](../testdata/golden/) are checked against it.

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
`process.argv_complete`, `process.argv_capture`, `parent.image_path`, `data_quality.sanitized_fields` and
`details.exec_filename`, `previous_image` and `thread_exec` as **additive** fields; kill audit events add
`details.chain`.

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
When enabled, the arguments are captured at exec **in the kernel**, not later from `/proc`: at most
`capture.argv_max_args` arguments (default 32, 1 to 1024) and `capture.argv_max_bytes` raw bytes, arguments plus their
NUL terminators (default 4096, 256 to 16383). It is an array, not a joined shell command. **An argument that the byte
limit cuts is omitted from `argv`**, and the event says what happened: an overflow is listed in
`data_quality.truncated_fields`, `process.argv_complete` is `false` and `process.argv_capture` holds `argc` (the
kernel's count), `captured_args`, `total_bytes` (the size of the argument area at exec), `captured_bytes`, `limit_args`,
`limit_bytes` and `partial` (`index`, the first bytes of the cut argument in `value`, `captured_bytes`). The partial
argument is evidence for an investigation and is never used by `exclude.argv_contains` or a kill rule. For
`sh -c -- <command>` (what PHP's `shell_exec` starts) the longest command that fits the default limit is 4,086 bytes.
Forks carry the inherited arguments of the creator, marked `argv_state: inherited`. Processes that were already running
at start get their arguments (`snapshot`) from `/proc/<pid>/cmdline`, after the start tick was compared **before and
after** reading with the kernel start time of the instance, so a reused PID is never mixed up; if that fails, `argv` is
`null` with a reason. Environment variables are not captured. Enable the capture only if the receivers and the local
log are prepared for it.
