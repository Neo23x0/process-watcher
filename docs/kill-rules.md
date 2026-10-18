# Kill rules (reaction)

Complete reference of the optional kill feature. The [README](../README.md#kill-rules) has the short version.

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
  spare_root_image: false    # true: never kill a descendant that runs its root's executable
```

| YAML | Flag |
| --- | --- |
| `kill.enabled` | `--kill-enabled` |
| `kill.dry_run` | `--kill-dry-run` |
| `kill.fields` | `--kill-field` (repeatable) |
| `kill.strings` | `--kill-string` (repeatable) |
| `kill.regex` | `--kill-regex` (repeatable) |
| `kill.spare_root_image` | `--kill-spare-root-image` |

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

**Protecting a service from its own rule.** A service master (php-fpm, apache2, nginx) forks its workers with its own
image, and a master that reloads executes itself again and forks a new master. A rule that matches that image, for
example `php` while `php-fpm` is watched, therefore hits every worker as it is forked and every worker that exists at
start; the master survives only because it is a root, and the service loses all its workers (measured against a real
PHP-FPM behind nginx: 9,501 signals in 3 seconds, requests answered with 502). Two safeguards exist:

- `check-config` prints a warning, and the agent logs one and lists it in `agent.started` (`details.kill.warnings`),
  when a kill string is contained in a watch pattern or a kill regex matches one (for `image` and `image_path`).
- `kill.spare_root_image: true` never kills a descendant whose executable is the one its root had when it was admitted
  (compared by path, by image name when a path is unknown). The decision is audited as `response.kill_result` with
  `outcome: skipped`, `reason: root_image_spared` and counted in `agent.health` (`response.skipped`). It spares workers
  and a re-executed master; what a worker starts, and a worker that replaces itself with another program by exec, is
  still judged by the rules. It is off by default so that existing rule sets keep their meaning.

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
`root_image_spared`, `actions_stopped`). A `response.kill_result` without a preceding `kill_requested` exists only for
`lineage_unconfirmed` and `root_image_spared`. `details.chain` lists the ancestors of the target from the root to its
direct parent (at most 8, the root and the nearest ones; `chain_truncated`) with `process_id`, `pid`, `image`,
`image_path`, `exec_index` and `argv` (at most 2 KiB each, `argv_complete`), so the decision explains itself without the
earlier events. The later `process.exit` of the instance carries `details.response_action_id` (a correlation,
no causal claim) and only exit/signal data that were actually captured. An agent crash can leave an open `pending`.
`agent.health` contains the counters: rule hits, signal attempts, signals accepted by the kernel, targets already
gone, skipped actions by reason, errors, dry-run actions, queue length and latency.

**Confirmation.** `signal_sent` only says that the kernel accepted the signal. For a long-running target the exit
confirms it (`process.exit` with `details.signal: 9` and the same `response_action_id`); a short-lived program can end
by itself just before the signal arrives, with the signal still accepted (measured with `sh -c 'uname -s'`: about 60 %
of 200 shells ended with SIGKILL, the rest had finished first).

**Privileges.** Besides root, `CAP_BPF`, `CAP_PERFMON`, `CAP_KILL` (signals to other users' processes) and
`CAP_SYS_PTRACE` (`/proc/<pid>/exe` of other users' processes for the re-check) are needed. Without permission the
agent reports `permission_denied` with `error.errno` and keeps observing.

**Reaction time (measured).** On a native arm64 kernel 6.12.54 (100 own target processes, 20 ms apart) the time from
the kernel's exec record to the locally written decision was **0.13 ms** on average (p95 0.19 ms, maximum 1.2 ms) and
to the return of `pidfd_send_signal` **0.27 ms** on average (p95 0.47 ms, maximum 1.4 ms); measured from outside,
from the start of the target process to its end, 0.47 ms on average (maximum 2.2 ms). Under heavy CPU load the values
grow to 1 to 3 ms; values from emulated CPUs are no measurement of the hardware. This is the time until the
**signal**: the target process keeps running until then and, until the signal takes effect, afterwards as well.
Details and spread: [measurements.md](measurements.md).
