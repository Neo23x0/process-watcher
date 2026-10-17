# Operation and limits

Health reporting, loss handling, shutdown and the known limits. The [README](../README.md#operation) has the short version.

## Health, gaps and shutdown

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
Measurements: [measurements.md](measurements.md).

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
  continuously; cost: [measurements.md](measurements.md).
- No monitoring of CPU, RAM, files or network of the observed processes; no automatic attack detection; no user
  interface; no Kubernetes integration.
- The kill feature reacts afterwards and is no preventive protection (see [kill-rules.md](kill-rules.md)).
- The path of the executed program is determined relative to the mount namespace of the process and limited to 1024
  bytes (truncated: suffix, marked in `truncated_fields`).
