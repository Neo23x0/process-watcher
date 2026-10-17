# Measurements: resources, throughput, latency, losses and reaction time

All numbers come from runs on 2026-10-17. There are no performance promises beyond these measurements.

## Environment and method

- **Environment:** Docker Desktop VM on an Apple silicon Mac, Linux `6.12.54-linuxkit`, `arm64`, 12 vCPUs, privileged
  container with `--pid=host` (initial PID namespace), Go 1.26.0. The kernel runs **natively** on the CPU, not
  emulated. The measurement runs only while no QEMU guest and no other test is active, and counts only if none was
  started during the run either (container events observed); otherwise it was repeated. The resource table comes from
  such a run. In the first run a guest appeared only after the reaction time measurement, so only that measurement
  is taken from it.
- **Command:** `make bench-docker` (the tests `TestMeasureResourcesAndThroughput` and `TestKillReactionLatency` in
  `tests/integration`). Raw data: `dist/e2e/report/perf.json` and `kill-latency.json`.
- **Load:** 10 s per phase; `NumCPU/2` = 6 processes start `/bin/true` children in a loop without pause (every start
  is one fork, one exec and one exit). Phases: idle, load **outside** the observed tree (the agent only filters), load
  **inside** the tree (every starter is a root itself; all events are logged), and the same with argument capture.
  The agent runs with the default values (ring buffer 16 MiB, log `rotate_size_mb: 100`, `keep_files: 5`).
- **Quantities:** CPU = `utime + stime` of the agent process from `/proc/<pid>/stat` (percent of **one** core); RSS =
  `VmHWM` (peak) and `VmRSS` at the end; latency = `observed_at − timestamp` per kernel event, that is the time from
  the event in the kernel to its processing in the agent (ring buffer, decoding, process model, event building);
  losses = the lost records counted by the kernel (`agent.stopped.details.collector.lost_total`).

## Idle and load

| Phase | Agent CPU | RSS peak / end | Starts/s | Kernel records | lost | process events written |
| --- | --- | --- | --- | --- | --- | --- |
| Idle (10 s) | 0.2 % | 58.4 / 44.0 MiB | 0 | 0 | 0 | 0 |
| Load outside the tree | 15.3 % | 63.8 / 50.4 MiB | 21,099 | 634,266 | 0 | 0 (filtered only) |
| Load inside the tree | 57.5 % | 66.4 / 51.2 MiB | 21,231 | 638,010 | 0 | 638,004 (63,695/s) |
| Load inside the tree, arguments on | 56.7 % | 62.8 / 49.4 MiB | 20,757 | 624,540 | 0 | 624,534 (62,274/s) |

- At about **21,000 process starts per second** (roughly 63,000 kernel records per second) the agent loses nothing
  with the default ring buffer: the number of written process events matches the number of kernel records up to a
  difference of six. It uses about **0.57 of one core** and at most 66 MiB while doing so.
- At rest the CPU is 0.2 % (one statistics poll per second, housekeeping when idle). The idle RSS is expected at
  `2 × ring_buffer_mb + 15 MiB` (47 MiB); measured 44 MiB at the end. The peak at the start comes from loading the
  kernel BTF and the programs and is returned to the operating system after the start.
- **Latency kernel event → processing** under this load: median 0.030 ms, p95 0.26 ms (with arguments 0.24 ms), mean
  0.43 ms; p99 16 ms and maximum 38 to 44 ms, because the load almost saturates the agent and events wait in the ring
  buffer. Without load the collector test `TestHookLatency` shows about **20 µs** on average (maximum 38 µs, n = 50)
  from the exit in the kernel to the hand-over to `Next`.
- The log rotates several times under this load (`rotate_size_mb: 100`, `keep_files: 5`); of the 638,004 written events
  420,729 were still on disk at the end. That is why the test reports the events **written** by the agent (counter
  `details.events` in `agent.stopped`) and not the lines of the file.

## Overload and losses

- **Load limit without loss:** a sustained load of 21,000 starts/s is loss-free (see above). A ring buffer of 1 MiB
  holds, as measured, **3,644 complete process lifecycles** (about 288 bytes per child from the fork, exec and exit
  records); the default buffer of 16 MiB accordingly holds about 58,000 children, which is just under three seconds of
  backlog at 21,000 starts/s.
- **Forced overflow** (`TestOverloadIsMeasuredAndReported`): ring buffer 1 MiB, the agent is stopped with `SIGSTOP`
  while 6,000 children are created. Result: 3,644 fork records reach the buffer, 2,361 fork records are lost (7,083
  records in total); the kernel counters add up with the delivered records to the generated processes. The agent
  reports `agent.gap` (`ring_buffer_full`) with the loss numbers, marks the processes discovered afterwards as
  unconfirmed and observes a tree started afterwards completely.
- **Small buffer** (`TestLossIsCountedInTheKernel`, 6.12): 1,164 records lost (fork 387, exec 387, exit 390), 42
  delivered; delivered plus lost gives the total.
- **Short-lived children** (`TestShortLivedChildrenNeedNoProcAccess`): 1,000 children after `agent.ready`, all logged
  with fork, exec and exit, kernel loss 0, no evaluation of `/proc` needed.

## Start, snapshot and reconciliation

| Processes in the system | Start to `agent.ready` | Snapshot (BPF task iterator) |
| --- | --- | --- |
| 15 | 163 to 166 ms | 0.11 to 0.15 ms |
| 1,014 | 166 to 170 ms | 0.87 to 0.93 ms |
| 4,015 | 165 to 174 ms | 3.0 to 4.3 ms |

The start (load the kernel BTF, load and attach the programs, snapshot, `agent.ready`) takes about 165 ms and hardly
depends on the number of processes; the snapshot costs about **1 µs per process**. Every root that is newly admitted
at run time triggers a reconciliation at most once per second; even with 4,000 processes in the system that is below
0.5 % of one core for the snapshot (without the process model).

## Kill reaction time

`TestKillReactionLatency`: 100 target processes started one after another (20 ms apart), own test processes, rule on
the image of the child; measured from the kernel timestamp of the exec record (`CLOCK_BOOTTIME`). Two clean runs on
the setup described above (arm64, 6.12.54, native):

| Quantity | Run 1 | Run 2 |
| --- | --- | --- |
| Decision (`response.kill_requested` written locally), mean / p95 / max | 0.107 / 0.167 / 0.358 ms | 0.128 / 0.189 / 1.173 ms |
| Signal attempt (`pidfd_send_signal` returned), mean / p50 / p95 / p99 / max | 0.249 / 0.240 / 0.365 / 0.449 / 0.571 ms | 0.274 / 0.248 / 0.468 / 1.089 / 1.398 ms |
| From outside, creator clock (start returned until wait returned), mean / p95 / max | 0.441 / 0.547 / 0.915 ms | 0.474 / 0.748 / 2.172 ms |
| From outside, test clock (until the end message was read), mean / p95 / max | 0.501 / 0.633 / 0.965 ms | 0.534 / 0.810 / 2.241 ms |

Further runs by the test authors on the same setup gave a mean of 0.15 to 0.27 ms for the signal attempt; under
artificially generated CPU load (36 to 48 busy processes) the mean grew to 0.8 to 1.3 ms and p95 to 1.8 to 3 ms.
**Values from an emulated CPU (QEMU TCG)** (signal attempt 1.9 ms on average, external 3 ms) say nothing about
hardware and are not used.

Interpretation: this is the time the agent needs from the kernel's exec event to the signal. The target process keeps
running in this time; a short-lived process can be long finished within 0.3 ms. The feature remains a reaction, not
blocking.

## Delivery of the remote outputs (loopback, arm64)

Measured by the `TestOut*` tests in `tests/integration`; the limits are those described in
[internal/output/DELIVERY.md](../internal/output/DELIVERY.md) and in the README:

- **UDP:** the smallest event is 1,039 bytes (`agent.ready`), usual process events 1.0 to 1.9 KB, exec/exit with a
  2,000 byte argument about 3.5 KB, with 3,000 bytes about 4.4 KB. With `udp.max_bytes: 512` all events are dropped
  for UDP only (`dropped_too_large`), the other outputs receive them completely; with 2,560, 47 fit and 80 large ones
  are dropped. On loopback with a 64 MiB receive buffer no datagram was lost (465/465, 1,812/1,812, 2,275/2,275);
  losses through a full queue (`queue_size: 50`) occurred only under bursts of 2,500 to 5,000 events per second.
- **TCP:** a receiver with a 2 KiB buffer stops the agent after about 417 events; after `write_timeout` (1 s) the agent
  reconnects and sends the **whole** line again (no duplicates, all events arrived, a fragment remained on the old
  connection). With `queue_size: 50`, 1,990 of 2,407 events were dropped (`dropped_queue_full`), the queue never went
  above 50, nothing remained open at exit.
- **Webhook:** 500 followed by 200: retry after about 1 s, counted once; `Retry-After: 3` is honored with at least
  2.9 s (the date form as well); a timeout (1 s) is retried later; with `max_retries: 2` exactly three attempts over at
  least four seconds, then `failed` and the next event follows; 400 and 302 (not followed) are final.
- **Shutdown** (`shutdown_timeout: 3 s`, receiver with 300 ms per request, 457 events in the queue): end after 3.00 to
  3.05 s, 10 to 11 events still delivered, `undelivered_at_shutdown` 446, which equals offered minus received events
  within ±1. Full disk (tmpfs with 64 KiB): exit code 1 in under a second, stderr names "no space left on device",
  UDP received all events written until then.
- **Rotation** (1 MiB, `keep_files: 3`): six rotations, only archives `.1` to `.3`, the `sequence` runs without gaps
  across the files, all 1,812 events reached all remote outputs.

## Not measured

- **Real amd64 hardware** and any CPU other than the Apple processor: no timing, throughput or CPU number applies
  there.
- **Long-running operation** over hours or days (memory growth, rotation over a long time) and hosts with very many
  simultaneously observed processes; the bound (`runtime.max_processes`) is tested in the unit and agent tests, not its
  memory use at 65,536 instances.
- **Networks other than loopback**, DNS names as targets and the upper bound of 60 s for `Retry-After` (it would cost
  60 s of waiting).
- Whether another process load (for example starts with very long paths or 4 KiB arguments) costs more per start: the
  "arguments on" phase measures short arguments.
