# Outputs and delivery limits

How events leave the agent and what is guaranteed. The [README](../README.md#outputs) has the short version; [internal/output/DELIVERY.md](../internal/output/DELIVERY.md) is the compact statement of the delivery limits.

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
[internal/output/DELIVERY.md](../internal/output/DELIVERY.md).
