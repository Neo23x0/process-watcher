## Delivery limits

The local JSONL log is the only reliable output: every line goes out with a single write, write errors are reported
(controlled abort), `fsync` runs at least every `sync_interval` and at exit. A crash can cost the last interval; a
torn last line is saved to `<file>.corrupt-<UTC>` at start. External rotation (rename/copytruncate) is not supported.
Remote outputs are best effort: each has its own bounded queue and a worker; when it is full, only the new event is
dropped for that output and counted. There is no replay across a restart and no transaction with the file.
TCP: "handed over" means written into the socket without an error, not acknowledged; after errors it reconnects (DNS is
resolved again) and repeats the whole line, so duplicates and truncated lines on the old connection are possible; TLS
verifies certificate and host name, without a plaintext fallback. UDP: one event per datagram, no acknowledgement, no
retry; events above `max_bytes` are dropped for UDP only, after socket errors it reconnects with backoff (events in
between are dropped and counted). Webhook: 2xx counts as accepted; network errors, timeouts, 408, 429 and 5xx are
retried (`Retry-After` up to 60 s), everything else including 3xx (redirects are not followed) is final, after a
timeout duplicates are possible. Retries: at most `max_retries`+1 attempts with backoff from 1 s to 30 s (±20 %), then
the event is dropped and counted. At shutdown the queues are drained until `shutdown_timeout`, the rest is counted and
dropped.
