# PHP deployments: what process-watcher sees, what it can do, what it cannot

Use case: monitoring PHP applications on Linux and, optionally, terminating suspicious descendant processes.
Nothing here assumes a particular vulnerability, version, exploit technique or advisory, and nothing here detects or
blocks a specific one. process-watcher is an **additional detection and response layer**: it records which programs a
PHP process starts, with their command lines, and can optionally send `SIGKILL` to such programs after the fact. It
does not prevent the exploitation of an unknown vulnerability.

Everything below was checked on real processes. Section 9 says exactly where and what was not.

## 1. What to deploy first

1. **Watch the process that runs PHP, not the web server** (section 2): `php-fpm` for NGINX or Apache with PHP-FPM,
   `apache2`/`httpd` for mod_php. Watching `nginx` or `apache2` in front of PHP-FPM sees nothing PHP starts.
2. **Capture arguments and raise the limits**: `capture.argv: true`, `argv_max_bytes: 16383`, `argv_max_args: 64`
   (section 4). With the defaults, a shell command longer than 4,086 bytes disappears from `argv`.
3. **Observe first, then dry-run, then (maybe) kill** (section 6). Never write a response rule that matches the service's
   own executable: a rule for `php` kills the PHP-FPM workers (measured: 9,501 signals in 3 seconds, 502 for the
   requests). `kill.spare_root_image: true` makes that mistake harmless.
4. Know the blind spot: **code that runs inside a worker and starts no process is invisible** (section 5).

Ready-made configurations are in [examples/php/](../examples/php/); `process-watcher check-config --config <file>`
validates one. They also ship inside every release archive under `php/`, so they are usable right after unpacking,
without cloning the repository (see the README's install steps).

## 2. Which executable to watch

`image` in an event is the file name of the program that was actually executed, resolved through symlinks. It is not
the service name (`php8.4-fpm.service`), not the process title shown by `ps` (`php-fpm: pool www`), not `comm`, and not
`argv[0]`. Observed for one FPM worker on Debian 13: image `php-fpm8.4`, comm `php-fpm8.4`, title
`php-fpm: pool www`, `/proc/<pid>/exe` -> `/usr/sbin/php-fpm8.4`.

| Deployment | Process that executes PHP | Watch | Verified executable (path) | Misses |
| --- | --- | --- | --- | --- |
| NGINX + PHP-FPM | FPM master and pool workers, a separate service | `php-fpm` | `php-fpm8.4` (`/usr/sbin`, Debian 13), `php-fpm8.3` (Ubuntu 24.04), `php-fpm8.2` (Debian 12), `php-fpm` (`/usr/sbin`, Rocky 9; `/usr/local/sbin`, official images) | A watch on `nginx` sees none of it (verified) |
| Apache + `proxy_fcgi` + PHP-FPM | the same FPM service | `php-fpm` | as above | A watch on `apache2` sees none of it (verified) |
| Apache + `mod_php` | the Apache worker processes; there is **no php process** | `apache2` (Debian, Ubuntu, official image) or `httpd` (RHEL family) | `/usr/sbin/apache2`, `/usr/sbin/httpd`; `libphp8.4.so` is mapped into the workers | A watch on `php` finds nothing (verified) |
| PHP as FastCGI daemon (`php-cgi -b`, spawn-fcgi) | a `php-cgi` master with children | `php-cgi` | `php-cgi8.4`, `php-cgi8.3`, `php-cgi8.2` (`/usr/bin`), `php-cgi` (Rocky, official images) | |
| Apache `mod_fcgid` (Debian wrapper) | `/usr/lib/cgi-bin/php8.4`, started by Apache | `apache2` or `php8.4` | image **`php8.4`**, not `php-cgi` | A watch on `php-cgi` misses it (verified) |
| PHP CLI, cron, queue workers | the `php` interpreter, a root of its own | `php8.` (versioned Debian/Ubuntu) or `php` | `php8.4`, `php8.3`, `php8.2` (`/usr/bin`; `/usr/bin/php` is a link); `php` (Rocky, official images) | |

Notes that decide whether a watch works:

- **`php` is not a safe universal substring.** It selects FPM, CGI and CLI binaries alike. `php8.` selects the versioned CLI
  and the versioned CGI wrapper but not `php-fpm8.4`. `php-fpm` selects every FPM version and pool.
- **Several PHP versions and pools**: one FPM master per version (all matched by `php-fpm`); pools are only worker titles
  of one master. A second master is a second root.
- **Alpine**: every busybox applet runs as image `busybox` (path `/bin/busybox`; verified for `sh`, `uname` and `id`), so
  an image rule cannot tell a shell from other programs, and rules written for `sh|dash|bash` never match. The arguments
  do (`sh -c ...`); rules on `argv` test every argument, there is no rule on `argv[0]` alone.
- **Already-running workers** are discovered at start (`process.discovered`, role `descendant`, depth 1, root = the master).
  Their `argv` comes from `/proc` and shows the process title, not the arguments of the exec (`argv_state: snapshot`).
- **Reload** (`kill -USR2 <master>`): the master executes itself again (root `process.exec`, same PID), forks a **new
  master that is a depth 1 descendant of the old root**, and the old master exits; the new workers are depth 2 and keep
  the original root. The pid file then names the new master, while events keep naming the original one (verified).
- **Containers, chroots, namespaces**: PIDs are host PIDs, so the agent must run on the host (it refuses to run in a
  container) and sees containerized PHP. `image_path` is relative to the **mount namespace root**: container-relative for
  a container, and with a chroot the chroot directory appears in it (`/srv/jail/usr/local/bin/x`) while
  `details.exec_filename` keeps the path the process asked for (`/usr/local/bin/x`). A **remote FastCGI backend**
  needs the agent on the backend host.

### Read-only discovery

```bash
# What runs PHP, what is it really called, who is the parent?
ps -eo pid,ppid,user,comm,args --forest | grep -E 'php|nginx|apache2|httpd' | grep -v grep
for p in $(pgrep -f 'php|apache2|httpd|nginx'); do printf '%s %s\n' "$p" "$(readlink /proc/$p/exe)"; done | sort -k2 -u

# Which handler connects the web server to PHP?
nginx -T 2>/dev/null | grep -E 'fastcgi_pass|fastcgi_param SCRIPT'
apachectl -t -D DUMP_MODULES 2>/dev/null | grep -E 'php|proxy_fcgi|fcgid|cgi'
grep -RhE 'SetHandler|AddHandler|FcgidWrapper|ProxyPassMatch' /etc/apache2 /etc/httpd 2>/dev/null
ls /etc/php/*/fpm/pool.d /etc/php-fpm.d 2>/dev/null

# What does the agent call them? (observation only, nothing is written outside the log)
sudo timeout 5 process-watcher --watch-image-contains php --watch-image-contains apache2 \
     --watch-image-contains httpd --watch-image-contains nginx --log-file /tmp/discover.jsonl
jq -r 'select(.event_type=="process.discovered" and .lineage.role=="root") | "\(.process.image)\t\(.process.image_path)"' /tmp/discover.jsonl | sort | uniq -c
```

## 3. Configurations and one-line commands

| Deployment | File | One-line equivalent (add `--log-file /var/log/process-watcher/events.jsonl`) |
| --- | --- | --- |
| PHP-FPM behind NGINX or Apache | [php-fpm-observe.yaml](../examples/php/php-fpm-observe.yaml) | `--watch-image-contains php-fpm --capture-argv=true --capture-argv-max-bytes 16383 --capture-argv-max-args 64` |
| Apache with mod_php | [apache-mod-php.yaml](../examples/php/apache-mod-php.yaml) | `--watch-image-contains apache2 --watch-image-contains httpd --capture-argv=true --capture-argv-max-bytes 16383 --capture-argv-max-args 64` |
| php-cgi, FastCGI daemon | [php-cgi.yaml](../examples/php/php-cgi.yaml) | `--watch-image-contains php-cgi --capture-argv=true ...` |
| PHP CLI workers | [php-cli-workers.yaml](../examples/php/php-cli-workers.yaml) | `--watch-image-contains php8. --capture-argv=true ...` |
| FPM, response rules as a dry run | [php-fpm-dry-run.yaml](../examples/php/php-fpm-dry-run.yaml) | the observe line plus `--kill-enabled=true --kill-dry-run=true --kill-spare-root-image=true --kill-field image --kill-regex '^(sh\|dash\|bash\|zsh\|ksh\|ash)$' --kill-regex '^python[0-9.]*$' --kill-regex '^(perl\|ruby[0-9.]*)$' --kill-regex '^(nc\|nc\.openbsd\|nc\.traditional\|ncat\|socat[0-9]*\|telnet\|inetutils-telnet)$' --kill-regex '^php[0-9.]*$'` |
| FPM, real termination | [php-fpm-kill.yaml](../examples/php/php-fpm-kill.yaml) | the same with `--kill-dry-run=false` |
| FPM, kill rules plus your own argv signatures | [php-fpm-kill-signatures.yaml](../examples/php/php-fpm-kill-signatures.yaml) | the same image-identity rules, with placeholder entries to fill in (section 6) |

What each covers and misses is in the tables of sections 2 and 5. No single pattern is right for every host.

## 4. Command-line evidence

### 4.1 What PHP produces (Debian 13, PHP 8.4, glibc)

| PHP code | `argv` of the program that is executed |
| --- | --- |
| `shell_exec`, `exec`, `system`, `passthru`, `popen` | `["sh","-c","--","<complete command string>"]`: the command is the **fourth** element; `sh` runs as `dash` (image `dash`) |
| `proc_open([...])` with an argument array | `["/usr/bin/uname","-s"]`: the program directly, **no shell**, parent = the worker |
| Python started by a shell | image `python3.13`, `["python3","-c","<code>"]`: the image carries the real version |
| PHP CLI started by a shell | image `php8.4`, `["php","-r","<code>"]` |
| `bash -c '<one command>'` | bash executes the command in its own PID: a second exec of the same process (`exec_index: 2`, `previous_image: bash`) |

Empty arguments, spaces, quotes, newlines and tabs stay separate array elements; `argv` is the authoritative array and no
joined string replaces it. Intermediate shells, deep chains, orphaned grandchildren and same-PID execs are all recorded
with their own events, `process_id`, `exec_index`, parent and root.

### 4.2 Limits, and what happens beyond them

The agent copies the argument area **at exec time, in the kernel** (never later from `ps` or `/proc`), at most
`capture.argv_max_bytes` raw bytes (default 4096, up to 16383) and `capture.argv_max_args` arguments (default 32, up to
1024). Raw bytes are the argument lengths plus one NUL each.

**An argument that the byte limit cuts is omitted from `argv`, not shortened.** For `sh -c -- <command>` the three
leading arguments use 9 bytes, so the longest command that fits is **4,086 bytes** at the default; one byte more and
`argv` is `["sh","-c","--"]` (verified, real PHP-FPM). The same applies to `python3 -c` (code up to 4,084 bytes) and
`php -r` (4,088). Inline code that merely *starts* near the end is lost too: after 4,071 bytes of options, `php -r 'echo
123456;'` ends as `["php","-d","<option>","-r"]`.

What the event says about it (additive fields of `process`; kill rules and exclusions never use them):

```json
"argv": ["sh", "-c", "--"],
"argv_state": "executed",
"argv_complete": false,
"argv_capture": {
  "argc": 4, "captured_args": 3, "total_bytes": 6015, "captured_bytes": 4096,
  "limit_args": 32, "limit_bytes": 4096,
  "partial": { "index": 3, "value": "echo AAAA...", "captured_bytes": 4087 }
}
```

- `argv_complete` is present whenever `argv` is a list; `argv_capture` only when it is `false`.
- `partial` is the first part of the cut argument, kept apart from `argv`. For a 6,005 byte command it holds the first
  4,087 bytes; with `argv_max_bytes: 16383` a 20,005 byte command is kept up to 16,374 bytes. It is evidence for an
  investigation. **A cut value never becomes a match**: `process.argv` holds only complete arguments, so an end anchor such
  as `^useradd$` cannot match a cut `useradd-long-name`. An omitted argument also means a rule on it cannot fire: rules on
  `image` do not depend on arguments, which is why the examples use them.
- `total_bytes` is what the kernel saw, so the size of what is missing is known: `total_bytes - captured_bytes`.
- `agent.started` reports the limits in effect (`details.capture_argv_limits`); `--capture-argv-max-bytes` and
  `--capture-argv-max-args` are the flags of the YAML keys. Values outside the supported range, or limits without
  `capture.argv`, are configuration errors (exit code 2), never silent clamps.

| Command length (`sh -c --`) | default limits | `argv_max_bytes: 16383` |
| --- | --- | --- |
| up to 4,086 bytes | complete | complete |
| 4,087 to 16,374 bytes | omitted, `partial` = the first 4,087 bytes | complete |
| above 16,374 bytes | omitted, `partial` = the first 4,087 bytes | omitted, `partial` = the first 16,374 bytes |
| more than 32 / 64 arguments | cut at 32 (`limit_args`), `argc` says how many | cut at 64 |

Processes that were already running when the agent started have no exec-time arguments: `argv` is read from
`/proc/<pid>/cmdline` (`argv_state: snapshot`). PHP-FPM and nginx rewrite their title; the padding that leaves behind
is not reported as empty arguments.

### 4.3 What larger limits cost

| Resource | Effect |
| --- | --- |
| Kernel buffer | one exec scratch buffer per CPU: about 24 KiB instead of 12 KiB. The ceiling of 16,383 bytes is the size of the argument area in it (the rest holds image, path and file names). |
| Ring buffer | records are variable-sized: only arguments that exist take space. A 16 KiB command fills 16 KiB of the ring (default 16 MiB), so a burst of such execs fills it much sooner than ordinary ones; an overflow is counted and reported as `agent.gap` like any loss (shown by the general overload test, not measured with large arguments). |
| Agent memory | every tracked process holds its arguments: worst case `runtime.max_processes` (65,536) x `argv_max_bytes`, 1 GiB at 16,383; ordinary processes hold a few hundred bytes. |
| Log size | the arguments repeat in the events of the process (fork of its children, exec, exit): a 16 KiB command appears in at least three events. Rotation (`rotate_size_mb`, `keep_files`) bounds the disk. |
| TCP / webhook | the full line is sent: lines of 18 KB arrive byte for byte identical to the log (verified). Queue memory is bounded by `delivery.queue_size` events, not bytes: lower it when raising the limits. |
| UDP | an event above `outputs.udp.max_bytes` (8192) is **not sent over UDP and counted** (`dropped_too_large`), never shortened (verified). The other outputs still get it. |
| Verifier | the exec program is verified with about 8,100 instructions on Linux 6.8 and 6.12 and about 20,800 on 5.15 (budget in the test 100,000, kernel limit 1,000,000); loaded and tested on 5.15, 6.8 and 6.12, each on arm64 and amd64. Not run on 6.17 with this change. |

There is no unlimited capture: beyond the ceiling the arguments are cut, reported, and kept as a prefix.

### 4.4 Attribution and reconstruction

Every process event names the `root` (the service master), the `lineage` (root to parent as `process_id`s) and the
`parent`. A worker that is replaced gets a new `process_id`; a process that executes another program keeps its
`process_id` and counts `exec_index`; PID reuse cannot mix identities. After an intermediate parent exits, a later
child still belongs to the tree (verified with a worker that ends while its shell is running).

A kill decision is self-contained: `response.kill_requested` and `response.kill_result` carry `details.chain`, the
ancestors from the root to the parent with image, path, exec index and arguments (at most 8 ancestors and 2 KiB of
arguments each, `chain_truncated` says when some are left out), so the audit line explains itself even where the
earlier events are not at hand.

## 5. Coverage

| Execution path | What is recorded | Match | Response | Blind spot |
| --- | --- | --- | --- | --- |
| FPM worker -> `sh -c --` -> program | fork (inherited image), exec of the shell with the full command, children with their arguments | watch `php-fpm`; rule on the shell or program image | reachable if it lives longer than about 0.3 ms | what the shell later reads (scripts, stdin, environment) |
| worker -> direct launch (`proc_open` array) | fork, exec of the program, parent = worker, no shell | same | same | |
| worker -> `python3 -c`, `php -r`, `bash -c` | exec with the inline code in `argv` (up to the limit, then `partial`) | image rule `^python[0-9.]*$`, `^php[0-9.]*$` | same | code passed through stdin (`python3 -`), a file or the network is not in `argv` |
| Apache mod_php worker -> shell | same, root = Apache master | watch `apache2`/`httpd` | descendants of the master only | PHP is inside the worker |
| worker replaces itself (exec in place) | a second exec of the same PID: new image and arguments, `previous_image` | rule on the new image | the worker is a descendant, so it can be killed (verified); the master respawns it | an exec of the same executable looks like a worker |
| worker forks, the child keeps running PHP | fork with the inherited image, later exit, no exec | only the inherited image | none that is safe: a rule that matches it also matches legitimate workers | everything the child does |
| code inside the worker (socket, file, database, `eval`) | **nothing** | - | none | complete: PHP opens connections itself (`fsockopen`); verified with a worker that held a connection to a loopback listener for 3 seconds: the OS shows it (`ss -tnp`), the agent logged no process event |
| request body, URL, identity of the request | nothing | - | - | FastCGI parameters are not process arguments |
| PHP CLI or queue worker | a root of its own; its children as descendants | watch `php8.` | the root is never a target | |
| remote FastCGI backend, containerized PHP | only on the host that runs the process | - | - | the agent must run there |

Exec arguments do not reveal what is supplied **later** (stdin, files, network, a running interpreter) or the PHP source
code, and the payload of an attack does not always appear in a command line. A connection-only network hook would not
show everything carried over an existing socket either (section 8).

## 6. Response rules

The feature is off by default, has a dry run, writes the decision (`response.kill_requested`) before it acts, opens a
pidfd for the exact process instance and verifies its kernel start time (a reused PID is never signalled), re-checks the
match right before the signal, and never targets the root, PID 1 or the agent.

**The failure mode of a broad rule (measured, real PHP-FPM behind nginx)**: with watch `php-fpm` and the rule `php` the
workers match as they are forked (the master forks with its own image) and the ones that already exist match at start.
Within 3 seconds the agent sent 9,501 signals (8,206 in a second run); five or six of six HTTP requests answered 502;
the master survived only because roots are protected. `check-config` and `agent.started` now warn when a rule matches a
watch pattern; `kill.spare_root_image: true` removes the damage: a descendant that runs the **same executable as its root
is never killed** (the decision is audited as `skipped` / `root_image_spared`, counted in `agent.health`). It spares workers and
a re-executed master after a reload; what a worker starts, and a worker that replaces itself with another program, is
still judged by the rules.

Recommended rules (see the examples): exact names of shells and interpreters, `fields: [image]`. Verified on the real
service: a shell and a PHP CLI interpreter started by a worker were killed with SIGKILL and ended with signal 9; an
ordinary program started the same way and all workers were untouched. By construction this already covers every
reverse or bind shell written in these interpreters, whatever its source code: it has to execute as one of them.

[php-fpm-kill-signatures.yaml](../examples/php/php-fpm-kill-signatures.yaml) adds an optional second layer, matching
your own command-line signatures against `argv` (field: `argv`, requires `capture.argv: true`). process-watcher ships
no such patterns itself: a literal match is brittle (renamed variables, a different encoding, an added `eval` defeat
it; this layer catches reuse of a known payload, not adaptation) and shares the `argv` blind spots below (code read
from stdin, a file or assembled at runtime is invisible, and a cut argument never matches). The file has placeholder
entries and the reasoning in full; fill in your own patterns, validate with `check-config`, and review a dry run
before switching it on.

| Pitfall | Reason |
| --- | --- |
| `sh` is a symlink | the image is `dash` (Debian, Ubuntu), `bash` (RHEL), `busybox` (Alpine, where it is also the image of `uname` and everything else) |
| versioned interpreter names | Python runs as `python3.13`, PHP as `php8.4`: use `^python[0-9.]*$`, `^php[0-9.]*$` (the second does not match `php-fpm8.4`) |
| `nc`, `socat`, `telnet` are rarely the literal name | distribution alternatives rewrite them. Verified with the real agent on Debian 13: `nc` execs as `nc.openbsd` or `nc.traditional`, `socat` as `socat1`, `telnet` as `inetutils-telnet`. Verified by executable path on Rocky 9: `nc` execs as `ncat`, `socat` and `telnet` keep their plain names. `ruby` is `ruby3.3` on Debian, `ruby` (unversioned) on Rocky. Not checked on Alpine (its `nc` is the `busybox` applet, already covered above). `examples/php/php-fpm-kill.yaml` lists the names found so far; discover more with the read-only commands of section 2 |
| false positives | PHP applications start mailers, image and PDF converters, `git`, `composer`; Python, Bash and PHP CLI are investigation signals, not proof |
| argument rules (`fields: [argv]`) | only complete arguments are matched: an omitted argument cannot fire a rule, a cut one never matches |
| exclusions | `exclude.*` only filter the reports; an excluded helper's later descendants are still observed and still subject to the rules |
| roots | the FPM master, an Apache master and a watched CLI process are roots: never targets, and in-process activity of a root cannot be stopped by these rules |

**`signal_sent` is not a death.** It means the kernel accepted `SIGKILL` for that process. The `process.exit` event
(`details.signal: 9`, same `response_action_id`) confirms it, and nothing says that damage was prevented.

Measured against a real FPM worker (200 requests, 25 ms apart; three runs on the native 6.12.54 kernel of a Docker VM on
Apple silicon; not hardware you run in production):

| Target | Result |
| --- | --- |
| long-running helper | 200 of 200 reached and ended with SIGKILL in every run. Decision (`kill_requested` written) after the kernel's exec record: mean 0.29 to 0.37 ms, p95 0.49 to 0.52 ms, p99 0.8 to 2.0 ms. Signal attempt returned: mean 0.47 to 0.59 ms, p95 0.78 to 0.81 ms, p99 1.6 to 2.5 ms, max 2.7 to 3.8 ms. A helper lived a median 0.6 to 0.75 ms from fork to death |
| `sh -c 'uname -s'` (about half a millisecond) | 119, 120 and 122 of 200 shells ended with SIGKILL, the others ended by themselves first |

Short-lived programs can finish, with their effects, before the signal arrives. This is a reaction, not blocking.

## 7. Tests

| What | Where | Run |
| --- | --- | --- |
| 23 integration tests with PHP-shaped topologies (service master, workers, replacement, reload, shells, direct launches, limits, response, transports) using harmless helper programs, `/bin/sh`, `/bin/true` | [tests/integration/php_test.go](../tests/integration/php_test.go) | `make test-docker`, `make test-vm-e2e` |
| the same shapes against the real nginx 1.26, Apache 2.4 and PHP 8.4 of Debian 13: 6 deployments, argument evidence, FPM lifecycle, response rules, blind spot, latency (15 runs, 108 checks) | [tests/php/](../tests/php/) | `tests/php/run.sh` |
| executable names on other images (Ubuntu 24.04, Debian 12, Rocky 9, official php images, Alpine) | `tests/php/names-images.sh` | |
| real-kernel tests of the capture limits, partial arguments and totals | `internal/collector/ebpf` | `make test-vm-matrix` |

The test matrix of the task is covered as follows: NGINX-only and Apache-only watches missing FPM, correct watches seeing
it, versioned and unversioned names, master and workers, two pools, existing workers, reload; `sh -c`, `python3 -c`,
`php -r`, direct launch, deep chains, same-PID exec, fork without exec; limits at 4,086/4,087 bytes, above 32 arguments,
empty arguments, quotes, newlines, tabs, a script that starts near the end; short-lived shells, exited parents,
reparenting; worker creation under broad and narrow rules, dry run, real termination, the already-exited case; an
outbound connection without a child; JSONL validity and identical arguments in the file, over TCP and webhook, and the
UDP drop above the datagram limit. Event loss and PID reuse are covered by the general tests
(`TestOverloadIsMeasuredAndReported`, `TestReusedPIDGetsANewIdentity`), not by PHP-specific ones.

## 8. Change proposal, by effort

**A. Usable today, configuration only**: the observe examples, then the dry run (section 3). Check the real executable
names first (section 2). Keep a copy of the log shipped to a place the web server user cannot write.

**B. Small implementation changes, done and verified** (each with unit, real-kernel and lab tests):

| Change | Why |
| --- | --- |
| `capture.argv_max_bytes` / `argv_max_args` and the flags; kernel buffer raised to 16 KiB | long inline commands were silently dropped from `argv` |
| `argv_complete`, `argv_capture` (argc, totals, limits, partial) | completeness is explicit instead of implied by `truncated_fields` |
| `kill.spare_root_image`, warnings in `check-config`, `agent.started`, the log | a broad rule cannot kill the service it protects |
| `details.chain` in the kill audit | the decision shows worker, shell and arguments without the earlier events |
| padding of rewritten process titles dropped from snapshot arguments | FPM workers no longer look as if they had 31 empty arguments |

Small candidates not done: a byte bound for the remote queues (today `queue_size` counts events); a shorter form of
inherited arguments in fork events (a large `argv` repeats in the events of the children); `argv_contains` exclusions
and kill rules on the partial argument (deliberately not done: a prefix must not become a match).

**C. Larger telemetry extensions (proposed, not built)**:

1. *Network connection events* for the tracked tree, the only way to see PHP that connects out without starting a
   process. Hook TCP connect in process context (for example `tp_btf/inet_sock_set_state` to `SYN_SENT`, or a kprobe on
   `tcp_v4_connect`/`tcp_v6_connect`), identify the process with the same `(tgid, start time)` key, emit
   `network.connect` with destination, port, protocol and the process reference. Limits: a connection that is inherited
   or passed as a file descriptor (a reverse shell that reuses the request's socket) has no connect call in the worker;
   UDP, Unix sockets and DNS need separate hooks; a connect does not prove RCE and does not show what an existing
   socket carries; containers have their own network namespaces. Overhead: one small record per connect of tracked
   processes (filtered in the kernel by a map), so far less than the exec path. Tests: a worker that dials a loopback
   listener (the test of section 5 turned around), inherited-socket and UDP cases as documented gaps, an overhead
   measurement with a connect-heavy PHP workload.
2. *Request correlation*: the FastCGI request id, URL and client address are not visible to a process hook. A
   correlation would need the web server or PHP-FPM access log joined by time and worker PID: possible outside the agent.
3. *Prevention* is out of scope for this tool. For blocking, use what the platform offers (`disable_functions`,
   seccomp or AppArmor profiles for the FPM service, container policy); the agent then shows what still runs.

**D. A minimal rollout**: day 1 discovery and the observe configuration on staging and one production host; days 2 to 3
dry run, review every would-be hit against real traffic, tune the rules; days 4 to 5 ship the log, alert on shells,
interpreters and `argv_complete: false` below workers; day 6 decide on real termination for narrow rules, keeping the
dry run everywhere else. Do not invent vulnerability-specific detection before an advisory exists.

## 9. Verified and not verified

Verified (2026-10-17): the real nginx 1.26.3, Apache 2.4.69 and PHP 8.4.26 of Debian 13 in a Docker VM (kernel 6.12.54,
arm64, native CPU), all 15 lab runs (108 checks) without a failing check; the 23 PHP integration tests as part of the
77-test end-to-end suite on the same kernel and in QEMU guests (Ubuntu 5.15 and 6.8, Debian 6.12, arm64 and amd64); the
26 collector tests on those six combinations. Executable names only (no behavior tests) on Ubuntu 24.04, Debian 12,
Rocky 9 and the official php images. The GitHub-hosted runners (kernel 6.17) have not run these changes: the code of
release v0.1.0 passed there, the changes of this guide came after it.

Verified (2026-10-18): the executable names of `nc`, `socat`, `telnet`, `perl`, `ruby`, `python3`, `bash` and `sh` with
the real agent against Debian 13 (`nc.openbsd`, `nc.traditional`, `socat1`, `inetutils-telnet`, `perl`, `ruby3.3`,
`python3.13`, `bash`, `dash`); the same set by executable path (not through the agent) on Rocky 9 (`ncat`, `socat`,
`telnet`, `perl`, `ruby`, `python3.9`, `bash`, `bash`). Not run through PHP's own process functions, only invoked
directly under the agent's watch; the matching code path (`killrule.Match`) is the same one the PHP lab's `killrules`
scenarios already exercise through real FPM workers.

Not verified: any real vulnerability or exploit (none was used); PHP-FPM with the `chroot` pool option (a plain chroot was
checked); `proc_open` with a command string; mailers and other legitimate helpers; FPM under heavy production load and
the cost of the larger limits there; other kernels and distributions; real amd64 hardware (latency numbers are from
the arm64 Docker VM only); other PHP versions than 8.4 in behavior; `nc`/`socat`/`telnet`/`ruby`/`perl` executable names
on Alpine or any distribution other than Debian 13 and Rocky 9; any command-line signature for a specific shell payload
(process-watcher ships none, see section 6).
