# Watching PHP with process-watcher: quick start

**See every program your PHP processes start, with its full command line, as it happens, and optionally kill the ones
you name.** One static binary, no dependencies, set up in minutes. It works whatever made PHP start a program: nothing
here depends on a particular vulnerability or exploit.

It is an **additional detection layer**, not a patch and not a block: it reports, and optionally reacts, after a program
has started. [What it cannot do](#what-it-cannot-do) is at the end; please read it.

**You need** Linux (`amd64` or `arm64`, kernel 5.15 or newer with BTF), root, `jq` for reading the log, and PHP running
as PHP-FPM (behind nginx or Apache), Apache `mod_php`, `php-cgi` or the PHP CLI. Run the agent on the host, not inside a
container: it sees PHP running in containers.

## 1. Download and unpack

```bash
ARCH=$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')
VERSION=$(curl -fsSLI -o /dev/null -w '%{url_effective}' https://github.com/Neo23x0/process-watcher/releases/latest | sed 's#.*/##')
curl -fsSLO https://github.com/Neo23x0/process-watcher/releases/download/$VERSION/process-watcher_${VERSION}_linux_${ARCH}.tar.gz
curl -fsSLO https://github.com/Neo23x0/process-watcher/releases/download/$VERSION/SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS
tar xzf process-watcher_${VERSION}_linux_${ARCH}.tar.gz && cd process-watcher_${VERSION}_linux_${ARCH}
ls php/
```

`php/` holds the ready-made configurations used below.

## 2. Pick the configuration

Watch **the process that runs PHP**, not the web server in front of it: a watch on `nginx` sees nothing that PHP starts.

| PHP runs as | Configuration |
| --- | --- |
| PHP-FPM behind nginx or Apache | `php/php-fpm-observe.yaml` |
| Apache with `mod_php` | `php/apache-mod-php.yaml` |
| `php-cgi` or another FastCGI daemon | `php/php-cgi.yaml` |
| PHP CLI (cron, queue workers) | `php/php-cli-workers.yaml` |

Not sure which one applies? `ps -eo pid,ppid,user,comm,args --forest | grep -E 'php|apache2|httpd'` shows what executes
PHP ([how to read it](php.md#2-which-executable-to-watch)). Check the file without root:

```bash
./process-watcher check-config --config php/php-fpm-observe.yaml     # "configuration OK"
```

## 3. Start observing

```bash
sudo ./process-watcher doctor                                  # kernel, BTF, permissions: every line [OK]
sudo ./process-watcher --config php/php-fpm-observe.yaml       # stop with Ctrl-C
```

Events go to `/var/log/process-watcher/events.jsonl` (the agent creates the directory, readable by root only). Command
lines are recorded because the configurations switch that on; they can contain secrets, which is one reason the log is
root-only. Keep it running in `tmux` or `screen` for a first look, or as a systemd service
([packaging/INSTALL.md](../packaging/INSTALL.md)).

## 4. See what PHP starts

In a second terminal:

```bash
sudo tail -f /var/log/process-watcher/events.jsonl | jq -r '
  select(.event_type=="process.exec" and .lineage.role=="descendant")
  | "\(.timestamp[:19])Z  \(.root.image) > \(.process.image)  \(.process.argv // [] | join(" "))"'
```

```
2026-10-19T12:40:27Z  php-fpm8.4 > dash  sh -c -- uname -s
2026-10-19T12:40:27Z  php-fpm8.4 > uname  uname -s
2026-10-19T12:40:27Z  php-fpm8.4 > dash  sh -c -- python3 -c 'print(40+2)'
2026-10-19T12:40:27Z  php-fpm8.4 > python3.13  python3 -c print(40+2)
```

PHP's `shell_exec()`, `system()`, `exec()`, `passthru()` and `popen()` all start `sh -c -- <command>`, so the whole
command is in the log (the shell shows as `dash` on Debian and Ubuntu, `bash` on RHEL and relatives). A program
started directly (`proc_open` with an array) has no shell in front. A silent log is normal for an application that
never starts programs: `agent.started` and `agent.ready` prove the agent is alive.

**Look first at shells, interpreters, netcat and download tools below PHP.** This filter shows only those:

```bash
sudo tail -f /var/log/process-watcher/events.jsonl | jq -r '
  select(.event_type=="process.exec" and .lineage.role=="descendant"
    and (.process.image | test("^(sh|dash|bash|zsh|ksh|ash|busybox|python[0-9.]*|perl[0-9.]*|ruby[0-9.]*|php[0-9.]*|nc|nc\\..*|ncat|socat[0-9]*|(inetutils-)?telnet|curl|wget)$")))
  | "\(.timestamp[:19])Z  \(.root.image) > \(.process.image)  \(.process.argv // [] | join(" "))"'
```

Applications start mailers, converters and sometimes a shell for good reasons: it is a signal to look at, not proof.
Send the events to your SIEM or log pipeline with `--tcp-address` or `--webhook-url`
([outputs](outputs.md)), and keep a copy where the web server user cannot write.

## 5. Optional: let it react (dry run first)

The response rules send `SIGKILL` to shells, Python, Perl, Ruby, PHP CLI, netcat, socat and telnet that a PHP worker
starts. A reverse or bind shell written in one of those languages, or built with those tools, has to run as one of these
programs, however its code looks. The PHP-FPM master is never a target and its workers are spared: the rules apply to
what they start.

**Read this first:** PHP routes `shell_exec()`, `system()`, `exec()`, `passthru()`, `popen()` and the `sendmail` call of
`mail()` through a shell, and the rules name shells. An application that uses them **will lose those calls**. So start
with the dry run: it logs every decision and sends no signal.

```bash
sudo ./process-watcher --config php/php-fpm-dry-run.yaml
```

```bash
sudo tail -f /var/log/process-watcher/events.jsonl | jq -r '
  select(.event_type=="response.kill_result" and (.details.exec_index // 0) > 0)
  | "\(.timestamp[:19])Z  \(.details.outcome)  \(.process.image)  \(.process.argv // [] | join(" "))"'
```

```
2026-10-19T12:41:08Z  dry_run  dash  sh -c -- uname -s
2026-10-19T12:41:08Z  dry_run  python3.13  python3 -c print(40+2)
```

Every `dry_run` line is a program that would have been killed. Let it see your real traffic first, a day if you can. If
the list holds only what you do not want, switch to real termination; if your application legitimately needs shells,
narrow the first rule instead ([php.md, section 6](php.md#6-response-rules)).

```bash
sudo ./process-watcher --config php/php-fpm-kill.yaml
```

The same filter now shows `signal_sent`; the matching `process.exit` with signal 9 confirms the death:

```bash
sudo tail -f /var/log/process-watcher/events.jsonl | jq -r '
  select(.event_type=="process.exit" and .details.signal==9)
  | "\(.timestamp[:19])Z  killed  \(.process.image)  signal \(.details.signal)"'
```

- **A reaction, not a block.** The signal is sent a fraction of a millisecond after the exec was seen. A program that
  lives less than about a millisecond can finish first: in the lab about 60 % of 200 one-command shells were killed,
  and all 200 long-running helpers (the shape of a shell that stays open).
- **Names differ by distribution.** The list has the names found on Debian 13 and Rocky 9 (`nc.openbsd`, `socat1`,
  `inetutils-telnet`, `ncat`, `ruby3.3`, ...). Check yours; on Alpine every applet is `busybox`
  ([php.md](php.md#6-response-rules)).
- **Only PHP-FPM ships response rules.** For other setups, copy the `kill:` block of `php/php-fpm-dry-run.yaml` into your
  observe file and run `check-config` on the result.
- **Your own command-line signatures** go into `php/php-fpm-kill-signatures.yaml` (placeholders; no patterns are shipped).

## What it cannot do

- **It prevents nothing.** It sees a program after it started; it is no substitute for patching or hardening.
- **Code that runs inside the PHP worker and starts no process is invisible**: a network connection, file access or
  `eval` done by PHP itself leaves no process event (checked with a worker that held a connection for three seconds).
- **Command lines show only what reached the program as arguments.** Code read from stdin, a file or the network does not
  appear. A command longer than 16 KB is flagged `argv_complete: false` and kept only as a prefix.
- **A burst can overflow the kernel buffer.** Losses are counted (`agent.health`) and reported (`agent.gap`); the agent
  takes no action on a lineage it cannot confirm.

More: [php.md](php.md) (every deployment, argument limits, measurements, what was and was not verified),
[kill-rules.md](kill-rules.md), [events.md](events.md).

*Tested from an unpacked release archive built from the sources, against nginx 1.26 and PHP 8.4-FPM on Debian 13 (kernel
6.12, arm64): `doctor`, `check-config`, the observe, dry-run and kill configurations, every `jq` filter above, and that
`mail()` starts its command through a shell (the download lines are the README's). Not run with these commands: amd64,
other distributions and PHP versions, Apache `mod_php` ([php.md](php.md#9-verified-and-not-verified) says what was
checked elsewhere).*
