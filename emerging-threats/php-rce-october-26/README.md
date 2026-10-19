# PHP RCE (October 26): see what your PHP starts

A PHP process that starts a shell, an interpreter or a download tool is a classic trace of remote code execution.
This kit shows you **every program your PHP processes start, with its full command line, as it happens**, and can
kill the ones you name. One command per host, one static binary. It works whatever made PHP start the program: nothing
here depends on a particular vulnerability or exploit.

It is an **additional detection layer**, not a patch and not a block: it reports, and optionally reacts, after a
program has started. [What it cannot do](#what-it-cannot-do) is at the end; please read it.

<!-- Add the link to the advisory here once it is public. -->

## 1. Run one command on each host that runs PHP

As root, on the host (not inside a container; the agent sees PHP running in containers). It needs Linux (`amd64` or
`arm64`, kernel 5.15 or newer with BTF) and `curl`.

```bash
curl -fsSL https://raw.githubusercontent.com/Neo23x0/process-watcher/main/emerging-threats/php-rce-october-26/install.sh | sudo sh
```

The script ([install.sh](install.sh), plain POSIX `sh`, short enough to read):

1. looks at the process list for PHP-FPM, Apache with `mod_php`, `php-cgi` and PHP CLI processes,
2. downloads the latest release of process-watcher for this machine and checks it against that release's `SHA256SUMS`,
3. unpacks it to `/opt/process-watcher` and starts it in the background with the configuration that fits what it
   found, **observing only: it kills nothing**.

Besides the running agent (it loads observation-only eBPF programs into the kernel while it runs) it touches
`/opt/process-watcher` and `/var/log/process-watcher` and nothing else: no service, no cron job, no sysctl or firewall
change. To undo it: `sh install.sh --stop`, then remove those two directories (keep the logs if you found something).

**A security tool piped into a root shell deserves a look first.** Read it, ask it what it would do, then run it:

```bash
curl -fsSLO https://raw.githubusercontent.com/Neo23x0/process-watcher/main/emerging-threats/php-rce-october-26/install.sh
less install.sh
sudo sh install.sh --plan        # what it found and what it would do; changes nothing
sudo sh install.sh
```

To pin the script, replace `main` in the URL with a release tag. The checksum protects against a damaged download, not
against a compromised release; `gh attestation verify <archive> --repo Neo23x0/process-watcher` checks the build
provenance of a release archive by hand.

Options, also in `sh install.sh --help` (when you pipe the script, put `sh -s --` before them): `--plan`, `--stop`,
`--foreground`, `--version TAG`, `--watch NAME` (watch a name yourself instead of the detected ones), `--config NAME`
(a configuration of the release, see step 3).

## 2. See what PHP starts

Install `jq` (`apt install jq`, `dnf install jq`), then:

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

PHP's `shell_exec()`, `system()`, `exec()`, `passthru()` and `popen()` start a shell with the whole command as one
argument, so it is in the log (`sh -c -- <command>` on Debian 13; `shell_exec()` on Alpine and Rocky showed
`sh -c <command>`). The shell shows as `dash` on Debian and Ubuntu, `bash` on RHEL and relatives, and every program as
`busybox` on Alpine. A program started directly (`proc_open` with an array) has no shell in front. A silent log is
normal for an application that never starts programs: `agent.started` and `agent.ready` prove the agent is alive.

**Look first at shells, interpreters, netcat and download tools below PHP.** This filter shows only those (on Alpine it
shows everything, because everything is `busybox` there):

```bash
sudo tail -f /var/log/process-watcher/events.jsonl | jq -r '
  select(.event_type=="process.exec" and .lineage.role=="descendant"
    and (.process.image | test("^(sh|dash|bash|zsh|ksh|ash|busybox|python[0-9.]*|perl[0-9.]*|ruby[0-9.]*|php[0-9.]*|nc|nc\\..*|ncat|socat[0-9]*|(inetutils-)?telnet|curl|wget)$")))
  | "\(.timestamp[:19])Z  \(.root.image) > \(.process.image)  \(.process.argv // [] | join(" "))"'
```

Applications start mailers, converters and sometimes a shell for good reasons: it is a signal to look at, not proof.
Send the events to your SIEM or log pipeline with `--tcp-address` or `--webhook-url`
([outputs](../../docs/outputs.md)), and keep a copy where the web server user cannot write.

## 3. Optional: let it react (dry run first)

The response rules send `SIGKILL` to shells, Python, Perl, Ruby, PHP CLI, netcat, socat and telnet that a PHP worker
starts. A reverse or bind shell written in one of those languages, or built with those tools, has to run as one of these
programs, however its code looks. The PHP-FPM master is never a target and its workers are spared: the rules apply to
what they start.

**Read this first:** PHP routes `shell_exec()`, `system()`, `exec()`, `passthru()`, `popen()` and the `sendmail` call of
`mail()` through a shell, and the rules name shells. An application that uses them **will lose those calls**. So start
with the dry run: it logs every decision and sends no signal. Stop the observer, then start the dry run (`install.sh`
is the file you downloaded in step 1; if you used the pipe, run `curl -fsSL <the URL> | sudo sh -s -- --stop` and so on):

```bash
sudo sh install.sh --stop
sudo sh install.sh --config php-fpm-dry-run
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
narrow the first rule instead ([guide, section 6](guide.md#6-response-rules)). A configuration that really kills is never
started by detection and needs `--allow-kill` on top:

```bash
sudo sh install.sh --stop
sudo sh install.sh --config php-fpm-kill --allow-kill
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
  ([guide](guide.md#6-response-rules)).
- **Only PHP-FPM has response rules.** For other setups, copy the `kill:` block of
  [configs/php-fpm-dry-run.yaml](configs/php-fpm-dry-run.yaml) into your observe file and run `check-config` on the result.
- **Your own command-line signatures** go into [configs/php-fpm-kill-signatures.yaml](configs/php-fpm-kill-signatures.yaml)
  (placeholders; no patterns are shipped): `sh install.sh --config php-fpm-kill-signatures`.

## What it cannot do

- **It prevents nothing.** It sees a program after it started; it is no substitute for patching or hardening.
- **Code that runs inside the PHP worker and starts no process is invisible**: a network connection, file access or
  `eval` done by PHP itself leaves no process event (checked with a worker that held a connection for three seconds).
- **Command lines show only what reached the program as arguments.** Code read from stdin, a file or the network does not
  appear. A command longer than 16 KB is flagged `argv_complete: false` and kept only as a prefix.
- **A burst can overflow the kernel buffer.** Losses are counted (`agent.health`) and reported (`agent.gap`); the agent
  takes no action on a lineage it cannot confirm.

## By hand, without the script

Download and unpack a release as in the [README](../../README.md#quick-start), pick the file under `php/` for your PHP
(`php-fpm-observe.yaml`: PHP-FPM behind nginx or Apache; `apache-mod-php.yaml`: Apache with `mod_php`; `php-cgi.yaml`;
`php-cli-workers.yaml`), check it with `./process-watcher check-config --config php/<file>`, and run
`sudo ./process-watcher --config php/<file>`. Watch the process that runs PHP, not the web server in front of it: a
watch on `nginx` sees nothing that PHP starts. What every configuration covers and misses, argument limits,
measurements and what was and was not verified: the [guide](guide.md).

*Tested with a local copy of a release built from the sources: the installer, piped into `sh`, against nginx with
PHP-FPM, Apache with `mod_php` and php-cgi with a PHP CLI process on Debian 13, and against PHP-FPM on Alpine 3.20 and
Rocky 9 (kernel 6.12, arm64); the detection under dash, busybox and bash. Not tested: the download from github.com
itself, amd64, SELinux in enforcing mode, other PHP versions and distributions. [guide, section 9](guide.md#9-verified-and-not-verified)
says what was checked elsewhere.*
