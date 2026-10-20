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

## 2. Check the configuration

One file covers every way of running PHP: `php/php-observe.yaml` watches **the processes that run PHP** (PHP-FPM behind
nginx or Apache, `php-cgi`, the PHP CLI of cron jobs and queue workers, Apache with `mod_php`), not the web server in
front of PHP-FPM: a watch on `nginx` sees nothing that PHP starts. Check the file without root:

```bash
./process-watcher check-config --config php/php-observe.yaml     # "configuration OK"
```

It also reports every PHP CLI job and everything Apache starts. If that is more than you want, narrow
`watch.image_contains` in the file ([which name belongs to which setup](guide.md#2-which-executable-to-watch)).

## 3. Start observing

```bash
sudo ./process-watcher doctor                                  # kernel, BTF, permissions: every line [OK]
sudo ./process-watcher --config php/php-observe.yaml           # stop with Ctrl-C
```

Events go to `/var/log/process-watcher/events.jsonl` (the agent creates the directory, readable by root only). Command
lines are recorded because the configurations switch that on; they can contain secrets, which is one reason the log is
root-only. Keep it running in `tmux` or `screen` for a first look, or as a systemd service
([packaging/INSTALL.md](../../packaging/INSTALL.md)).

## 4. See what PHP starts

In a second terminal (control characters in names and arguments are printed as `?`: an attacker chooses them):

```bash
sudo tail -f /var/log/process-watcher/events.jsonl | jq -r '
  select(.event_type=="process.exec" and .lineage.role=="descendant")
  | "\(.timestamp[:19])Z  \(.root.image) > \(.process.image)  \(.process.argv // [] | join(" "))" | gsub("[[:cntrl:]]"; "?")'
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
    and (.process.image | test("^(sh|dash|bash|zsh|ksh|ash|busybox|python[0-9.]*|perl[0-9.]*|ruby[0-9.]*|php[0-9.]*|nc|nc[.].*|ncat|socat[0-9]*|(inetutils-)?telnet|curl|wget)$")))
  | "\(.timestamp[:19])Z  \(.root.image) > \(.process.image)  \(.process.argv // [] | join(" "))" | gsub("[[:cntrl:]]"; "?")'
```

Applications start mailers, converters and sometimes a shell for good reasons: it is a signal to look at, not proof.
Send the events to your SIEM or log pipeline with `--tcp-address` or `--webhook-url`
([outputs](../../docs/outputs.md)), and keep a copy where the web server user cannot write.

## 5. Optional: let it react (dry run first)

The response rules send `SIGKILL` to shells, Python, Perl, Ruby, PHP CLI, netcat, socat and telnet that a PHP worker
starts, and to any program whose command line matches one of the reverse- and bind-shell signatures in the same file. A
reverse or bind shell written in one of those languages, or built with those tools, has to run as one of these programs,
however its code looks; the signatures are a second layer for known payloads and catch reuse, not adaptation
([what each layer misses](guide.md#6-response-rules)). The PHP-FPM master is never a target and its workers are spared:
the rules apply to what they start.

**Read this first:** PHP routes `shell_exec()`, `system()`, `exec()`, `passthru()`, `popen()` and the `sendmail` call of
`mail()` through a shell, and the rules name shells. An application that uses them **will lose those calls**. So start
with the dry run: the file ships as one (`dry_run: true`), logs every decision and sends no signal. The console says
so at start and prints one `kill decision` line per decision (outcome, program, PID, the rules that matched, no
arguments); the log file holds the full events.

```bash
sudo ./process-watcher --config php/php-fpm-kill-signatures.yaml
```

In the second terminal use this filter instead of step 4's, which shows only `process.exec` and so never a kill decision.
It prints the exec, the decision with the rules that matched, and a death by signal 9. Control characters in names and
arguments, which an attacker chooses, are printed as `?` so that they cannot forge lines or drive your terminal:

```bash
sudo tail -f /var/log/process-watcher/events.jsonl | jq -r '
  select((.event_type=="process.exec" and .lineage.role=="descendant")
      or (.event_type=="response.kill_result" and (.details.exec_index // 0) > 0)
      or (.event_type=="process.exit" and .details.signal==9))
  | ("\(.timestamp[:19])Z  " + (
      if .event_type=="response.kill_result" then "=> " + (.details.summary // "\(.details.outcome) \(.process.image)")
      elif .event_type=="process.exit" then "=> exited by signal 9: \(.process.image) (pid \(.process.pid))"
      else "\(.root.image) > \(.process.image)  \(.process.argv // [] | join(" "))" end))
  | gsub("[[:cntrl:]]"; "?")'
```

```
2026-10-20T21:09:47Z  php-fpm8.4 > bash  sh -c -- uname -s 2>&1
2026-10-20T21:09:47Z  => dry run, no signal sent, would have killed bash (pid 632, exec 1, uid 33), started by php-fpm8.4 (pid 592) below php-fpm8.4 (pid 591); matched kill.regex[0] "^(sh|dash|bash|zsh|ksh|ash)$" in image, argv[0]
2026-10-20T21:09:47Z  php-fpm8.4 > uname  uname -s
```

Every `=> dry run` line is a program that would have been killed. The sentence is `details.summary` of the
`response.kill_result` event; the same event has the matching rules with their patterns in `details.rules`, the
process, its parent and the ancestors. Let it see your real traffic first, a day if you can. If
the list holds only what you do not want, switch to real termination with the same file; if your application
legitimately needs shells, narrow the first rule instead ([guide.md, section 6](guide.md#6-response-rules)).

```bash
sudo ./process-watcher --config php/php-fpm-kill-signatures.yaml --kill-dry-run=false
```

The same filter now shows `SIGKILL sent` and the death by signal 9 (the death can be logged just before the decision
line: the process is gone within a millisecond):

```
2026-10-20T21:09:50Z  php-fpm8.4 > bash  sh -c -- uname -s 2>&1
2026-10-20T21:09:50Z  => SIGKILL sent to bash (pid 667, exec 1, uid 33), started by php-fpm8.4 (pid 593) below php-fpm8.4 (pid 591); matched kill.regex[0] "^(sh|dash|bash|zsh|ksh|ash)$" in image, argv[0]
2026-10-20T21:09:50Z  => exited by signal 9: bash (pid 667)
```

`SIGKILL sent` only says the kernel accepted the signal; the `process.exit` with signal 9 is what confirms the death.

- **A reaction, not a block.** The signal is sent a fraction of a millisecond after the exec was seen. A program that
  lives less than about a millisecond can finish first: in the lab about 60 % of 200 one-command shells were killed,
  and all 200 long-running helpers (the shape of a shell that stays open).
- **Names differ by distribution.** The list has the names found on Debian 13 and Rocky 9 (`nc.openbsd`, `socat1`,
  `inetutils-telnet`, `ncat`, `ruby3.3`, ...). Check yours; on Alpine every applet is `busybox`
  ([guide.md](guide.md#6-response-rules)).
- **Only PHP-FPM ships response rules.** For another setup, copy `php/php-observe.yaml`, narrow its
  `watch.image_contains` to the process that runs PHP (rules apply to everything below every watched process, CLI jobs
  included), add the `kill:` block of `php/php-fpm-kill-signatures.yaml` and run `check-config` on the result.
- **Add your own command-line signatures** in `php/php-fpm-kill-signatures.yaml` next to the shipped ones, following
  the reasoning and the format documented in the file itself.

## What it cannot do

- **It prevents nothing.** It sees a program after it started; it is no substitute for patching or hardening.
- **Code that runs inside the PHP worker and starts no process is invisible**: a network connection, file access or
  `eval` done by PHP itself leaves no process event (checked with a worker that held a connection for three seconds).
- **Command lines show only what reached the program as arguments.** Code read from stdin, a file or the network does not
  appear. A command longer than 16 KB is flagged `argv_complete: false` and kept only as a prefix.
- **A burst can overflow the kernel buffer.** Losses are counted (`agent.health`) and reported (`agent.gap`); the agent
  takes no action on a lineage it cannot confirm.

More: [guide.md](guide.md) (every deployment, argument limits, measurements, what was and was not verified),
[kill-rules.md](../../docs/kill-rules.md), [events.md](../../docs/events.md).

*Tested against nginx 1.26 and PHP 8.4 on Debian 13 (kernel 6.12, arm64). From an unpacked release archive built from the
sources: `doctor`, `check-config`, the image-identity response rules as a dry run and as real termination, and that
`mail()` starts its command through a shell. In the PHP lab with the real agent: `php/php-observe.yaml` on PHP-FPM behind
nginx and behind Apache, `mod_php`, `php-cgi`, `mod_fcgid` and a CLI worker next to FPM, and both observe `jq` filters
on those events. The step 5 filter ran on a web shell request below PHP-FPM, as a dry run and with real termination. Not run with
these commands: the download lines, the command-line signatures other than the `/dev/tcp` one (validated with
`check-config` only), amd64, other distributions and PHP versions
([guide.md](guide.md#9-verified-and-not-verified) says what was checked elsewhere).*
