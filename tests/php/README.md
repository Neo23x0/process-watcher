# PHP lab

Checks the shapes of real PHP deployments against the real nginx, Apache and PHP of a distribution, with the real
agent. It is the evidence behind [PHP guide](../../emerging-threats/php-rce-october-26/guide.md). The Go integration tests
([tests/integration/php_test.go](../integration/php_test.go)) cover the same shapes with harmless helper programs and
run in CI; this lab needs Docker and network access and is run by hand.

```bash
tests/php/run.sh                         # everything, about 5 minutes (the first run builds the lab image)
tests/php/run.sh argv killrules:narrow   # a selection (name or name:argument)
tests/php/names-images.sh                # executable names on other images (Ubuntu, Debian 12, Rocky 9, php:*)
```

`run.sh` builds the agent for the architecture of the Docker VM, builds the lab image
([Dockerfile.debian](Dockerfile.debian): Debian 13 with nginx, Apache with mod_php and mod_fcgid, PHP 8.4 FPM, CGI and
CLI), and runs every scenario in a fresh privileged container (`--pid=host`, so the agent sees host PIDs). Each scenario
prints `PW-PHP: PASS|FAIL|INFO ...` lines and exits with the number of failed checks; the logs are in `dist/php/out/`.

| Scenario | Checks |
| --- | --- |
| `deployments:<name>` | `nginx-fpm`, `apache-fpm`, `apache-modphp`, `nginx-phpcgi`, `apache-fcgid`, `cli`: the real executable and the process tree of each deployment, which watch target sees what PHP starts and which does not |
| `argv` | the shape of shell, Python, PHP and bash command lines started by PHP; the 4,086 byte boundary of `sh -c --`; code that starts near the end of the capture; more than 32 arguments; the raised limits |
| `fpm-lifecycle` | workers that exist at start, two pools, worker replacement (`pm.max_requests`), a graceful reload (`USR2`) |
| `killrules:<mode>` | `narrow`, `guard`, `broad`, `dry`, `root`: response rules against a real FPM service, including the failure of a broad rule |
| `blindspot` | a worker that opens a network connection itself: visible to `ss`, invisible to the agent |
| `latency` | decision and signal latency against 200 helpers, and the outcome against 200 short-lived shells |
| `installer:<mode>` | `fpm`, `modphp`, `cgi`, `negative`: the one-line installer of the PHP kit ([install.sh](../../emerging-threats/php-rce-october-26/install.sh)), piped into `sh` as the documented command does, against real PHP and a release (v9.9.9) that `run.sh` builds from this tree and serves from a local mirror: detection, checksum, install, observe, stop, the refusal of a really killing configuration, and the refusals (no PHP, not root, damaged archive, missing checksum entry, unknown release, a release without `php/`) |

`probe.php` ([lab/fixture/](lab/fixture/)) is a test fixture, **not a web shell**: it runs fixed, harmless programs
selected by a mode name (`id`, `uname`, `echo`, a copy of `sleep`, a loopback connection). Sizes and counts come from
the request, never a command.

## Things to know

- The `installer` scenarios need Go on the host: `run.sh` builds the release archive with `go run ./tools/release`
  (into `dist/php/release/`). Nothing is downloaded from the internet in them; the installer fetches from the local mirror.
- The containers share the PID namespace of the Docker VM. Run one lab at a time, make sure no other container with PHP
  or web server processes runs there (`docker ps`), and do not run the Go integration tests at the same time: a watch
  on `php-fpm` also selects their helper processes. A scenario that hangs leaves its container running:
  `docker rm -f pw-php-lab-run`.
- The `broad` scenario makes a real PHP-FPM service in the container fail on purpose (thousands of kills in a few
  seconds). It only touches processes below the master of that container.
- Timing numbers (`latency`) come from the machine you run it on. The ones quoted in the PHP guide are from an arm64
  Docker VM with a native kernel.
