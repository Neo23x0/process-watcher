# Installing as a systemd service

## Check the requirements

```bash
sudo ./process-watcher doctor
```

`doctor` reports missing kernel functions and missing privileges (exit code 3) and uses a probe process of its own to
check that fork, exec and exit arrive without `/proc`. The agent must run **on the host** in the initial PID
namespace; running in a container is refused.

## Install

The binary comes from a [release](https://github.com/Neo23x0/process-watcher/releases) (unpack the archive, see the
[README](../README.md#installation)) or from `make build-linux`; `install.sh` and the unit are in this directory of
the repository.

```bash
# either the binary from an unpacked release archive ...
sudo ./packaging/install.sh /path/to/process-watcher
# ... or one you built yourself:
make build-linux
sudo ./packaging/install.sh ./dist/process-watcher-linux-amd64    # arm64: ...-linux-arm64
# then, in both cases:
sudoedit /etc/process-watcher/config.yaml                         # adjust the watch list
sudo process-watcher check-config --config /etc/process-watcher/config.yaml
sudo systemctl enable --now process-watcher
journalctl -u process-watcher -f                                  # operational diagnostics (stderr)
sudo tail -f /var/log/process-watcher/events.jsonl                # events
```

`install.sh` copies the binary to `/usr/local/bin/process-watcher`, creates `/etc/process-watcher/config.yaml`
(`0600`, only if none exists yet) and the unit `/etc/systemd/system/process-watcher.service`, and does **not** start
the service.

## The unit [systemd/process-watcher.service](systemd/process-watcher.service)

- **Absolute paths and an explicit configuration file.** `run` validates the configuration itself before it creates
  or attaches anything and exits with code 2 on an error. There is deliberately no
  `ExecStartPre=… check-config`: systemd applies `RestartPreventExitStatus` to the main process only, so a failing
  `ExecStartPre` would be restarted every `RestartSec` (measured: five restarts in 30 s). Check the configuration by
  hand before starting (`process-watcher check-config`, see above).
- **`Restart=on-failure`** with `RestartPreventExitStatus=2 3`: a restart cannot fix configuration errors (2) or
  missing kernel requirements (3).
- **`LogsDirectory=process-watcher`** creates `/var/log/process-watcher` with `0700` and keeps it writable under
  `ProtectSystem=strict`; `outputs.file.path` belongs there.
- **`CapabilityBoundingSet`** contains only what the agent needs: `CAP_BPF` and `CAP_PERFMON` (load and attach the
  programs), `CAP_SYS_RESOURCE` (`RLIMIT_MEMLOCK` before kernel 5.11), `CAP_SYS_PTRACE` (read `/proc/<pid>/exe` of other
  users' processes), `CAP_KILL` (only for `kill.enabled`: signals to processes of other users).
- **Other log directories.** Under `ProtectSystem=strict` nothing but `/var/log/process-watcher` is writable. If
  `outputs.file.path` is elsewhere, in a directory that must already exist, the unit needs a drop-in
  (`sudo systemctl edit process-watcher`):

  ```ini
  [Service]
  ReadWritePaths=/srv/pwlogs
  ```

  Directories under `/root` and `/home` cannot be used because of `ProtectHome=yes`. A wrong path ends the agent with
  exit code 1; `Restart=on-failure` then restarts it every `RestartSec` until the path is right (the journal shows
  `open local log: …`).
- **Restricting the capabilities further.** A drop-in has to empty the set first, otherwise systemd only adds to it:

  ```ini
  [Service]
  CapabilityBoundingSet=
  CapabilityBoundingSet=CAP_BPF CAP_PERFMON CAP_SYS_RESOURCE CAP_SYS_PTRACE
  ```

  (without `CAP_KILL` the kill feature reports `permission_denied` for processes of other users).
- **Deliberately not set:** `ProtectProc=invisible`, `PrivateUsers=` and `PrivateNetwork=` (the agent has to see all
  host processes and reach remote targets). Adopt further hardening options only after a test with
  `process-watcher doctor` under the service account: a service that runs without its required privileges and
  observes nothing is not operational.

## Changing the configuration, rotation, updates

- Changes: `sudo systemctl restart process-watcher`. Every start begins a new run (new `agent_instance_id`);
  `agent.started` names the start window in which history is unknown.
- The agent rotates the log itself (`outputs.file.rotate_size_mb`, `keep_files`). Do **not** use external rotation
  through `logrotate` (rename/copytruncate).
- Update: copy the new binary to `/usr/local/bin/process-watcher` and restart.

## Uninstalling

```bash
sudo systemctl disable --now process-watcher
sudo rm /etc/systemd/system/process-watcher.service /usr/local/bin/process-watcher
sudo rm -r /etc/process-watcher        # configuration
# /var/log/process-watcher holds the events and is kept
```

## Troubleshooting

| Symptom | Cause |
| --- | --- |
| Exit code 3 with "privileges" | The service runs without `CAP_BPF`/`CAP_PERFMON` (restricted capability set, container). |
| Exit code 3 with "pid namespace" | Started in a container without `--pid=host`; start it on the host. |
| Exit code 3 with "kernel BTF" | The kernel has no `CONFIG_DEBUG_INFO_BTF`; `/sys/kernel/btf/vmlinux` is missing. |
| Exit code 3 with "kernel lockdown" | Lockdown mode `confidentiality` forbids BPF to read kernel memory. |
| Exit code 1 at start, "another process-watcher" | A second agent writes the same log (`<path>.lock`). |
| `agent.gap` with `ring_buffer_full` | More process events than the ring buffer holds: increase `runtime.ring_buffer_mb`. |
