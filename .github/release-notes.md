## process-watcher @TAG@

Observes the process trees of programs whose executable name contains a configured substring (eBPF, Linux 5.15 or newer with BTF) and logs process creation, exec and exit as JSONL.

**What is in a release.** One archive per architecture, `linux/amd64` and `linux/arm64`. Each contains `process-watcher` (a single static binary; the eBPF programs are embedded, nothing else is needed at run time), `process-watcher.yaml` (the documented example configuration), `LICENSE`, below `php/` the two configurations of the PHP kit (`php-observe.yaml` observes every PHP runtime, `php-fpm-kill-signatures.yaml` holds the PHP-FPM response rules and ships as a dry run), usable right after unpacking (the [PHP kit](https://github.com/@REPO@/tree/main/emerging-threats/php-rce-october-26) has the guide), and in `packaging/` the systemd unit with the script that installs it. Every archive is published under two names with the same files: `process-watcher_@TAG@_linux_<arch>.tar.gz` (this version) and `process-watcher_linux_<arch>.tar.gz` (the same name in every release; `https://github.com/@REPO@/releases/latest/download/process-watcher_linux_<arch>.tar.gz` serves the newest stable release). `SHA256SUMS` lists all of them.

**Install**

```bash
ARCH=$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')    # amd64 or arm64
curl -fsSLO https://github.com/@REPO@/releases/download/@TAG@/process-watcher_@TAG@_linux_${ARCH}.tar.gz
curl -fsSLO https://github.com/@REPO@/releases/download/@TAG@/SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS
tar xzf process-watcher_@TAG@_linux_${ARCH}.tar.gz
cd process-watcher_@TAG@_linux_${ARCH}
sudo ./process-watcher doctor          # kernel, BTF, permissions
sudoedit process-watcher.yaml          # set watch.image_contains
sudo ./process-watcher                 # finds process-watcher.yaml next to the binary
```

The binary needs root (or `CAP_BPF` and `CAP_PERFMON`) and the host's PID namespace. To keep it running as a systemd service, run `sudo ./packaging/install.sh ./process-watcher` from the unpacked archive, edit `/etc/process-watcher/config.yaml` and start it with `sudo systemctl enable --now process-watcher`. See the README for the configuration and the delivery limits.

---

