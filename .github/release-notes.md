## process-watcher @TAG@

Observes the process trees of programs whose executable name contains a configured substring (eBPF, Linux 5.15 or newer with BTF) and logs process creation, exec and exit as JSONL.

**What is in a release.** One archive per architecture, `linux/amd64` and `linux/arm64`. Each contains `process-watcher` (a single static binary; the eBPF programs are embedded, nothing else is needed at run time), `process-watcher.yaml` (the documented example configuration), `LICENSE`, and below `php/` the PHP deployment configurations of [docs/php.md](https://github.com/@REPO@/blob/main/docs/php.md) (observe, dry-run and kill variants for PHP-FPM, Apache mod_php, php-cgi and PHP CLI), usable right after unpacking; the [PHP quick start](https://github.com/@REPO@/blob/main/docs/php-quickstart.md) walks through them. `SHA256SUMS` lists the archives.

**Install**

```bash
ARCH=amd64    # or arm64
curl -fsSLO https://github.com/@REPO@/releases/download/@TAG@/process-watcher_@TAG@_linux_${ARCH}.tar.gz
curl -fsSLO https://github.com/@REPO@/releases/download/@TAG@/SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS
tar xzf process-watcher_@TAG@_linux_${ARCH}.tar.gz
cd process-watcher_@TAG@_linux_${ARCH}
sudo ./process-watcher doctor          # kernel, BTF, permissions
sudoedit process-watcher.yaml          # set watch.image_contains
sudo ./process-watcher                 # finds process-watcher.yaml next to the binary
```

The binary needs root (or `CAP_BPF` and `CAP_PERFMON`) and the host's PID namespace. See the README for the configuration, the systemd service and the delivery limits.

---

