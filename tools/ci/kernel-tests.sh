#!/usr/bin/env bash
# Builds the agent and the privileged test binaries and runs them as root
# against the kernel of this machine: the collector tests (real eBPF programs),
# the real pidfd tests and the agent end-to-end tests. They need root and the
# initial PID namespace of the host; a throw-away VM or a privileged container
# started with --pid=host is fine. Used by .github/workflows/ci.yml.
set -euo pipefail

cd "$(dirname "$0")/../.."
out=dist/ci
mkdir -p "$out"

go build -trimpath -buildvcs=false -o "$out/process-watcher" ./cmd/process-watcher
go test -c -o "$out/procfs.test" ./internal/procfs
go test -c -o "$out/response.test" ./internal/response
go test -c -o "$out/collector.test" ./internal/collector/ebpf
go test -c -o "$out/e2e.test" ./tests/integration

echo "kernel: $(uname -srm)"
ls -la /sys/kernel/btf/vmlinux || echo "no /sys/kernel/btf/vmlinux: the agent cannot run here"
cat /sys/kernel/security/lockdown 2> /dev/null || true

sudo=""
[ "$(id -u)" -eq 0 ] || sudo="sudo"
cd "$out"
$sudo ./procfs.test -test.v
$sudo ./response.test -test.v
$sudo ./collector.test -test.v -test.timeout 10m
$sudo env PW_AGENT_BIN="$PWD/process-watcher" ./e2e.test -test.v -test.timeout 30m
