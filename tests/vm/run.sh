#!/usr/bin/env bash
# Boots a real Linux kernel in QEMU and runs a static test binary in it as root.
#
#   tests/vm/run.sh <arch> <kernel-id> <test-binary> [args for the binary...]
#
#   arch         arm64 | amd64
#   kernel-id    an entry of tests/vm/kernels.txt (run.sh --list shows them)
#
# The VM console is streamed to stdout. The script exits with the exit status
# of the binary. Other outcomes: 124 timeout (PW_VM_TIMEOUT), 125 VM or tooling
# failure (kernel panic, no exit marker, download or build problem), 64 usage.
# Details, environment variables and caching: tests/vm/README.md.
#
# Written for the bash 3.2 that ships with macOS.

set -o pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
CACHE=${PW_VM_CACHE:-$HERE/cache}
TIMEOUT=${PW_VM_TIMEOUT:-900}

# Userland of the guest: the official Ubuntu 22.04 image, pinned by the digest
# of the per-architecture manifest (as of the 2026-09-30 image). Per-arch
# digests, because Docker's classic image store cannot hold two platforms under
# one index digest.
ROOTFS_NAME=ubuntu-22.04
rootfs_image() {
	case $1 in
	amd64) echo "ubuntu@sha256:98510ac07bb4545e389be502a8918b385c018bfe4ceeb5ac7e0375c782268b04" ;;
	arm64) echo "ubuntu@sha256:88881eb36da489f9ff8746ece8048ca16cc94f80e8cd3ae7e8335d8822631591" ;;
	esac
}

say() { echo "PW-VM: $*" >&2; }
die() {
	local code=$1
	shift
	say "$*"
	exit "$code"
}

usage() {
	cat >&2 <<EOF
usage: $0 <arch> <kernel-id> <test-binary> [args for the binary...]
       $0 --list

  arch         arm64 | amd64
  kernel-id    an entry of $HERE/kernels.txt
  test-binary  a static Linux binary of that architecture, e.g. built with
               GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go test -c ./internal/collector/ebpf

environment: PW_VM_TIMEOUT (seconds, default 900), PW_VM_SMP (default 4),
             PW_VM_MEM (MiB, default 2048), PW_VM_KARGS, PW_VM_ENV, PW_VM_CPU,
             PW_VM_QEMU_EXTRA, PW_VM_KVM (auto|0|1), PW_VM_CACHE, PW_VM_LOG
EOF
	exit 64
}

list_kernels() {
	echo "kernel-id    arch   version"
	while read -r id arch ver rest; do
		case $id in '' | '#'*) continue ;; esac
		printf '%-12s %-6s %s\n' "$id" "$arch" "$ver"
	done < "$HERE/kernels.txt"
}

sha256_of() {
	if command -v sha256sum > /dev/null 2>&1; then
		sha256sum "$1" | cut -d' ' -f1
	else
		shasum -a 256 "$1" | cut -d' ' -f1
	fi
}

# --- arguments --------------------------------------------------------------------
if [ "${1:-}" = "--list" ]; then
	list_kernels
	exit 0
fi
[ $# -ge 3 ] || usage
ARCH=$1
KID=$2
BIN=$3
shift 3

case $ARCH in
arm64 | amd64) ;;
*) die 64 "unknown architecture '$ARCH' (use arm64 or amd64)" ;;
esac

K_URL=
K_CFG_URL=
K_CFG_SHA=
while read -r id arch ver url sha cfg_url cfg_sha rest; do
	case $id in '' | '#'*) continue ;; esac
	if [ "$id" = "$KID" ] && [ "$arch" = "$ARCH" ]; then
		K_VERSION=$ver
		K_URL=$url
		K_SHA=$sha
		K_CFG_URL=$cfg_url
		K_CFG_SHA=$cfg_sha
		break
	fi
done < "$HERE/kernels.txt"
if [ -z "$K_URL" ]; then
	say "no kernel '$KID' for $ARCH in $HERE/kernels.txt; available:"
	list_kernels >&2
	exit 64
fi

[ -f "$BIN" ] || die 64 "test binary '$BIN' not found"
case "$TIMEOUT" in '' | *[!0-9]*) die 64 "PW_VM_TIMEOUT must be a number of seconds, got '$TIMEOUT'" ;; esac

# The binary must be an ELF executable of the guest's architecture; a mismatch
# would otherwise only show up as "exec format error" after a long boot.
elf_hdr=$(od -An -tx1 -N20 "$BIN" | tr -d ' \n')
case $elf_hdr in
7f454c46*) ;;
*) die 64 "'$BIN' is not an ELF binary (build it with GOOS=linux)" ;;
esac
case $ARCH:${elf_hdr:36:4} in
amd64:3e00 | arm64:b700) ;;
*:3e00) die 64 "'$BIN' is an x86-64 binary but the guest architecture is $ARCH" ;;
*:b700) die 64 "'$BIN' is an arm64 binary but the guest architecture is $ARCH" ;;
*) die 64 "'$BIN' has an unexpected ELF machine type (${elf_hdr:36:4}) for $ARCH" ;;
esac

# --- docker -----------------------------------------------------------------------
command -v docker > /dev/null 2>&1 || die 125 "docker not found; Docker Desktop is required"
docker info > /dev/null 2>&1 || die 125 "the Docker daemon is not reachable; start Docker Desktop"

T_START=$(date +%s)
CNAME=
STAGE=
RCID=
cleanup() {
	[ -n "$CNAME" ] && docker rm -f "$CNAME" > /dev/null 2>&1
	[ -n "$RCID" ] && docker rm -f "$RCID" > /dev/null 2>&1
	[ -n "$STAGE" ] && rm -rf "$STAGE"
	CNAME=
	RCID=
	STAGE=
}
trap cleanup EXIT
trap 'cleanup; exit 130' INT TERM

# Tool image: rebuilt only when the Dockerfile changes.
IMAGE=pw-vm-qemu:$(sha256_of "$HERE/Dockerfile" | cut -c1-12)
if ! docker image inspect "$IMAGE" > /dev/null 2>&1; then
	say "building the QEMU tool image $IMAGE (first run only)"
	docker build -q -t "$IMAGE" - < "$HERE/Dockerfile" > /dev/null || die 125 "building the QEMU tool image failed"
fi

mkdir -p "$CACHE/kernels" "$CACHE/rootfs" "$CACHE/logs"
tool() { # tool <extra docker args...> -- <command...>
	docker run --rm --init -v "$CACHE:/cache" -v "$HERE:/vm:ro" "$@"
}

# Kernel: downloaded, verified against the pinned checksum, cached.
KDIR=$CACHE/kernels/$ARCH/$KID
K_STAMP=$K_SHA${K_CFG_SHA:+ $K_CFG_SHA}
if [ ! -f "$KDIR/vmlinuz" ] || [ "$(cat "$KDIR/stamp" 2> /dev/null)" != "$K_STAMP" ]; then
	say "fetching kernel $KID/$ARCH ($K_VERSION)"
	FETCH=("$K_URL" "$K_SHA" "/cache/kernels/$ARCH/$KID")
	if [ -n "$K_CFG_URL" ]; then FETCH+=("$K_CFG_URL" "$K_CFG_SHA"); fi
	tool "$IMAGE" /vm/container/fetch-kernel.sh "${FETCH[@]}" || die 125 "fetching the kernel failed"
fi

# Rootfs: docker export of the pinned Ubuntu image, turned into an initramfs
# archive once per architecture.
RIMG=$(rootfs_image "$ARCH")
ROOTFS=$CACHE/rootfs/$ROOTFS_NAME-$ARCH-$(echo "${RIMG#*sha256:}" | cut -c1-12).cpio.gz
if [ ! -f "$ROOTFS" ]; then
	say "building the $ARCH root file system from $RIMG (first run only)"
	RCID=$(docker create --platform "linux/$ARCH" "$RIMG" /bin/true) || die 125 "docker create $RIMG failed"
	docker export "$RCID" | tool -i "$IMAGE" /vm/container/build-rootfs.sh "/cache/rootfs/$(basename "$ROOTFS")"
	rc=("${PIPESTATUS[@]}")
	docker rm "$RCID" > /dev/null 2>&1
	RCID=
	[ "${rc[0]}" -eq 0 ] && [ "${rc[1]}" -eq 0 ] || die 125 "building the root file system failed"
fi

# Stage a copy of the binary inside the shared cache directory: it is a path
# Docker is certain to share, and the run is immune to a rebuild of the binary.
BNAME=$(basename "$BIN")
STAGE=$CACHE/stage.$$
mkdir -p "$STAGE"
cp "$BIN" "$STAGE/$BNAME" || die 125 "cannot copy the test binary"
# Optional second file: the agent binary an end-to-end test starts. It appears
# in the guest as /pwtest/process-watcher (pass PW_VM_ENV=PW_AGENT_BIN=/pwtest/process-watcher).
if [ -n "${PW_VM_AGENT:-}" ]; then
	cp "$PW_VM_AGENT" "$STAGE/process-watcher" || die 125 "cannot copy the agent binary"
fi

# Acceleration: KVM only helps a guest of the host's own architecture.
HOST_ARCH=$(docker info --format '{{.Architecture}}' 2> /dev/null)
case $HOST_ARCH in
aarch64 | arm64) HOST_ARCH=arm64 ;;
x86_64 | amd64) HOST_ARCH=amd64 ;;
esac
ACCEL=tcg
KVM_ARGS=(--init)
KVM=${PW_VM_KVM:-auto}
if [ "$KVM" != 0 ] && [ "$HOST_ARCH" = "$ARCH" ]; then
	if docker run --rm --device /dev/kvm "$IMAGE" true > /dev/null 2>&1; then
		ACCEL=kvm
		KVM_ARGS=(--init --device /dev/kvm)
	fi
fi
if [ "$KVM" = 1 ] && [ "$ACCEL" != kvm ]; then
	die 125 "PW_VM_KVM=1 but /dev/kvm is not usable in the Docker VM for a $ARCH guest"
fi

LOG=${PW_VM_LOG:-$CACHE/logs/$ARCH-$KID.log}
mkdir -p "$(dirname "$LOG")"
: > "$LOG"

say "kernel $KID $ARCH $K_VERSION, guest $ROOTFS_NAME, accel $ACCEL, timeout ${TIMEOUT}s, log $LOG"

T_VM=$(date +%s)
CNAME=pw-vm-$$-$(date +%s)
docker run --rm --name "$CNAME" "${KVM_ARGS[@]}" \
	-v "$HERE:/vm:ro" \
	-v "$KDIR:/kernel:ro" \
	-v "$ROOTFS:/rootfs.cpio.gz:ro" \
	-v "$STAGE:/in:ro" \
	-e "PW_VM_TIMEOUT=$TIMEOUT" -e "PW_VM_ACCEL=$ACCEL" \
	-e PW_VM_SMP -e PW_VM_MEM -e PW_VM_KARGS -e PW_VM_ENV -e PW_VM_CPU -e PW_VM_QEMU_EXTRA \
	"$IMAGE" /vm/container/boot.sh "$ARCH" /kernel/vmlinuz /rootfs.cpio.gz "/in/$BNAME" -- "$@" 2>&1 | tee "$LOG"
DOCKER_RC=${PIPESTATUS[0]}
CNAME=
T_END=$(date +%s)

# --- verdict ----------------------------------------------------------------------
# The guest prints PW-VM-EXIT=<status> as the last thing before powering off.
STATUS=$(sed -n 's/^PW-VM-EXIT=\([0-9][0-9]*\)$/\1/p' "$LOG" | tail -n 1)
if [ -n "$STATUS" ]; then
	RC=$STATUS
	WHAT="the test binary exited with status $RC"
	if [ "$DOCKER_RC" -ne 0 ]; then
		say "warning: the guest reported its result but the VM did not exit cleanly (QEMU/docker status $DOCKER_RC)"
	fi
elif grep -q 'PW-VM: TIMEOUT' "$LOG" || [ "$DOCKER_RC" -eq 124 ]; then
	say "TIMEOUT: no result after ${TIMEOUT}s (set PW_VM_TIMEOUT to allow more); the VM was killed"
	RC=124
	WHAT="timeout"
elif grep -q 'Kernel panic' "$LOG"; then
	say "KERNEL PANIC before the binary reported a result (see the console output above)"
	RC=125
	WHAT="kernel panic"
else
	say "the VM ended without an exit marker (QEMU/docker status $DOCKER_RC): boot failure or crash, see the console output above"
	RC=125
	WHAT="no result"
fi

say "exit status $RC ($WHAT); prepare $((T_VM - T_START))s, VM $((T_END - T_VM))s, total $((T_END - T_START))s"
exit "$RC"
