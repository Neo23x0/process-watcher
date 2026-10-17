#!/usr/bin/env bash
# Boots a real Linux kernel in QEMU with systemd as PID 1 and runs the systemd
# service tests of process-watcher in it (tests/vm/guest/systemd-test.sh).
#
#   tests/vm/run-systemd.sh <arch> <kernel-id> <agent-binary> [scenario...]
#
#   arch          arm64 | amd64
#   kernel-id     an entry of tests/vm/kernels.txt (run.sh --list shows them)
#   agent-binary  the static process-watcher binary of that architecture:
#                 GOOS=linux GOARCH=<arch> CGO_ENABLED=0 go build -trimpath \
#                   -o dist/vm/process-watcher-<arch> ./cmd/process-watcher
#   scenario      S1 ... S8 (default: all); e.g. "S3 S4" for a quick run
#
# `make test-vm-systemd ARCH=arm64 KERNEL=ubuntu-5.15` builds the binary and
# calls this script.
#
# The guest is the Ubuntu 22.04 userland WITH systemd 249 (Dockerfile.systemd),
# booted from an initramfs: guest/init-systemd mounts a few pseudo file systems
# and execs systemd. systemd runs pw-vm-test.service, which installs the
# product exactly as a user would (packaging/install.sh), runs the scenarios
# against the real unit and prints PASS/FAIL lines plus PW-VM-EXIT=<number of
# failed checks>. The VM console is streamed to stdout; this script exits with
# that number (0: everything passed). Other outcomes as in run.sh: 124 timeout
# (PW_VM_TIMEOUT, default 1800 s here), 125 VM or tooling failure, 64 usage.
# Details, environment variables and caching: tests/vm/README.md.
#
# Shares kernels.txt, the cache directory and the tool image with run.sh; does
# not touch run.sh or the plain-mode guest. Written for the bash 3.2 that ships
# with macOS.

set -o pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
CACHE=${PW_VM_CACHE:-$HERE/cache}
TIMEOUT=${PW_VM_TIMEOUT:-1800}

# Same Ubuntu 22.04 base images as run.sh (keep the digests in sync with it).
ROOTFS_NAME=ubuntu-22.04-systemd
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
usage: $0 <arch> <kernel-id> <agent-binary> [scenario...]

  arch          arm64 | amd64
  kernel-id     an entry of $HERE/kernels.txt
  agent-binary  static process-watcher binary of that architecture, e.g. built with
                GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath ./cmd/process-watcher
  scenario      S1 ... S8, default all

environment: PW_VM_TIMEOUT (seconds, default 1800), PW_VM_SMP (default 4),
             PW_VM_MEM (MiB, default 2048), PW_VM_KARGS, PW_VM_ENV, PW_VM_CPU,
             PW_VM_QEMU_EXTRA, PW_VM_KVM (auto|0|1), PW_VM_CACHE, PW_VM_LOG
EOF
	exit 64
}

sha256_of() {
	if command -v sha256sum > /dev/null 2>&1; then
		sha256sum "$1" | cut -d' ' -f1
	else
		shasum -a 256 "$1" | cut -d' ' -f1
	fi
}

# --- arguments --------------------------------------------------------------------
[ $# -ge 3 ] || usage
ARCH=$1
KID=$2
BIN=$3
shift 3
SCENARIOS=("$@")

case $ARCH in
arm64 | amd64) ;;
*) die 64 "unknown architecture '$ARCH' (use arm64 or amd64)" ;;
esac
for s in ${SCENARIOS[@]+"${SCENARIOS[@]}"}; do
	case $s in
	S[1-8] | S[1-8][a-z]) ;;
	*) die 64 "unknown scenario '$s' (use S1 ... S8, or a part such as S7a)" ;;
	esac
done

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
	"$HERE/run.sh" --list >&2
	exit 64
fi

[ -f "$BIN" ] || die 64 "agent binary '$BIN' not found"
case "$TIMEOUT" in '' | *[!0-9]*) die 64 "PW_VM_TIMEOUT must be a number of seconds, got '$TIMEOUT'" ;; esac
[ -f "$REPO/packaging/install.sh" ] || die 64 "$REPO/packaging/install.sh not found"

# The binary must be an ELF executable of the guest's architecture.
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

# Tool image: the one of run.sh, rebuilt only when its Dockerfile changes.
IMAGE=pw-vm-qemu:$(sha256_of "$HERE/Dockerfile" | cut -c1-12)
if ! docker image inspect "$IMAGE" > /dev/null 2>&1; then
	say "building the QEMU tool image $IMAGE (first run only)"
	docker build -q -t "$IMAGE" - < "$HERE/Dockerfile" > /dev/null || die 125 "building the QEMU tool image failed"
fi

mkdir -p "$CACHE/kernels" "$CACHE/rootfs" "$CACHE/logs"
tool() { # tool <extra docker args...> -- <command...>
	docker run --rm --init -v "$CACHE:/cache" -v "$HERE:/vm:ro" "$@"
}

# Kernel: downloaded, verified against the pinned checksum, cached (shared with run.sh).
KDIR=$CACHE/kernels/$ARCH/$KID
K_STAMP=$K_SHA${K_CFG_SHA:+ $K_CFG_SHA}
if [ ! -f "$KDIR/vmlinuz" ] || [ "$(cat "$KDIR/stamp" 2> /dev/null)" != "$K_STAMP" ]; then
	say "fetching kernel $KID/$ARCH ($K_VERSION)"
	FETCH=("$K_URL" "$K_SHA" "/cache/kernels/$ARCH/$KID")
	if [ -n "$K_CFG_URL" ]; then FETCH+=("$K_CFG_URL" "$K_CFG_SHA"); fi
	tool "$IMAGE" /vm/container/fetch-kernel.sh "${FETCH[@]}" || die 125 "fetching the kernel failed"
fi

# Rootfs: the pinned Ubuntu image plus systemd 249 (Dockerfile.systemd), built
# once per architecture and turned into an initramfs archive. The name carries
# a hash of the Dockerfile and the base image, so a change rebuilds it.
RIMG=$(rootfs_image "$ARCH")
RHASH=$( (cat "$HERE/Dockerfile.systemd"; echo "$RIMG") | { if command -v sha256sum > /dev/null 2>&1; then sha256sum; else shasum -a 256; fi; } | cut -c1-12)
ROOTFS=$CACHE/rootfs/$ROOTFS_NAME-$ARCH-$RHASH.cpio.gz
if [ ! -f "$ROOTFS" ]; then
	SD_TAG=pw-vm-systemd-rootfs:$ARCH-$RHASH
	say "building the $ARCH systemd root file system from $RIMG (first run only)"
	docker build -q --platform "linux/$ARCH" --build-arg "BASE=$RIMG" -t "$SD_TAG" - < "$HERE/Dockerfile.systemd" > /dev/null \
		|| die 125 "building the systemd guest image failed (docker build --platform linux/$ARCH -f tests/vm/Dockerfile.systemd shows why)"
	RCID=$(docker create --platform "linux/$ARCH" "$SD_TAG" /bin/true) || die 125 "docker create $SD_TAG failed"
	docker export "$RCID" | tool -i "$IMAGE" /vm/container/build-rootfs.sh "/cache/rootfs/$(basename "$ROOTFS")"
	rc=("${PIPESTATUS[@]}")
	docker rm "$RCID" > /dev/null 2>&1
	RCID=
	[ "${rc[0]}" -eq 0 ] && [ "${rc[1]}" -eq 0 ] || die 125 "building the root file system failed"
fi

# Stage a copy of the agent binary inside the shared cache directory: it is a
# path Docker is certain to share, and the run is immune to a rebuild.
STAGE=$CACHE/stage-systemd.$$
mkdir -p "$STAGE"
cp "$BIN" "$STAGE/process-watcher" || die 125 "cannot copy the agent binary"

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

LOG=${PW_VM_LOG:-$CACHE/logs/$ARCH-$KID-systemd.log}
mkdir -p "$(dirname "$LOG")"
: > "$LOG"

say "systemd test: kernel $KID $ARCH $K_VERSION, guest $ROOTFS_NAME, accel $ACCEL, timeout ${TIMEOUT}s, log $LOG"

T_VM=$(date +%s)
CNAME=pw-vm-$$-$(date +%s)
docker run --rm --name "$CNAME" "${KVM_ARGS[@]}" \
	-v "$HERE:/vm:ro" \
	-v "$KDIR:/kernel:ro" \
	-v "$ROOTFS:/rootfs.cpio.gz:ro" \
	-v "$STAGE:/in:ro" \
	-v "$REPO/packaging:/packaging:ro" \
	-e "PW_VM_TIMEOUT=$TIMEOUT" -e "PW_VM_ACCEL=$ACCEL" \
	-e PW_VM_SMP -e PW_VM_MEM -e PW_VM_KARGS -e PW_VM_ENV -e PW_VM_CPU -e PW_VM_QEMU_EXTRA \
	"$IMAGE" /vm/container/boot-systemd.sh "$ARCH" /kernel/vmlinuz /rootfs.cpio.gz /in/process-watcher /packaging \
	-- ${SCENARIOS[@]+"${SCENARIOS[@]}"} 2>&1 | tee "$LOG"
DOCKER_RC=${PIPESTATUS[0]}
CNAME=
T_END=$(date +%s)

# --- verdict ----------------------------------------------------------------------
# The guest prints PW-VM-EXIT=<failed checks> as the last thing before powering off.
STATUS=$(sed -n 's/^PW-VM-EXIT=\([0-9][0-9]*\)$/\1/p' "$LOG" | tail -n 1)
if [ -n "$STATUS" ]; then
	RC=$STATUS
	WHAT="the guest reported $RC failed check(s)"
	if [ "$DOCKER_RC" -ne 0 ]; then
		say "warning: the guest reported its result but the VM did not exit cleanly (QEMU/docker status $DOCKER_RC)"
	fi
elif grep -q 'PW-VM: TIMEOUT' "$LOG" || [ "$DOCKER_RC" -eq 124 ]; then
	say "TIMEOUT: no result after ${TIMEOUT}s (set PW_VM_TIMEOUT to allow more); the VM was killed"
	RC=124
	WHAT="timeout"
elif grep -q 'Kernel panic' "$LOG"; then
	say "KERNEL PANIC before the test script reported a result (see the console output above)"
	RC=125
	WHAT="kernel panic"
else
	say "the VM ended without an exit marker (QEMU/docker status $DOCKER_RC): boot failure or crash, see the console output above"
	RC=125
	WHAT="no result"
fi

# Per-check summary from the log (the guest prefixes its verdict lines with PW-SYSTEMD:).
NPASS=$(grep -c '^PW-SYSTEMD: PASS ' "$LOG")
NFAIL=$(grep -c '^PW-SYSTEMD: FAIL ' "$LOG")
say "checks: $NPASS passed, $NFAIL failed"
if [ "$NFAIL" -gt 0 ]; then
	grep '^PW-SYSTEMD: FAIL ' "$LOG" | sed 's/^PW-SYSTEMD: /PW-VM:   /' >&2
fi
say "exit status $RC ($WHAT); prepare $((T_VM - T_START))s, VM $((T_END - T_VM))s, total $((T_END - T_START))s"
exit "$RC"
