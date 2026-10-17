#!/bin/bash
# Runs inside the pw-vm-qemu container (see tests/vm/run.sh).
#
#   boot.sh <arch> <kernel-image> <rootfs.cpio.gz> <test-binary> [-- args...]
#
# Builds the per-run initramfs overlay (/init, the test binary, its arguments),
# boots the kernel under QEMU and relays the serial console to stdout with
# CR/LF turned into LF. Exit status: that of QEMU (0 after the guest powered
# itself off), 124 if the global timeout killed the VM.
#
# Environment (all optional):
#   PW_VM_TIMEOUT      seconds the VM may run in total (default 900)
#   PW_VM_SMP          virtual CPUs (default 4)
#   PW_VM_MEM          guest RAM in MiB (default 2048)
#   PW_VM_KARGS        extra kernel command line words
#   PW_VM_ENV          blank separated NAME=value pairs exported to the binary
#   PW_VM_CPU          value of qemu's -cpu (default: max for amd64, max,pauth=off for arm64)
#   PW_VM_QEMU_EXTRA   extra qemu arguments, split at blanks
#   PW_VM_ACCEL        tcg (default) or kvm (needs /dev/kvm and a same-arch guest)
set -u -o pipefail

[ $# -ge 4 ] || { echo "usage: boot.sh <arch> <kernel> <rootfs.cpio.gz> <binary> [-- args...]" >&2; exit 64; }
arch=$1
kernel=$2
rootfs=$3
bin=$4
shift 4
if [ "${1:-}" = "--" ]; then shift; fi

timeout_s=${PW_VM_TIMEOUT:-900}
smp=${PW_VM_SMP:-4}
mem=${PW_VM_MEM:-2048}
accel=${PW_VM_ACCEL:-tcg}
name=$(basename "$bin")

# shq prints its argument as one single-quoted POSIX shell word.
shq() {
	local q=\' s=$1
	s=${s//$q/$q\\$q$q}
	printf "'%s'" "$s"
}

# --- initramfs overlay ----------------------------------------------------------
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/overlay/pwtest"
install -m 0755 /vm/guest/init "$work/overlay/init"
install -m 0755 "$bin" "$work/overlay/pwtest/$name"
# The agent binary, when run.sh staged one next to the test binary.
if [ -f "$(dirname "$bin")/process-watcher" ]; then
	install -m 0755 "$(dirname "$bin")/process-watcher" "$work/overlay/pwtest/process-watcher"
fi
# Build configuration of the kernel, when the cache entry has one.
if [ -f "$(dirname "$kernel")/config" ]; then
	install -m 0644 "$(dirname "$kernel")/config" "$work/overlay/pwtest/kernel.config"
fi
{
	printf 'PW_BIN=%s\n' "$(shq "/pwtest/$name")"
	for kv in ${PW_VM_ENV:-}; do
		case $kv in
		[A-Za-z_]*=*) printf 'export %s=%s\n' "${kv%%=*}" "$(shq "${kv#*=}")" ;;
		*) echo "PW-VM: ignoring malformed PW_VM_ENV item '$kv'" >&2 ;;
		esac
	done
	printf 'set --'
	for a in "$@"; do printf ' %s' "$(shq "$a")"; done
	printf '\n'
} > "$work/overlay/pwtest/env.sh"
(cd "$work/overlay" && find . -print0 | LC_ALL=C sort -z | cpio --null -o -H newc -R 0:0 --quiet) > "$work/overlay.cpio"

# The kernel accepts several concatenated archives. A raw cpio archive must
# start on a 4 byte boundary, so pad the compressed base archive with zeros.
size=$(stat -c %s "$rootfs")
pad=$(((4 - size % 4) % 4))
{
	cat "$rootfs"
	head -c "$pad" /dev/zero
	cat "$work/overlay.cpio"
} > "$work/initrd.img"

# --- machine ---------------------------------------------------------------------
case $arch in
arm64)
	qemu=qemu-system-aarch64
	console=ttyAMA0
	machine=(-machine virt,gic-version=3)
	cpu=(-cpu max,pauth=off)
	;;
amd64)
	qemu=qemu-system-x86_64
	console=ttyS0
	machine=(-machine q35)
	cpu=(-cpu max)
	;;
*)
	echo "PW-VM: unsupported architecture '$arch'" >&2
	exit 64
	;;
esac

if [ -n "${PW_VM_CPU:-}" ]; then
	cpu=(-cpu "$PW_VM_CPU")
fi

case $accel in
tcg) ;;
kvm)
	[ -c /dev/kvm ] || { echo "PW-VM: PW_VM_ACCEL=kvm but /dev/kvm is not available in the container" >&2; exit 125; }
	machine[1]="${machine[1]},accel=kvm"
	cpu=(-cpu host)
	;;
*)
	echo "PW-VM: PW_VM_ACCEL must be tcg or kvm" >&2
	exit 64
	;;
esac

cmdline="console=$console rdinit=/init panic=-1 oops=panic loglevel=4 ${PW_VM_KARGS:-}"
args=(
	"${machine[@]}" "${cpu[@]}"
	-smp "$smp" -m "$mem"
	-kernel "$kernel" -initrd "$work/initrd.img" -append "$cmdline"
	-nodefaults -no-user-config -display none -monitor none -serial stdio
	-no-reboot
)
# shellcheck disable=SC2206 # intentional word splitting of the extra arguments
args+=(${PW_VM_QEMU_EXTRA:-})

echo "PW-VM: booting ($arch, $accel, $smp vCPUs, $mem MiB, timeout ${timeout_s}s): $qemu --version: $("$qemu" --version | head -n 1)" >&2

timeout -k 10 "$timeout_s" "$qemu" "${args[@]}" 2>&1 | sed -u 's/\r$//'
rc=${PIPESTATUS[0]}
if [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ]; then
	echo "PW-VM: TIMEOUT: the VM was still running after ${timeout_s}s and was killed"
	exit 124
fi
exit "$rc"
