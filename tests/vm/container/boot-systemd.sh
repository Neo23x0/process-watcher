#!/bin/bash
# Runs inside the pw-vm-qemu container (see tests/vm/run-systemd.sh).
#
#   boot-systemd.sh <arch> <kernel-image> <rootfs.cpio.gz> <agent-binary> <packaging-dir> [-- scenario...]
#
# The systemd-mode counterpart of boot.sh: builds the per-run initramfs overlay
# (guest/init-systemd as /init, the agent binary, packaging/, the guest test
# script and the unit that runs it, /pwtest/env.sh), boots the kernel under QEMU
# and relays the serial console to stdout with CR/LF turned into LF. Exit
# status: that of QEMU (0 after the guest powered itself off), 124 if the
# global timeout killed the VM.
#
# Environment (all optional):
#   PW_VM_TIMEOUT      seconds the VM may run in total (default 1800)
#   PW_VM_SMP          virtual CPUs (default 4)
#   PW_VM_MEM          guest RAM in MiB (default 2048)
#   PW_VM_KARGS        extra kernel command line words
#   PW_VM_ENV          blank separated NAME=value pairs exported to the test script
#   PW_VM_CPU          value of qemu's -cpu (default: max for amd64, max,pauth=off for arm64)
#   PW_VM_QEMU_EXTRA   extra qemu arguments, split at blanks
#   PW_VM_ACCEL        tcg (default) or kvm (needs /dev/kvm and a same-arch guest)
set -u -o pipefail

[ $# -ge 5 ] || { echo "usage: boot-systemd.sh <arch> <kernel> <rootfs.cpio.gz> <agent> <packaging-dir> [-- scenario...]" >&2; exit 64; }
arch=$1
kernel=$2
rootfs=$3
agent=$4
packaging=$5
shift 5
if [ "${1:-}" = "--" ]; then shift; fi

timeout_s=${PW_VM_TIMEOUT:-1800}
smp=${PW_VM_SMP:-4}
mem=${PW_VM_MEM:-2048}
accel=${PW_VM_ACCEL:-tcg}

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
install -m 0755 /vm/guest/init-systemd "$work/overlay/init"
install -m 0755 "$agent" "$work/overlay/pwtest/process-watcher"
install -m 0755 /vm/guest/systemd-test.sh "$work/overlay/pwtest/systemd-test.sh"
install -m 0644 /vm/guest/pw-vm-test.service "$work/overlay/pwtest/pw-vm-test.service"
# packaging/ exactly as the repository has it: install.sh finds config/ and
# systemd/ next to itself.
cp -R "$packaging" "$work/overlay/pwtest/packaging"
# Build configuration of the kernel, when the cache entry has one.
if [ -f "$(dirname "$kernel")/config" ]; then
	install -m 0644 "$(dirname "$kernel")/config" "$work/overlay/pwtest/kernel.config"
fi
{
	for kv in ${PW_VM_ENV:-}; do
		case $kv in
		[A-Za-z_]*=*) printf 'export %s=%s\n' "${kv%%=*}" "$(shq "${kv#*=}")" ;;
		*) echo "PW-VM: ignoring malformed PW_VM_ENV item '$kv'" >&2 ;;
		esac
	done
	# The scenarios to run (empty: all of them).
	printf 'PW_SCENARIOS='
	sep=
	for a in "$@"; do
		printf '%s%s' "$sep" "$(shq "$a")"
		sep=' '
	done
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

# Same command line as boot.sh, plus plain-text systemd logging.
cmdline="console=$console rdinit=/init panic=-1 oops=panic loglevel=4 systemd.log_color=0 ${PW_VM_KARGS:-}"
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
