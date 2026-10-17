#!/bin/bash
# Runs inside the pw-vm-qemu container (see tests/vm/run.sh).
#
#   docker export <container> | build-rootfs.sh <output.cpio.gz>
#
# Reads the tar of an exported Ubuntu container root file system from stdin and
# writes a gzip compressed "newc" cpio archive that the kernel can unpack as
# its initramfs. The archive is the real distribution userland (GNU coreutils,
# dash, bash, glibc), only with the device nodes the kernel needs before /init
# can mount devtmpfs. /init and the test binary are not part of it: they come
# in a small per-run overlay (container/boot.sh), so this file is built once
# per architecture and reused.
set -euo pipefail

out=$1

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

echo "PW-VM: unpacking root file system" >&2
tar -x -C "$work" --numeric-owner --same-owner -p

# Sanity: this must be a real distribution userland, not a busybox image.
[ -x "$work/usr/bin/true" ] && [ ! -L "$work/usr/bin/true" ] || { echo "PW-VM: /usr/bin/true is not a regular file" >&2; exit 1; }
[ -L "$work/bin" ] || { echo "PW-VM: expected a merged-/usr layout (/bin -> usr/bin)" >&2; exit 1; }

# The kernel opens /dev/console before it runs /init.
mkdir -p "$work/dev" "$work/proc" "$work/sys" "$work/tmp" "$work/run" "$work/pwtest"
rm -f "$work/dev/console" "$work/dev/null"
mknod -m 0600 "$work/dev/console" c 5 1
mknod -m 0666 "$work/dev/null" c 1 3
chmod 1777 "$work/tmp"

# Package caches and lists are dead weight in a RAM file system.
rm -rf "$work"/var/lib/apt/lists/* "$work"/var/cache/apt/* "$work"/var/cache/debconf/*-old "$work"/usr/share/doc/* "$work"/usr/share/man/* "$work"/usr/share/info/*

echo "PW-VM: building initramfs archive" >&2
mkdir -p "$(dirname "$out")"
tmp_out=$out.tmp.$$
(
	cd "$work"
	find . -print0 | LC_ALL=C sort -z | cpio --null -o -H newc -R 0:0 --quiet
) | gzip -9n > "$tmp_out"
mv "$tmp_out" "$out"
echo "PW-VM: wrote $out ($(stat -c %s "$out") bytes compressed, $(du -sk "$work" | cut -f1) KiB unpacked)" >&2
