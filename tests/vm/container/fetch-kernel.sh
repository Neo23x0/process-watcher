#!/bin/bash
# Runs inside the pw-vm-qemu container (see tests/vm/run.sh).
#
#   fetch-kernel.sh <url> <sha256> <outdir> [<config-url> <config-sha256>]
#
# Downloads a linux-image .deb over HTTPS, verifies its SHA-256, extracts only
# the kernel image from it and stores it as <outdir>/vmlinuz. If a config
# package is given (Ubuntu: linux-buildinfo), its build configuration is stored
# as <outdir>/config; without one the script looks for /boot/config-* inside
# the kernel package (Debian). <outdir>/stamp records the checksums the cache
# entry was built from; run.sh compares it with kernels.txt.
set -euo pipefail

url=$1
want=$2
out=$3
cfg_url=${4:-}
cfg_want=${5:-}

die() { echo "PW-VM: $*" >&2; exit 1; }

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# download <url> <sha256> <file>
download() {
	echo "PW-VM: downloading $1" >&2
	curl --fail --silent --show-error --location \
		--retry 3 --retry-delay 3 --connect-timeout 20 --max-time 1800 \
		--output "$3" "$1" || die "download failed: $1"
	local got
	got=$(sha256sum "$3" | cut -d' ' -f1)
	[ "$got" = "$2" ] || die "checksum mismatch for $1: expected $2, got $got"
	echo "PW-VM: checksum ok ($got)" >&2
}

download "$url" "$want" "$tmp/pkg.deb"

mkdir "$tmp/x"
dpkg-deb --fsys-tarfile "$tmp/pkg.deb" | tar -x -C "$tmp/x" --wildcards './boot/vmlinuz-*' './boot/config-*' 2> /dev/null || true
shopt -s nullglob
images=("$tmp"/x/boot/vmlinuz-*)
[ "${#images[@]}" -eq 1 ] || die "expected exactly one /boot/vmlinuz-* in the package, found ${#images[@]}"
img=${images[0]}

# Ubuntu's arm64 kernels are gzip compressed Image files. Give QEMU the raw
# image so it does not depend on its own decompression support.
magic=$(od -An -tx1 -N2 "$img" | tr -d ' \n')
if [ "$magic" = "1f8b" ]; then
	gzip -dc "$img" > "$tmp/vmlinuz"
else
	cp "$img" "$tmp/vmlinuz"
fi
chmod 0644 "$tmp/vmlinuz"

# Build configuration, if there is one.
rm -f "$tmp/config"
if [ -n "$cfg_url" ]; then
	download "$cfg_url" "$cfg_want" "$tmp/cfg.deb"
	mkdir "$tmp/c"
	dpkg-deb --fsys-tarfile "$tmp/cfg.deb" | tar -x -C "$tmp/c" --wildcards './usr/lib/linux/*/config'
	cfgs=("$tmp"/c/usr/lib/linux/*/config)
	[ "${#cfgs[@]}" -eq 1 ] || die "expected exactly one config in the config package"
	cp "${cfgs[0]}" "$tmp/config"
else
	cfgs=("$tmp"/x/boot/config-*)
	if [ "${#cfgs[@]}" -eq 1 ]; then cp "${cfgs[0]}" "$tmp/config"; fi
fi

mkdir -p "$out"
rm -f "$out/vmlinuz" "$out/config" "$out/stamp" "$out/deb.sha256"
mv "$tmp/vmlinuz" "$out/vmlinuz"
if [ -f "$tmp/config" ]; then
	chmod 0644 "$tmp/config"
	mv "$tmp/config" "$out/config"
fi
echo "$want${cfg_want:+ $cfg_want}" > "$out/stamp"
echo "PW-VM: kernel cached as $out/vmlinuz ($(stat -c %s "$out/vmlinuz") bytes, from $(basename "$img"))$([ -f "$out/config" ] && echo ", with build config")" >&2
