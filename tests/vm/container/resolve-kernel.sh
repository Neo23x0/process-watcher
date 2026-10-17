#!/bin/bash
# Runs inside the pw-vm-qemu container. Maintenance helper for kernels.txt: lists
# kernel image packages of a distribution archive together with the SHA-256
# from the archive's own index. The chain is verified first: the InRelease file
# must carry a valid signature of the distribution keyring, and the Packages
# index must match the checksum listed in it.
#
#   docker run --rm -v "$PWD/tests/vm:/vm:ro" <image> /vm/container/resolve-kernel.sh \
#       <ubuntu|debian> <suite> <arch> <package-regex> [count]
#
# Examples:
#   resolve-kernel.sh ubuntu jammy-updates amd64 '^linux-image-5\.15\.0-[0-9]+-generic$'
#   resolve-kernel.sh ubuntu noble-updates arm64 '^linux-image-6\.8\.0-[0-9]+-generic$'
#   resolve-kernel.sh debian trixie-security amd64 '^linux-image-6\.12\.[0-9]+\+deb13-amd64$'
#
# Output, newest first (count lines, default 3): version, package, size,
# sha256, URL.
set -euo pipefail

[ $# -ge 4 ] || { sed -n '2,19p' "$0" >&2; exit 64; }
distro=$1
suite=$2
arch=$3
regex=$4
count=${5:-3}

case $distro:$arch in
ubuntu:amd64) base=https://archive.ubuntu.com/ubuntu ;;
ubuntu:arm64) base=https://ports.ubuntu.com/ubuntu-ports ;;
debian:*)
	case $suite in
	*-security) base=https://deb.debian.org/debian-security ;;
	*) base=https://deb.debian.org/debian ;;
	esac
	;;
*)
	echo "unsupported distro/arch $distro/$arch" >&2
	exit 64
	;;
esac
case $distro in
ubuntu) keyring=/usr/share/keyrings/ubuntu-archive-keyring.gpg ;;
debian) keyring=/usr/share/keyrings/debian-archive-keyring.pgp ;;
esac

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"

curl -fsS -o InRelease "$base/dists/$suite/InRelease"
gpgv --keyring "$keyring" --output Release InRelease >&2 || { echo "InRelease signature check failed" >&2; exit 1; }

index=main/binary-$arch/Packages.xz
curl -fsS -o Packages.xz "$base/dists/$suite/$index"
want=$(awk -v f="$index" '/^SHA256:/ { s = 1; next } /^[A-Za-z]/ { s = 0 } s && $3 == f { print $1 }' Release)
got=$(sha256sum Packages.xz | cut -d' ' -f1)
[ -n "$want" ] && [ "$want" = "$got" ] || { echo "Packages index checksum mismatch (want $want, got $got)" >&2; exit 1; }
echo "verified: $base/dists/$suite/$index ($got)" >&2

xz -dc Packages.xz | awk -v re="$regex" -v base="$base" 'BEGIN { RS = ""; FS = "\n" } {
	pkg = ""; ver = ""; fn = ""; sha = ""; size = ""
	for (i = 1; i <= NF; i++) {
		if ($i ~ /^Package: /) pkg = substr($i, 10)
		else if ($i ~ /^Version: /) ver = substr($i, 10)
		else if ($i ~ /^Filename: /) fn = substr($i, 11)
		else if ($i ~ /^SHA256: /) sha = substr($i, 9)
		else if ($i ~ /^Size: /) size = substr($i, 7)
	}
	if (pkg ~ re) print ver, pkg, size, sha, base "/" fn
}' | sort -V | tail -n "$count" | sort -rV
