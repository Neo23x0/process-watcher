# Tool image for tests/vm/run.sh: QEMU (aarch64 and x86_64 system emulators)
# plus the few tools that fetch kernels and build initramfs images.
#
# Reproducibility: the base image is pinned by digest and apt resolves packages
# from the Debian snapshot of the base image's build date (HTTPS only; plain
# HTTP is blocked from containers on Docker Desktop). Same pinning scheme as
# build/ebpf/Dockerfile.
FROM debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f

ARG SNAPSHOT=20261005T000000Z
# QEMU 10.0 is the trixie version; an explicit pin makes a snapshot bump that
# changes the emulator fail loudly instead of silently.
ARG QEMU_VERSION=1:10.0.13+ds-0+deb13u1

# debian:trixie-slim ships no CA bundle, so TLS verification is switched off
# for the single bootstrap install of ca-certificates only. apt still verifies
# the signed InRelease of the snapshot against debian-archive-keyring, so a
# tampered mirror cannot inject packages. Everything after that is verified.
RUN printf '%s\n' \
      'Types: deb' \
      "URIs: https://snapshot.debian.org/archive/debian/${SNAPSHOT}/" \
      'Suites: trixie trixie-updates' \
      'Components: main' \
      'Signed-By: /usr/share/keyrings/debian-archive-keyring.pgp' \
      '' \
      'Types: deb' \
      "URIs: https://snapshot.debian.org/archive/debian-security/${SNAPSHOT}/" \
      'Suites: trixie-security' \
      'Components: main' \
      'Signed-By: /usr/share/keyrings/debian-archive-keyring.pgp' \
      > /etc/apt/sources.list.d/debian.sources \
 && apt-get -o Acquire::Check-Valid-Until=false -o Acquire::https::Verify-Peer=false update \
 && apt-get -o Acquire::https::Verify-Peer=false install -y --no-install-recommends ca-certificates \
 && apt-get -o Acquire::Check-Valid-Until=false update \
 && apt-get install -y --no-install-recommends \
      qemu-system-arm=${QEMU_VERSION} qemu-system-x86=${QEMU_VERSION} qemu-system-data=${QEMU_VERSION} seabios \
      curl gpgv ubuntu-keyring cpio gzip zstd xz-utils tar \
 && rm -rf /var/lib/apt/lists/* \
 && qemu-system-aarch64 --version | head -n1 \
 && qemu-system-x86_64 --version | head -n1

WORKDIR /vm
