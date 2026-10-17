# Toolchain image that generates the embedded eBPF objects (make generate).
# The target host never needs clang/LLVM; only developers regenerating the
# objects do. The base image is pinned by digest and apt resolves packages from
# the Debian snapshot of the base image's build date (HTTPS only), so the
# compiler version is reproducible.
FROM golang:1.26-trixie@sha256:f06b7122f888680048afb247c4e5f49c0069eb6c4c1ccae0f3f4834527a8d22c

ARG SNAPSHOT=20261005T000000Z

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
 && apt-get -o Acquire::Check-Valid-Until=false update \
 && apt-get install -y --no-install-recommends clang llvm libbpf-dev bpftool make \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
