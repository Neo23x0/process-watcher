SHELL := /bin/bash

VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS  := -s -w -X main.version=$(VERSION)
DIST     := dist
EBPF_IMAGE ?= process-watcher-ebpf-build

GO_IMAGE ?= golang:1.26-trixie
# Architecture of the Docker host VM (arm64 on Apple silicon, amd64 elsewhere).
DOCKER_ARCH ?= $(shell docker info --format '{{.Architecture}}' 2>/dev/null | sed 's/aarch64/arm64/;s/x86_64/amd64/')

.PHONY: all build build-linux release-archives test vet generate ebpf-image test-docker bench-docker test-vm test-vm-matrix test-vm-e2e test-race-docker clean

all: vet test build

build:
	go build -trimpath -ldflags '$(LDFLAGS)' -o $(DIST)/process-watcher ./cmd/process-watcher

# Static Linux binaries; the embedded eBPF objects are already committed.
build-linux:
	mkdir -p $(DIST)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags '$(LDFLAGS)' -o $(DIST)/process-watcher-linux-amd64 ./cmd/process-watcher
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags '$(LDFLAGS)' -o $(DIST)/process-watcher-linux-arm64 ./cmd/process-watcher

test:
	go test ./...

vet:
	go vet ./...

# Toolchain image for the eBPF objects (pinned base image and Debian snapshot).
ebpf-image:
	docker build -t $(EBPF_IMAGE) build/ebpf

# Regenerates internal/collector/ebpf/pw_bpfel.{go,o} inside the toolchain
# container. Only needed after changing the C sources.
generate: ebpf-image
	docker run --rm -v "$(CURDIR)":/src -w /src \
		-v process-watcher-gomod:/go/pkg/mod -v process-watcher-gocache:/root/.cache/go-build \
		$(EBPF_IMAGE) go generate ./internal/collector/ebpf/...

# Collector and end-to-end tests against the real kernel of the Docker VM: a
# privileged container in the initial PID namespace (--pid=host). Needs a Linux
# userland with coreutils, setpriv and mount (the golang image has them).
test-docker:
	mkdir -p $(DIST)/e2e
	GOOS=linux GOARCH=$(DOCKER_ARCH) CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o $(DIST)/e2e/process-watcher ./cmd/process-watcher
	GOOS=linux GOARCH=$(DOCKER_ARCH) CGO_ENABLED=0 go test -c -o $(DIST)/e2e/collector.test ./internal/collector/ebpf
	GOOS=linux GOARCH=$(DOCKER_ARCH) CGO_ENABLED=0 go test -c -o $(DIST)/e2e/procfs.test ./internal/procfs
	GOOS=linux GOARCH=$(DOCKER_ARCH) CGO_ENABLED=0 go test -c -o $(DIST)/e2e/response.test ./internal/response
	GOOS=linux GOARCH=$(DOCKER_ARCH) CGO_ENABLED=0 go test -c -o $(DIST)/e2e/e2e.test ./tests/integration
	docker run --rm --privileged --pid=host -v "$(CURDIR)/$(DIST)/e2e":/work -w /work \
		-e PW_AGENT_BIN=/work/process-watcher $(GO_IMAGE) \
		sh -c './procfs.test -test.v && ./response.test -test.v && ./collector.test -test.v -test.timeout 600s && ./e2e.test -test.v -test.timeout 1800s'

# Collector tests, including the verifier complexity report, in a real kernel of
# another version and architecture under QEMU (tests/vm/README.md). The CPU is
# emulated, the kernel is the distribution's own.
ARCH   ?= $(DOCKER_ARCH)
KERNEL ?= ubuntu-5.15
test-vm:
	mkdir -p $(DIST)/vm
	GOOS=linux GOARCH=$(ARCH) CGO_ENABLED=0 go test -c -o $(DIST)/vm/collector-$(ARCH).test ./internal/collector/ebpf
	tests/vm/run.sh $(ARCH) $(KERNEL) $(DIST)/vm/collector-$(ARCH).test -test.v -test.timeout 3300s

# The same for every kernel of tests/vm/kernels.txt on both architectures.
test-vm-matrix:
	for arch in arm64 amd64; do \
		for kernel in $$(tests/vm/run.sh --list | awk 'NR>1 {print $$1}' | sort -u); do \
			$(MAKE) --no-print-directory test-vm ARCH=$$arch KERNEL=$$kernel || exit 1; \
		done; \
	done

# The agent end-to-end tests (tests/integration) in a QEMU guest: the agent
# binary is staged next to the test binary. TESTS selects tests (go test -run);
# the emulated CPU makes timing and load tests meaningless, see tests/vm/README.md.
TESTS ?= .
# PW_E2E_TIMEOUT_SCALE stretches the waiting times of the tests that honour it.
SCALE ?= 10
test-vm-e2e:
	mkdir -p $(DIST)/vm
	GOOS=linux GOARCH=$(ARCH) CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o $(DIST)/vm/process-watcher-$(ARCH) ./cmd/process-watcher
	GOOS=linux GOARCH=$(ARCH) CGO_ENABLED=0 go test -c -o $(DIST)/vm/e2e-$(ARCH).test ./tests/integration
	PW_VM_AGENT=$(DIST)/vm/process-watcher-$(ARCH) PW_VM_ENV='PW_AGENT_BIN=/pwtest/process-watcher PW_E2E_TIMEOUT_SCALE=$(SCALE)' PW_VM_TIMEOUT=7200 \
		tests/vm/run.sh $(ARCH) $(KERNEL) $(DIST)/vm/e2e-$(ARCH).test -test.v -test.run '$(TESTS)' -test.timeout 7000s

# The race detector over the Go pipeline on Linux (cgo and a C compiler are in the golang image).
test-race-docker:
	docker run --rm -v "$(CURDIR)":/src -w /src -v process-watcher-gomod:/go/pkg/mod -v process-watcher-gocache:/root/.cache/go-build $(GO_IMAGE) \
		go test -race -count=1 ./cmd/... ./internal/app ./internal/clock ./internal/config ./internal/event ./internal/filter \
		./internal/killrule ./internal/output ./internal/procfs ./internal/proctree ./internal/response ./internal/schemacheck \
		./internal/collector ./internal/collector/replay

# The systemd unit (packaging/systemd/process-watcher.service) under a REAL
# systemd 249 as PID 1 of a QEMU guest: install.sh, start, observation, kill
# feature, stop, failure behaviour, every hardening directive (tests/vm/README.md,
# "systemd mode"). ARCH and KERNEL as for test-vm; SCENARIOS="S3 S4" runs a subset.
.PHONY: test-vm-systemd
SCENARIOS ?=
test-vm-systemd:
	mkdir -p $(DIST)/vm-systemd
	GOOS=linux GOARCH=$(ARCH) CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o $(DIST)/vm-systemd/process-watcher-$(ARCH) ./cmd/process-watcher
	tests/vm/run-systemd.sh $(ARCH) $(KERNEL) $(DIST)/vm-systemd/process-watcher-$(ARCH) $(SCENARIOS)

# CPU, memory, throughput and latency measurements (docs/measurements.md).
bench-docker:
	mkdir -p $(DIST)/e2e
	GOOS=linux GOARCH=$(DOCKER_ARCH) CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o $(DIST)/e2e/process-watcher ./cmd/process-watcher
	GOOS=linux GOARCH=$(DOCKER_ARCH) CGO_ENABLED=0 go test -c -o $(DIST)/e2e/e2e.test ./tests/integration
	docker run --rm --privileged --pid=host -v "$(CURDIR)/$(DIST)/e2e":/work -w /work \
		-e PW_AGENT_BIN=/work/process-watcher -e PW_E2E_PERF=1 -e PW_E2E_REPORT_DIR=/work/report $(GO_IMAGE) \
		./e2e.test -test.v -test.run 'MeasureResources|KillReactionLatency' -test.timeout 1800s

# The release archives (per architecture a static binary, the example configuration,
# the license, the PHP example configurations and the systemd unit with its install
# script, under a versioned and an unversioned name, plus SHA256SUMS) exactly as the
# release workflow builds them:
#   make release-archives VERSION=v0.1.1
# The same version, source and Go toolchain give byte-identical archives.
release-archives:
	@case "$(VERSION)" in v[0-9]*) ;; *) echo "set VERSION=vMAJOR.MINOR.PATCH, for example: make release-archives VERSION=v0.1.0"; exit 2 ;; esac
	go run ./tools/release -version $(VERSION) -out $(DIST)/release

clean:
	rm -rf $(DIST)
