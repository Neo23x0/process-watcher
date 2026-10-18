#!/bin/bash
# Runs the PHP lab scenarios (tests/php/README.md) against the real nginx, Apache and PHP of the lab image.
#
#   tests/php/run.sh                      all scenarios
#   tests/php/run.sh argv killrules:narrow    a selection (name or name:argument)
#
# Needs Docker with a Linux kernel that the agent supports (BTF, 5.15 or newer). The containers are privileged
# and share the PID namespace of the Docker VM: run one lab at a time and nothing else that matches the watch
# patterns (php-fpm, apache2, nginx, php) on that VM.
set -u
cd "$(dirname "$0")/../.." || exit 1
IMAGE=${PW_PHP_IMAGE:-pw-php-lab:trixie-2}
CONTAINER=pw-php-lab-run
ARCH=$(docker info --format '{{.Architecture}}' | sed 's/aarch64/arm64/;s/x86_64/amd64/')

ALL="deployments:nginx-fpm deployments:apache-fpm deployments:apache-modphp deployments:nginx-phpcgi deployments:apache-fcgid deployments:cli argv fpm-lifecycle killrules:narrow killrules:guard killrules:broad killrules:dry killrules:root blindspot latency"
SELECT=${*:-$ALL}

mkdir -p dist/php/out
echo "building the agent for linux/$ARCH"
GOOS=linux GOARCH="$ARCH" CGO_ENABLED=0 go build -trimpath -buildvcs=false -o dist/php/process-watcher ./cmd/process-watcher || exit 1
if ! docker image inspect "$IMAGE" > /dev/null 2>&1; then
	echo "building the lab image $IMAGE"
	docker build -q -t "$IMAGE" -f tests/php/Dockerfile.debian tests/php || exit 1
fi

failed=0
for sel in $SELECT; do
	name=${sel%%:*}
	arg=
	[ "$sel" != "$name" ] && arg=${sel#*:}
	docker rm -f "$CONTAINER" > /dev/null 2>&1
	echo "=== $sel"
	log=dist/php/out/$name${arg:+-$arg}.log
	docker run --rm --name "$CONTAINER" --privileged --pid=host \
		-v "$PWD/tests/php/lab":/lab:ro -v "$PWD/dist/php":/dist:ro -v "$PWD/dist/php/out":/out \
		"$IMAGE" /lab/scenarios/"$name".sh ${arg:+"$arg"} 2>&1 | tee "$log" | grep -E '^PW-PHP: (PASS|FAIL|INFO|TOTAL)' | sed 's/^PW-PHP: //' | cut -c1-240
	n=$(grep -c '^PW-PHP: FAIL' "$log")
	failed=$((failed + n))
	docker rm -f "$CONTAINER" > /dev/null 2>&1
done
echo
echo "PHP lab: $failed failed check(s)"
exit "$failed"
