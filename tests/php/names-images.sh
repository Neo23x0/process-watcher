#!/bin/bash
# Which executable names do PHP services have on other distributions and images? Starts the service in a
# privileged container that shares the PID namespace of the Docker VM, then lets the agent discover it and
# prints what the kernel reports (image, path) next to comm and the process title.
#
#   tests/php/names-images.sh                  all images
#   tests/php/names-images.sh php:8.4-fpm      a selection
#
# Needs network access (images and packages). Run one at a time, like the other lab scenarios.
set -u
cd "$(dirname "$0")/../.." || exit 1
ARCH=$(docker info --format '{{.Architecture}}' | sed 's/aarch64/arm64/;s/x86_64/amd64/')
GOOS=linux GOARCH="$ARCH" CGO_ENABLED=0 go build -trimpath -buildvcs=false -o dist/php/process-watcher ./cmd/process-watcher || exit 1

IMAGES=${*:-php:8.4-fpm php:8.4-fpm-alpine php:8.4-apache php:8.4-cli ubuntu:24.04 debian:bookworm rockylinux:9}

# the script run inside the container: $1 = family (official, alpine, apt, dnf)
read -r -d '' INNER <<'SCRIPT'
FAMILY=$1
case $FAMILY in
apt)
	export DEBIAN_FRONTEND=noninteractive
	printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d; chmod +x /usr/sbin/policy-rc.d
	apt-get update -qq > /dev/null && apt-get install -y -qq --no-install-recommends php-fpm php-cli php-cgi apache2 libapache2-mod-php procps jq > /dev/null 2>&1
	mkdir -p /run/php; PHPV=$(ls /usr/sbin | grep -o 'php-fpm[0-9.]*' | head -n 1)
	$PHPV --fpm-config /etc/php/*/fpm/php-fpm.conf; echo "ServerName localhost" > /etc/apache2/conf-available/servername.conf; a2enconf -q servername > /dev/null; apache2ctl start > /dev/null 2>&1
	setsid php-cgi -b 127.0.0.1:9100 > /dev/null 2>&1 &
	setsid php -r 'sleep(30);' > /dev/null 2>&1 &
	;;
dnf)
	dnf install -y -q php-fpm php-cli php-cgi httpd procps-ng jq > /dev/null 2>&1
	mkdir -p /run/php-fpm /run/httpd; php-fpm -D 2> /dev/null; echo "ServerName localhost" > /etc/httpd/conf.d/servername.conf; httpd -k start > /dev/null 2>&1
	setsid php-cgi -b 127.0.0.1:9100 > /dev/null 2>&1 &
	setsid php -r 'sleep(30);' > /dev/null 2>&1 &
	;;
official)
	command -v apt-get > /dev/null && apt-get update -qq > /dev/null 2>&1 && apt-get install -y -qq procps jq > /dev/null 2>&1
	command -v apk > /dev/null && apk add -q procps jq > /dev/null 2>&1
	if [ -x /usr/local/sbin/php-fpm ]; then php-fpm -D 2> /dev/null; fi
	if command -v apache2-foreground > /dev/null; then (apache2-foreground > /dev/null 2>&1 &); fi
	setsid php-cgi -b 127.0.0.1:9100 > /dev/null 2>&1 &
	setsid php -r 'sleep(30);' > /dev/null 2>&1 &
	;;
esac
sleep 3
echo "--- processes (pid exe | comm | title)"
for p in $(ps -eo pid,args | grep -E 'php|apache2|httpd' | grep -v -E 'grep|ps -eo|process-watcher|apt|dnf' | awk '{print $1}'); do
	[ -e /proc/$p/exe ] && printf '%s %s | %s | %s\n' "$p" "$(readlink /proc/$p/exe)" "$(cat /proc/$p/comm)" "$(tr '\0' ' ' < /proc/$p/cmdline | cut -c1-48)"
done | sort -k2 -u | head -20
echo "--- what the agent reports (root processes: image | image_path), watching php, apache2, httpd"
/dist/process-watcher --watch-image-contains php --watch-image-contains apache2 --watch-image-contains httpd --log-file /tmp/ev.jsonl 2> /dev/null &
A=$!; sleep 2; kill -TERM $A; wait $A 2> /dev/null
jq -r 'select(.event_type=="process.discovered" and .lineage.role=="root") | "\(.process.image) | \(.process.image_path)"' /tmp/ev.jsonl | sort | uniq -c | tr -s ' '
SCRIPT

for img in $IMAGES; do
	case $img in
	php:*-alpine) fam=official ;;
	php:*) fam=official ;;
	ubuntu:* | debian:*) fam=apt ;;
	rockylinux:* | almalinux:*) fam=dnf ;;
	*) fam=official ;;
	esac
	echo "=================== $img"
	docker pull -q "$img" > /dev/null 2>&1 || { echo "cannot pull $img"; continue; }
	docker rm -f pw-php-names > /dev/null 2>&1
	docker run --rm --name pw-php-names --privileged --pid=host -v "$PWD/dist/php":/dist:ro --entrypoint sh "$img" -c "$INNER" _ "$fam" 2>&1 | grep -v '^$' | head -60
	docker rm -f pw-php-names > /dev/null 2>&1
done
