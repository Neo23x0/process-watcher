#!/bin/bash
# The one-line installer of the PHP kit (emerging-threats/php-rce-october-26/install.sh) against a real kernel,
# real PHP processes and a local copy of a release. The script runs as the documented one-liner runs it: piped
# into sh. The release is built from the working tree by run.sh (version v9.9.9) and served by a local mirror
# (PW_BASE_URL), so nothing is downloaded from the internet. PHP only runs the harmless lab fixture.
#
# usage: installer.sh fpm | modphp | cgi | negative
. /lab/lib.sh
MODE=${1:?mode}
KIT=/emerging-threats/php-rce-october-26
INSTALL=/opt/process-watcher
EVENTS=/var/log/process-watcher/events.jsonl
export PW_VERSION=v9.9.9 PW_INSTALL_DIR=$INSTALL
prepare_fixture

serve() { # serve <dir> <port>: a release mirror
	(cd "$1" && python3 -m http.server "$2" --bind 127.0.0.1 > "/out/mirror-$2.log" 2>&1 &)
	wait_port "$2"
}
serve /dist/release 8099
MIRROR=http://127.0.0.1:8099

# piped [args]: the script as the one-liner runs it, output in $OUTPUT, exit status in $RC
piped() {
	OUTPUT=$(cat "$KIT/install.sh" | PW_BASE_URL=${MIRROR_OVERRIDE:-$MIRROR} sh -s -- "$@" 2>&1)
	RC=$?
	printf '%s\n' "$OUTPUT" > /out/installer.last.txt
}
has() { grep -q -- "$1" /out/installer.last.txt; }
agents() { pgrep -fc "^$INSTALL/process-watcher_" || true; }
fresh_log() { rm -rf /var/log/process-watcher; }
yes_if() { if "$@"; then echo yes; else echo no; fi; }
atleast1() { [ "$(count "$1")" -ge 1 ] && echo yes || echo no; }

case $MODE in
fpm)
	up_fpm; up_nginx_fpm
	info "the plan: detects PHP-FPM, says nothing was changed, changes nothing"
	cat "$KIT/install.sh" | sh -s -- --plan > /out/plan.txt 2>&1
	check I1 "the plan says that nothing was changed" "$(grep -c 'Plan only: nothing was changed' /out/plan.txt)" 1
	check I2 "the plan watches php-fpm" "$(grep '^  watching' /out/plan.txt | sed 's/^  watching *//')" php-fpm
	check_true I3 "the plan installed nothing" test ! -e "$INSTALL"

	info "the one-liner"
	piped
	check I4 "it succeeds" "$RC" 0
	check I5 "it checked the download against SHA256SUMS" "$(yes_if has 'checksum ok')" yes
	check I6 "it ran the agent's doctor" "$(yes_if has 'doctor: all required checks passed')" yes
	check I7 "it reports that the agent runs" "$(yes_if has 'process-watcher is running')" yes
	check I8 "current points into the install directory" "$(readlink "$INSTALL/current" | sed 's#/process-watcher_.*##')" "$INSTALL"
	check I9 "one agent runs, from there" "$(agents)" 1
	check I10 "observe only: the kill feature is off" "$(first '.event_type=="agent.started"' '.details.kill.enabled')" false
	check I11 "the agent watches what was detected" "$(yes_if grep -q 'watch=\[php-fpm\]' /var/log/process-watcher/agent.log)" yes
	check I12 "the log is root-only" "$(stat -c '%a' /var/log/process-watcher) $(stat -c '%a' "$EVENTS")" "700 600"
	curl_php "$(url shell)" > /dev/null; curl_php "$(url python)" > /dev/null; sleep 1
	check I13 "a shell started by PHP is in the log, below the FPM master" "$(atleast1 '.event_type=="process.exec" and .process.image=="dash" and .root.image=="php-fpm8.4"')" yes
	check I14 "...and Python below that shell, with its command line" "$(atleast1 '.event_type=="process.exec" and (.process.image|test("^python3")) and (.process.argv|join(" ")|test("print"))')" yes
	check I15 "observe only: no decision of the response rules" "$(count '.event_type|test("^response\\.")')" 0

	info "a second run while the agent runs, and --stop"
	PIDS=$(pgrep -f "^$INSTALL/process-watcher_" | tr '\n' ' ')
	piped
	check I16 "a second run says it is already running and exits 0" "$RC $(yes_if has 'already running')" "0 yes"
	check I17 "...and starts no second agent" "$(pgrep -f "^$INSTALL/process-watcher_" | tr '\n' ' ')" "$PIDS"
	piped --stop
	check I18 "--stop succeeds" "$RC $(yes_if has 'stopped (pid')" "0 yes"
	check I19 "no agent is left" "$(agents)" 0
	check I20 "the agent ended in order" "$(count '.event_type=="agent.stopped"')" 1
	piped --stop
	check I21 "--stop twice is harmless" "$RC $(yes_if has 'is not running')" "0 yes"

	info "a configuration that really kills needs --allow-kill"
	fresh_log
	piped --config php-fpm-kill
	check I22 "it is refused without --allow-kill" "$RC $(yes_if has 'really sends SIGKILL')" "1 yes"
	check I23 "...and nothing runs" "$(agents)" 0

	info "the dry run of the release: decisions, no signal"
	piped --config php-fpm-dry-run
	check I24 "it starts" "$RC" 0
	curl_php "$(url shell)" > /dev/null; sleep 1
	check I25 "the decision is logged as a dry run" "$(atleast1 '.event_type=="response.kill_result" and .details.outcome=="dry_run" and .process.image=="dash"')" yes
	check I26 "...and nothing was signalled" "$(count '.event_type=="response.kill_result" and .details.outcome=="signal_sent"')" 0
	piped --stop

	info "real termination, with --allow-kill (a shell that only sleeps)"
	fresh_log
	piped --config php-fpm-kill --allow-kill
	check I27 "it starts and warns" "$RC $(yes_if has 'sends SIGKILL to matching processes')" "0 yes"
	curl_php "$(url shellbg)&ms=5000" > /dev/null; sleep 2
	check I28 "the shell ended with signal 9" "$(atleast1 '.event_type=="process.exit" and .details.signal==9 and .process.image=="dash"')" yes
	piped --stop

	info "--foreground: the agent runs in the foreground until it is stopped"
	fresh_log
	(cat "$KIT/install.sh" | PW_BASE_URL=$MIRROR timeout 8 sh -s -- --foreground > /out/foreground.txt 2>&1; echo "foreground exit status: $?" >> /out/foreground.txt) &
	for _ in $(seq 1 60); do grep -q '"event_type":"agent.ready"' "$EVENTS" 2> /dev/null && break; sleep 0.2; done
	check I29 "it is ready in the foreground" "$(count '.event_type=="agent.ready"')" 1
	wait
	check I30 "it ended in order when it was stopped" "$(count '.event_type=="agent.stopped"')" 1
	;;

modphp)
	up_apache_modphp
	cat "$KIT/install.sh" | sh -s -- --plan > /out/plan.txt 2>&1
	check M1 "the plan finds Apache with mod_php" "$(grep '^  PHP found' /out/plan.txt | sed 's/^  PHP found *//; s/ (pid.*//')" "apache2 with mod_php"
	check M2 "...and watches apache2 with the mod_php configuration" "$(grep '^  watching' /out/plan.txt | sed 's/^  watching *//') $(grep '^  configuration' /out/plan.txt | sed 's/^  configuration *//; s/ (.*//')" "apache2 php/apache-mod-php.yaml"
	piped
	check M3 "the one-liner succeeds" "$RC" 0
	curl_php "$(url81 shell)" > /dev/null; sleep 1
	check M4 "a shell started by an Apache worker is in the log, below the Apache master" "$(atleast1 '.event_type=="process.exec" and .process.image=="dash" and .root.image=="apache2"')" yes
	piped --stop
	check M5 "--stop ends it" "$(agents)" 0
	;;

cgi)
	setsid php-cgi8.4 -b 127.0.0.1:9100 > /dev/null 2>&1 &
	setsid php8.4 -r 'sleep(300);' > /dev/null 2>&1 &
	sleep 1
	cat "$KIT/install.sh" | sh -s -- --plan > /out/plan.txt 2>&1
	check C1 "the plan finds php-cgi and the PHP CLI and watches both" "$(grep '^  watching' /out/plan.txt | sed 's/^  watching *//')" "php-cgi php8."
	check C2 "...starting from the php-cgi configuration" "$(grep '^  configuration' /out/plan.txt | sed 's/^  configuration *//; s/ (.*//')" php/php-cgi.yaml
	piped
	check C3 "the one-liner succeeds" "$RC" 0
	check C4 "both processes that already ran are roots" "$(count '.event_type=="process.discovered" and .lineage.role=="root"')" 2
	php8.4 -r 'echo shell_exec("uname -s");' > /dev/null
	sleep 1
	check C5 "a shell started by a new PHP CLI is in the log" "$(atleast1 '.event_type=="process.exec" and .process.image=="dash" and .root.image=="php8.4"')" yes
	piped --stop
	pkill -f 'php-cgi8.4 -b' || true; pkill -f "php8.4 -r sleep" || true
	;;

negative)
	info "no PHP at all"
	piped
	check N1 "the real run stops and says why" "$RC $(yes_if has 'no PHP process found')" "1 yes"
	check N2 "...and installed nothing" "$(yes_if test -e "$INSTALL")" no
	info "not root"
	OUTPUT=$(cat "$KIT/install.sh" | su -s /bin/sh nobody -c "PW_BASE_URL=$MIRROR PW_VERSION=v9.9.9 sh -s --" 2>&1); RC=$?
	printf '%s\n' "$OUTPUT" > /out/installer.last.txt
	check N3 "it refuses to run without root" "$RC $(yes_if has 'run as root')" "1 yes"
	info "with PHP running, but a download that cannot be trusted"
	up_fpm
	mkdir -p /tmp/bad && cp -r /dist/release/. /tmp/bad/
	ARC=$(ls /tmp/bad/v9.9.9/*.tar.gz)
	printf 'tampered' | dd of="$ARC" bs=1 seek=100 conv=notrunc 2> /dev/null
	serve /tmp/bad 8098
	MIRROR_OVERRIDE=http://127.0.0.1:8098 piped
	check N4 "a damaged archive is refused by its checksum" "$RC $(yes_if has 'checksum mismatch')" "1 yes"
	check N5 "...and nothing was installed or started" "$(yes_if test -e "$INSTALL") $(agents)" "no 0"
	mkdir -p /tmp/nosum && cp -r /dist/release/. /tmp/nosum/ && : > /tmp/nosum/v9.9.9/SHA256SUMS
	serve /tmp/nosum 8097
	MIRROR_OVERRIDE=http://127.0.0.1:8097 piped
	check N6 "an archive that SHA256SUMS does not list is refused" "$RC $(yes_if has 'not listed exactly once')" "1 yes"
	PW_VERSION=v0.0.1 piped
	check N7 "a release that does not exist is a clear download error" "$RC $(yes_if has 'download failed')" "1 yes"
	ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
	D=process-watcher_v9.9.9_linux_$ARCH
	mkdir -p "/tmp/nophp/v9.9.9/x/$D" && printf '#!/bin/sh\nexit 0\n' > "/tmp/nophp/v9.9.9/x/$D/process-watcher" && chmod 755 "/tmp/nophp/v9.9.9/x/$D/process-watcher"
	tar -czf "/tmp/nophp/v9.9.9/$D.tar.gz" -C "/tmp/nophp/v9.9.9/x" "$D"
	(cd /tmp/nophp/v9.9.9 && sha256sum "$D.tar.gz" > SHA256SUMS)
	serve /tmp/nophp 8096
	MIRROR_OVERRIDE=http://127.0.0.1:8096 piped
	check N8 "a release without the php/ configurations is refused" "$RC $(yes_if has 'has no php/ directory')" "1 yes"
	check N9 "...and no agent was started" "$(agents)" 0
	;;
esac
finish
