#!/bin/bash
# Response rules against a real PHP-FPM service. usage: killrules.sh broad | guard | narrow | dry | root
. /lab/lib.sh
prepare_fixture
MODE=${1:?mode}
http() { curl -s -o /dev/null -w '%{http_code}' --max-time 3 "$1"; }
runagent() { # runagent <config file>
	rm -f "$EVENTS" "$EVENTS.lock"
	"$AGENT" --config "$1" 2> "$OUT/agent.stderr" &
	export AGENT_PID=$!
	local i; for i in $(seq 1 100); do grep -q '"event_type":"agent.ready"' "$EVENTS" 2> /dev/null && break; sleep 0.1; done
}
config() { # config <kill block lines...> -> /tmp/k.yaml
	local watch=${WATCH:-php-fpm}
	{ echo "config_version: 1"; echo "watch:"; echo "  image_contains: [\"$watch\"]"; echo "capture:"; echo "  argv: true"; echo "kill:"; echo "  enabled: true"; printf '  %s\n' "$@"; echo "outputs:"; echo "  file:"; echo "    path: $EVENTS"; } > /tmp/k.yaml
}
NARROW='regex: ["^(dash|sh|bash|zsh|ksh|python[0-9.]*|perl|nc|ncat|socat)$", "^php[0-9.]*$"]'

case $MODE in
broad)
	up_fpm; up_nginx_fpm
	config 'dry_run: false' 'fields: [image]' 'strings: ["php"]'
	info "check-config on the broad rule"
	W=$("$AGENT" check-config --config /tmp/k.yaml 2>&1 | grep '^warning' | head -n 1)
	check_true K1 "check-config warns that the rule matches the watched program" grep -q 'kill.strings\[0\] "php" is contained in the watch pattern "php-fpm"' <<< "$W"
	M=$(cat /run/php/php8.4-fpm.pid)
	check K2 "before the agent: the service answers" "$(http "$(url info)")" 200
	runagent /tmp/k.yaml
	check K3 "agent.started carries the warning" "$(first '.event_type=="agent.started"' '.details.kill.warnings|length')" 1
	for i in 1 2 3 4 5 6; do http "$(url info)" > /tmp/codes.$i; sleep 0.5; done
	CODES=$(cat /tmp/codes.* | tr '\n' ' ')
	stop_agent > /dev/null
	KILLS=$(count '.event_type=="response.kill_result" and .details.outcome=="signal_sent" and .process.image=="php-fpm8.4"')
	info "signals sent to php-fpm8.4 in 3 s: $KILLS; HTTP status of six requests: $CODES"
	check K4 "workers were killed in large numbers (the master forks, the rule kills, repeatedly)" "$([ "$KILLS" -gt 100 ] && echo yes || echo no)" yes
	check_true K6 "at least one request failed" bash -c "echo '$CODES' | grep -q -E '502|000|503'"
	check K7 "the master, a root, was never a target" "$(count ".event_type==\"response.kill_result\" and .process.pid==$M")" 0
	check_true K8 "the master survived" kill -0 "$M"
	;;
guard)
	up_fpm; up_nginx_fpm
	config 'dry_run: false' 'fields: [image]' 'strings: ["php"]' 'spare_root_image: true'
	M=$(cat /run/php/php8.4-fpm.pid); WORKERS=$(pgrep -f 'php-fpm: pool' | sort | tr '\n' ' ')
	runagent /tmp/k.yaml
	check K10 "agent.started: guard on, no warning" "$(first '.event_type=="agent.started"' '[.details.kill.spare_root_image,(.details.kill.warnings|length)]|join(" ")')" "true 0"
	CODES=
	for i in 1 2 3 4 5 6; do CODES="$CODES $(http "$(url info)")"; sleep 0.5; done
	sleep 1; stop_agent > /dev/null
	check K11 "the service answers throughout" "$(echo $CODES | tr ' ' '\n' | sort -u | tr '\n' ' ')" "200 "
	check K12 "no signal was sent" "$(count '.event_type=="response.kill_result" and .details.outcome=="signal_sent"')" 0
	check K13 "the decisions are audited as spared" "$([ "$(count '.event_type=="response.kill_result" and .details.outcome=="skipped" and .details.reason=="root_image_spared"')" -ge 2 ] && echo yes || echo no)" yes
	check K14 "the same workers still run" "$(pgrep -f 'php-fpm: pool' | sort | tr '\n' ' ')" "$WORKERS"
	check K15 "agent.health counts the spared decisions" "$(jq -r 'select(.event_type=="agent.stopped") | .details.response.skipped.root_image_spared' "$EVENTS" | awk '{ print ($1 >= 2) ? "yes" : "no" }')" yes
	;;
narrow)
	up_fpm; up_nginx_fpm
	config 'dry_run: false' 'fields: [image]' "$NARROW"
	WORKERS=$(pgrep -f 'php-fpm: pool' | sort | tr '\n' ' ')
	runagent /tmp/k.yaml
	check K20 "no warning for a narrow rule" "$(first '.event_type=="agent.started"' '.details.kill.warnings|length')" 0
	curl_php "$(url shellbg)&ms=20000" > /dev/null; curl_php "$(url phpbg)&ms=20000" > /dev/null; curl_php "$(url direct)" > /dev/null
	sleep 2
	stop_agent > /dev/null
	SH=$(first '.event_type=="response.kill_result" and .process.image=="dash"' '.process.pid')
	PH=$(first '.event_type=="response.kill_result" and .process.image=="php8.4"' '.process.pid')
	check K21 "the shell that PHP started was sent SIGKILL" "$(first ".event_type==\"response.kill_result\" and .process.pid==$SH" '.details.outcome')" signal_sent
	check K22 "...and it ended with SIGKILL (the exit confirms what the signal result only promises)" "$(first ".event_type==\"process.exit\" and .process.pid==$SH" '.details.signal')" 9
	check K23 "the exit carries the action id of the decision" "$([ "$(first ".event_type==\"process.exit\" and .process.pid==$SH" '.details.response_action_id')" = "$(first ".event_type==\"response.kill_result\" and .process.pid==$SH" '.details.action_id')" ] && echo yes || echo no)" yes
	check K24 "the PHP CLI interpreter that PHP started was killed too" "$(first ".event_type==\"process.exit\" and .process.pid==$PH" '.details.signal')" 9
	check K25 "a direct launch of an ordinary program was left alone" "$(first '.event_type=="process.exit" and .process.image=="uname"' '.details.exit_code')" 0
	check K26 "no worker was a target" "$(count '.event_type=="response.kill_result" and .process.image=="php-fpm8.4"')" 0
	check K27 "the workers still run" "$(pgrep -f 'php-fpm: pool' | sort | tr '\n' ' ')" "$WORKERS"
	check K29 "the audit lists the ancestors above the shell: master and worker" "$(first ".event_type==\"response.kill_requested\" and .process.pid==$SH" '.details.chain | map(.image) | join(" ")')" "php-fpm8.4 php-fpm8.4"
	check K28 "the audit names rule, field and write order (requested before result)" "$(jq -r 'select(.event_type=="response.kill_requested" and .process.image=="dash") | [.details.rules[0].type, .details.rules[0].field] | join(" ")' "$EVENTS" | head -n 1)" "regex image"
	;;
dry)
	up_fpm; up_nginx_fpm
	config 'dry_run: true' 'fields: [image]' "$NARROW"
	runagent /tmp/k.yaml
	curl_php "$(url shellbg)&ms=3000" > /dev/null
	sleep 4.5
	stop_agent > /dev/null
	SH=$(first '.event_type=="response.kill_result" and .process.image=="dash"' '.process.pid')
	check K30 "the decision is audited as a dry run" "$(first ".event_type==\"response.kill_result\" and .process.pid==$SH" '[.details.outcome,.details.dry_run]|join(" ")')" "dry_run true"
	check K31 "the shell ended by itself, not by a signal" "$(first ".event_type==\"process.exit\" and .process.pid==$SH" '[.details.exit_code,(.details.signal // "none")]|join(" ")')" "0 none"
	check K32 "agent.health shows no real signal attempt" "$(jq -r 'select(.event_type=="agent.stopped") | .details.response.signal_attempts' "$EVENTS")" 0
	;;
root)
	up_fpm
	WATCH=php8.4 config 'dry_run: false' 'fields: [image]' 'strings: ["php"]'
	runagent /tmp/k.yaml
	setsid php8.4 -r 'sleep(6);' > /dev/null 2>&1 &
	sleep 2
	CLI=$(pgrep -o -f 'php8.4 -r')
	check_true K40 "a watched PHP CLI process (a root) is alive although the rule matches it" kill -0 "$CLI"
	check K41 "no kill decision exists for it" "$(count '.event_type|test("^response\\.")')" 0
	stop_agent > /dev/null
	;;
esac
finish
