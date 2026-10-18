#!/bin/bash
# How fast does the response act on a real PHP-FPM worker's children? Measured from the kernel's exec record.
. /lab/lib.sh
prepare_fixture; up_fpm; up_nginx_fpm
N=${N:-200}
config() {
	cat > /tmp/k.yaml <<Y
config_version: 1
watch:
  image_contains: ["php-fpm"]
capture:
  argv: true
kill:
  enabled: true
  fields: [image]
  regex: ["$1"]
outputs:
  file:
    path: $EVENTS
Y
}
runagent() { rm -f "$EVENTS" "$EVENTS.lock"; "$AGENT" --config /tmp/k.yaml 2> "$OUT/agent.stderr" & export AGENT_PID=$!; for _ in $(seq 1 100); do grep -q '"event_type":"agent.ready"' "$EVENTS" 2> /dev/null && break; sleep 0.1; done; }
stats() { # stats <jq path of the latency> : n mean p50 p95 p99 max in ms
	jq -s -r "[.[] | select(.event_type==\"response.kill_result\" and .details.outcome==\"signal_sent\" and .process.image==\"$1\") | (.details.$2|tonumber)/1e6] | sort | if length==0 then \"none\" else [length, ((add/length)*1000|round/1000), (.[(length*0.5|floor)]*1000|round/1000), (.[(length*0.95|floor)]*1000|round/1000), (.[(length*0.99|floor)]*1000|round/1000), (.[-1]*1000|round/1000)] | map(tostring) | join(\" \") end" "$EVENTS"
}

info "long-running helpers (pwlab-helper, a copy of sleep) started by a worker, $N requests 25 ms apart"
config '^pwlab-helper$'; runagent
for _ in $(seq 1 "$N"); do curl_php "$(url helper)&ms=60000" > /dev/null; sleep 0.025; done
sleep 1; stop_agent > /dev/null
info "decision (kill_requested written locally), n mean p50 p95 p99 max [ms]: $(stats pwlab-helper decision_latency_ns)"
info "signal attempt (pidfd_send_signal returned),  n mean p50 p95 p99 max [ms]: $(stats pwlab-helper attempt_latency_ns)"
SENT=$(count '.event_type=="response.kill_result" and .details.outcome=="signal_sent"')
KILLED=$(count '.event_type=="process.exit" and .process.image=="pwlab-helper" and .details.signal==9')
check T1 "every helper was reached" "$SENT" "$N"
check T2 "every signal is confirmed by an exit with SIGKILL" "$KILLED" "$N"
DUR=$(jq -s -r '[.[] | select(.event_type=="process.exit" and .process.image=="pwlab-helper" and .details.signal==9) | (.details.duration_ns|tonumber)/1e6] | sort | "median \(.[(length*0.5|floor)]|.*1000|round/1000) ms, max \(.[-1]|.*1000|round/1000) ms"' "$EVENTS")
info "life of a helper from its fork to its death: $DUR"
pkill -f pwlab-helper

info "short-lived shells (sh -c 'uname -s', about half a millisecond), $N requests 25 ms apart"
config '^dash$'; runagent
for _ in $(seq 1 "$N"); do curl_php "$(url shell)" > /dev/null; sleep 0.025; done
sleep 1; stop_agent > /dev/null
OUTC=$(jq -r 'select(.event_type=="response.kill_result" and .process.image=="dash") | .details.outcome' "$EVENTS" | sort | uniq -c | tr -s ' ' | tr '\n' ',')
info "outcomes of the kill decisions (an exec hit and an inherited-image fork hit per shell): $OUTC"
CONF=$(count '.event_type=="process.exit" and .process.image=="dash" and .details.signal==9')
ALL=$(count '.event_type=="process.exit" and .process.image=="dash"')
info "of $ALL shells, $CONF ended with SIGKILL and $((ALL - CONF)) ended by themselves"
finish
