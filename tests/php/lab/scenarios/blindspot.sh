#!/bin/bash
# The visibility boundary: PHP code that opens a network connection itself and starts no process.
. /lab/lib.sh
prepare_fixture; up_fpm; up_nginx_fpm
nc -l -p 9999 -s 127.0.0.1 > /tmp/received.txt 2> /dev/null &
LISTENER=$!
sleep 0.3
start_agent --watch-image-contains php-fpm --capture-argv=true
BEFORE=$(count '.event_type|test("^process\\.")')
info "a worker connects to 127.0.0.1:9999 and holds the connection for 3 s"
curl_php "$(url sockhold)" > /dev/null &
CURL=$!
sleep 1.2
W=$(pgrep -f 'php-fpm: pool' | while read -r p; do ss -tnp 2> /dev/null | grep -q "pid=$p," && echo "$p"; done | head -n 1)
CONN=$(ss -tnp 2> /dev/null | grep ':9999' | grep -o 'users:.*' | grep php-fpm | head -n 1 | cut -c1-60)
check_true B1 "the operating system shows the connection, owned by an FPM worker" test -n "$W"
info "ss: $CONN"
wait "$CURL"
sleep 1
AFTER=$(count '.event_type|test("^process\\.")')
check B2 "what the listener received" "$(tr -d '\n' < /tmp/received.txt)" "pw-sock-hello"
check B3 "the agent logged no process event for it" "$((AFTER - BEFORE))" 0
check B4 "no exec, no fork, nothing below the worker" "$(count '.event_type=="process.exec" or (.event_type=="process.fork" and .lineage.depth>=2)')" 0
info "the control: the same worker starts a shell and the agent sees it at once"
curl_php "$(url shell)" > /dev/null; sleep 1
check B5 "the shell is observed" "$(count '.event_type=="process.exec" and .process.image=="dash"')" 1
stop_agent > /dev/null
kill "$LISTENER" 2> /dev/null
finish
