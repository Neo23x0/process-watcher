#!/bin/bash
# Shared helpers of the PHP lab scenarios (run inside the lab container, which is privileged and shares
# the PID namespace of the host: the agent must see host PIDs).
set -u
AGENT=${AGENT:-/dist/process-watcher}
OUT=${OUT:-/out}
EVENTS=$OUT/events.jsonl
mkdir -p "$OUT"

# --- results ---------------------------------------------------------------------------------------------
NPASS=0
NFAIL=0
say() { echo "PW-PHP: $*"; }
pass() { NPASS=$((NPASS + 1)); say "PASS $*"; }
fail() { NFAIL=$((NFAIL + 1)); say "FAIL $*"; }
info() { say "INFO $*"; }
# check ID "what" got want
check() { if [ "$3" = "$4" ]; then pass "$1 $2: $3"; else fail "$1 $2: got '$3', want '$4'"; fi; }
# check_true ID "what" command...
check_true() { local id=$1 what=$2; shift 2; if "$@" > /dev/null 2>&1; then pass "$id $what"; else fail "$id $what"; fi; }
finish() { say "TOTAL: $NPASS passed, $NFAIL failed"; exit "$NFAIL"; }

# --- the event log ---------------------------------------------------------------------------------------
# count <jq condition on one event>: number of matching events
count() { jq -c "select($1)" "$EVENTS" 2> /dev/null | wc -l | tr -d ' '; }
# first <jq condition> <jq expression>: expression of the first matching event
first() { jq -r "select($1) | $2" "$EVENTS" 2> /dev/null | head -n 1; }
# exec_of <image>: the exec events of that image
exec_of() { echo "(.event_type==\"process.exec\" and .process.image==\"$1\")"; }

# start_agent <flags...>: starts the agent in the background and waits for agent.ready
start_agent() {
	rm -f "$EVENTS" "$EVENTS.lock"
	"$AGENT" --log-file "$EVENTS" "$@" 2> "$OUT/agent.stderr" &
	export AGENT_PID=$!
	for _ in $(seq 1 100); do
		grep -q '"event_type":"agent.ready"' "$EVENTS" 2> /dev/null && return 0
		sleep 0.1
	done
	echo "agent did not become ready"; cat "$OUT/agent.stderr"; return 1
}

stop_agent() {
	kill -TERM "$AGENT_PID" 2> /dev/null
	wait "$AGENT_PID" 2> /dev/null
	echo "agent exit status: $?"
}

# rows: the process events of the log, one compact line each
rows() {
	jq -r 'select(.event_type|test("^process\\.")) |
	  [.sequence, .event_type, (.lineage.role // "-"), ("d=" + ((.lineage.depth // "-")|tostring)),
	   ("pid=" + ((.process.pid // "-")|tostring)), ("ppid=" + ((.parent.pid // "-")|tostring)),
	   (.process.image // "-"), (.process.image_path // "-"),
	   (if .process.argv then (.process.argv|tojson) else "-" end),
	   ((.details.exec_index // "") | tostring)] | join(" ")' "$EVENTS" 2> /dev/null
}

# curl_php <url>: one request, body to stdout, short timeout
curl_php() { curl -s --max-time 10 "$1"; }

wait_port() { # wait_port <port>
	for _ in $(seq 1 100); do
		(exec 3<> /dev/tcp/127.0.0.1/"$1") 2> /dev/null && return 0
		sleep 0.1
	done
	return 1
}

# ---- deployments ---------------------------------------------------------------------------------------

prepare_fixture() {
	install -m 0644 /lab/fixture/probe.php /var/www/html/probe.php
	install -m 0644 /lab/fixture/worker.php /var/www/html/worker.php
	cp /bin/sleep /usr/local/bin/pwlab-helper
	mkdir -p /run/php
}

# up_fpm: the Debian php-fpm8.4 service (daemonizes), listening on /run/php/php8.4-fpm.sock
up_fpm() {
	php-fpm8.4 --fpm-config /etc/php/8.4/fpm/php-fpm.conf
	for _ in $(seq 1 50); do [ -S /run/php/php8.4-fpm.sock ] && return 0; sleep 0.1; done
	echo "php-fpm did not come up"; return 1
}

# up_nginx_fpm: nginx on :8080 forwarding .php to the FPM socket
up_nginx_fpm() {
	cat > /etc/nginx/sites-enabled/default <<'NG'
server {
  listen 8080 default_server;
  root /var/www/html;
  location ~ \.php$ {
    include snippets/fastcgi-php.conf;
    fastcgi_pass unix:/run/php/php8.4-fpm.sock;
  }
}
NG
	nginx
	wait_port 8080
}

# exec rows: argument lengths are what matters for the capture limits
execsum() {
	jq -r 'select(.event_type=="process.exec") | [(.process.image // "-"), ("argc=" + ((.process.argv // [])|length|tostring)),
	  ("lens=" + ([(.process.argv // [])[]|length]|tojson)), ("state=" + (.process.argv_state // "-")),
	  ("trunc=" + (.data_quality.truncated_fields|tojson))] | join(" ")' "$EVENTS"
}

url() { printf 'http://127.0.0.1:8080/probe.php?m=%s' "$1"; }

# up_apache_modphp: Apache prefork with the embedded PHP module on :8081
up_apache_modphp() {
	a2dismod -q mpm_event 2> /dev/null; a2enmod -q mpm_prefork php8.4 > /dev/null
	echo "ServerName localhost" > /etc/apache2/conf-available/servername.conf; a2enconf -q servername > /dev/null
	sed -i 's/^Listen 80$/Listen 8081/' /etc/apache2/ports.conf
	sed -i 's/<VirtualHost \*:80>/<VirtualHost *:8081>/' /etc/apache2/sites-enabled/000-default.conf
	apache2ctl start > /dev/null 2>&1
	wait_port 8081
}

# up_apache_fpm: Apache event MPM forwarding .php to the separate FPM service (proxy_fcgi) on :8081
up_apache_fpm() {
	a2dismod -q php8.4 mpm_prefork 2> /dev/null; a2enmod -q mpm_event proxy_fcgi setenvif > /dev/null
	a2enconf -q php8.4-fpm > /dev/null
	echo "ServerName localhost" > /etc/apache2/conf-available/servername.conf; a2enconf -q servername > /dev/null
	sed -i 's/^Listen 80$/Listen 8081/' /etc/apache2/ports.conf
	sed -i 's/<VirtualHost \*:80>/<VirtualHost *:8081>/' /etc/apache2/sites-enabled/000-default.conf
	apache2ctl start > /dev/null 2>&1
	wait_port 8081
}

url81() { printf 'http://127.0.0.1:8081/probe.php?m=%s' "$1"; }
ps_forest() { ps -eo pid,ppid,user,comm,args --forest | grep -E "$1" | grep -v grep | cut -c1-150; }
exes() { local p; for p in $(pgrep -f "$1"); do printf '%s %s -> %s\n' "$p" "$(cat /proc/$p/comm)" "$(readlink /proc/$p/exe)"; done | sort -k3 -u; }
