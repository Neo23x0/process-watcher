#!/bin/bash
# PHP-FPM as a service: workers that already run, several pools, worker replacement and a graceful reload.
. /lab/lib.sh
prepare_fixture
sed -i 's/^;pm.max_requests.*/pm.max_requests = 2/' /etc/php/8.4/fpm/pool.d/www.conf
cat > /etc/php/8.4/fpm/pool.d/api.conf <<'P'
[api]
user = www-data
group = www-data
listen = /run/php/php8.4-fpm-api.sock
listen.owner = www-data
listen.group = www-data
pm = static
pm.max_children = 2
P
up_fpm
cat > /etc/nginx/sites-enabled/default <<'NG'
server {
  listen 8080 default_server;
  root /var/www/html;
  location ~ \.php$ { include snippets/fastcgi-php.conf; fastcgi_pass unix:/run/php/php8.4-fpm.sock; }
  location ~ ^/api/(.+\.php)$ { include fastcgi_params; fastcgi_param SCRIPT_FILENAME /var/www/html/$1; fastcgi_pass unix:/run/php/php8.4-fpm-api.sock; }
}
NG
nginx; wait_port 8080
M=$(cat /run/php/php8.4-fpm.pid)

info "the agent starts while the master and the workers of two pools already run"
start_agent --watch-image-contains php-fpm --capture-argv=true
check L1 "one root for both pools" "$(count '.event_type=="process.discovered" and .lineage.role=="root"')" 1
check L2 "its workers: 2 in pool www, 2 in pool api, all depth 1 below the one master" "$(jq -r 'select(.event_type=="process.discovered" and .lineage.role=="descendant" and .lineage.depth==1) | .process.argv[0]' "$EVENTS" | sort | uniq -c | tr -s ' ' | tr '\n' ',' | sed 's/,$//')" " 2 php-fpm: pool api, 2 php-fpm: pool www"
check L3 "the title replaced the arguments of the process; trailing padding is not reported" "$(first '.event_type=="process.discovered" and .lineage.role=="descendant"' '[(.process.argv|length), .process.argv_state, .process.argv_complete]|join(" ")')" "1 snapshot true"

info "pm.max_requests = 2: workers end and the master replaces them"
for _ in 1 2 3 4 5 6; do curl_php "$(url info)" > /dev/null; done
sleep 1
check L4 "workers ended (exit events at depth 1 for the pool www)" "$([ "$(count '.event_type=="process.exit" and .lineage.depth==1')" -ge 2 ] && echo yes || echo no)" yes
check L5 "the master forked replacements: new instances, inherited image, same root" "$([ "$(count ".event_type==\"process.fork\" and .lineage.depth==1 and .root.pid==$M and .process.image_state==\"inherited\"")" -ge 2 ] && echo yes || echo no)" yes
check L6 "no gap, no loss" "$(count '.event_type=="agent.gap"')" 0

info "graceful reload: kill -USR2 <master>"
kill -USR2 "$M"; sleep 2.5
curl_php "$(url shell)" > /dev/null; sleep 1
NEW=$(cat /run/php/php8.4-fpm.pid)
check L7 "the pid file names a new master after the reload" "$([ "$NEW" != "$M" ] && echo yes || echo no)" yes
check L8 "the old master executed itself again (exec of the root, exec-time arguments)" "$(first ".event_type==\"process.exec\" and .process.pid==$M" '[.lineage.role,.details.exec_index,.process.argv_complete,(.process.argv|join(" "))]|join(" | ")')" "root | 1 | true | php-fpm8.4 --fpm-config /etc/php/8.4/fpm/php-fpm.conf"
check L9 "the new master is a depth 1 descendant of the old root" "$(first ".event_type==\"process.fork\" and .process.pid==$NEW" '[.lineage.role,.lineage.depth,.root.pid==('"$M"'),.parent.pid==('"$M"')]|join(" ")')" "descendant 1 true true"
check L10 "the old master ended" "$(count ".event_type==\"process.exit\" and .process.pid==$M")" 1
check L11 "a request after the reload is attributed to the ORIGINAL root" "$(first '.event_type=="process.exec" and .process.image=="dash" and .process.argv[3]=="uname -s"' "[.root.pid==$M, .lineage.depth]|join(\" \")")" "true 3"
stop_agent > /dev/null
check L12 "every event is valid JSON" "$(jq -c . "$EVENTS" | wc -l | tr -d ' ')" "$(wc -l < "$EVENTS" | tr -d ' ')"
finish
