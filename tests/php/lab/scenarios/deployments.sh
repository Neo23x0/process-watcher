#!/bin/bash
# Which executable names and process trees do the real PHP deployments have, and which watch target covers them?
# usage: deployments.sh nginx-fpm | apache-fpm | apache-modphp | nginx-phpcgi | apache-fcgid | cli
. /lab/lib.sh
prepare_fixture
D=${1:?deployment}

# the process list as the operator sees it, then the executable behind every process
show() {
	info "process tree:"; ps -eo pid,ppid,user,comm,args --forest | grep -E "$1" | grep -v -E 'grep|process-watcher' | sed 's/^/PW-PHP:   | /' | cut -c1-170
}
exe() { readlink "/proc/$1/exe"; }
title() { tr '\0' ' ' < "/proc/$1/cmdline" | cut -c1-60; }
pid_of() { pgrep -o -f "$1" ; }

case $D in
nginx-fpm)
	up_fpm; up_nginx_fpm
	show 'nginx|php-fpm'
	M=$(pid_of 'php-fpm: master')
	check D1.1 "the master's executable" "$(exe "$M")" /usr/sbin/php-fpm8.4
	check D1.2 "comm of the master (not the image, not the title)" "$(cat /proc/$M/comm)" php-fpm8.4
	check D1.3 "the displayed process title" "$(title "$M" | cut -c1-23)" "php-fpm: master process"
	W=$(pgrep -f 'php-fpm: pool www' | head -n 1)
	check D1.4 "a worker runs the same executable" "$(exe "$W")" /usr/sbin/php-fpm8.4

	info "agent watches php-fpm; the workers already exist when it starts"
	start_agent --watch-image-contains php-fpm --capture-argv=true
	check D1.5 "the master is discovered as root with the versioned image" "$(first ".event_type==\"process.discovered\" and .process.pid==$M" '[.lineage.role,.process.image,.process.image_path]|join(" ")')" "root php-fpm8.4 /usr/sbin/php-fpm8.4"
	check D1.6 "its workers are discovered as depth 1 descendants" "$(count ".event_type==\"process.discovered\" and .lineage.role==\"descendant\" and .lineage.depth==1 and .root.pid==$M")" 2
	curl_php "$(url shell)" > /dev/null; curl_php "$(url direct)" > /dev/null
	sleep 1
	stop_agent > /dev/null
	check D1.7 "the shell started by PHP is observed" "$(count '.event_type=="process.exec" and .process.image=="dash" and (.process.argv==["sh","-c","--","uname -s"])')" 1
	check D1.8 "its root is the FPM master" "$(first '.event_type=="process.exec" and .process.image=="dash"' ".root.pid")" "$M"
	check D1.9 "uname below the shell is at depth 3" "$(first '.event_type=="process.exec" and .process.image=="uname" and .process.argv==["uname","-s"]' ".lineage.depth")" 3
	check D1.10 "a direct launch (proc_open array) has no shell: its parent is a worker" "$(first '.event_type=="process.exec" and .process.image=="uname" and .process.argv==["/usr/bin/uname","-s"]' '[.lineage.depth, .parent.image]|join(" ")')" "2 php-fpm8.4"

	info "agent watches nginx only"
	start_agent --watch-image-contains nginx --capture-argv=true
	curl_php "$(url shell)" > /dev/null; curl_php "$(url direct)" > /dev/null
	sleep 1; stop_agent > /dev/null
	check D1.11 "an nginx-only watch sees nothing of what PHP started" "$(count '.event_type=="process.exec" and (.process.image=="dash" or .process.image=="uname")')" 0
	check D1.12 "it only knows the nginx processes" "$(count '.event_type=="process.discovered" and .process.image!="nginx"')" 0
	;;

apache-fpm)
	up_fpm; up_apache_fpm
	show 'apache2|php-fpm'
	M=$(pid_of 'php-fpm: master')
	info "agent watches apache2 only (PHP runs in the separate FPM service)"
	start_agent --watch-image-contains apache2 --capture-argv=true
	curl_php "$(url81 shell)" > /dev/null; curl_php "$(url81 direct)" > /dev/null
	sleep 1; stop_agent > /dev/null
	check D2.1 "an apache2-only watch sees nothing of what PHP-FPM started" "$(count '.event_type=="process.exec" and (.process.image=="dash" or .process.image=="uname")')" 0
	info "agent watches php-fpm"
	start_agent --watch-image-contains php-fpm --capture-argv=true
	curl_php "$(url81 shell)" > /dev/null; curl_php "$(url81 direct)" > /dev/null
	sleep 1; stop_agent > /dev/null
	check D2.2 "a php-fpm watch sees the shell" "$(count '.event_type=="process.exec" and .process.image=="dash"')" 1
	check D2.3 "attributed to the FPM master" "$(first '.event_type=="process.exec" and .process.image=="dash"' ".root.pid")" "$M"
	;;

apache-modphp)
	up_apache_modphp
	show 'apache2'
	M=$(pid_of 'apache2 -k start')
	check D3.1 "Apache's executable (mod_php is loaded into it)" "$(exe "$M")" /usr/sbin/apache2
	check D3.2 "no php executable is running (PHP lives inside Apache)" "$(for p in /proc/[0-9]*; do b=$(basename "$(readlink "$p/exe" 2> /dev/null)"); case $b in php*) echo "$b" ;; esac; done | wc -l | tr -d ' ')" 0
	check_true D3.3 "libphp8.4.so is mapped into the Apache workers" grep -q libphp8.4.so "/proc/$M/maps"
	start_agent --watch-image-contains apache2 --capture-argv=true
	curl_php "$(url81 shell)" > /dev/null; curl_php "$(url81 direct)" > /dev/null
	sleep 1; stop_agent > /dev/null
	check D3.4 "the shell is a descendant of the Apache master" "$(first '.event_type=="process.exec" and .process.image=="dash"' '[.root.pid, .root.image, .lineage.depth]|join(" ")')" "$M apache2 2"
	check D3.5 "a direct launch from an Apache worker" "$(first '.event_type=="process.exec" and .process.image=="uname" and .process.argv==["/usr/bin/uname","-s"]' '.lineage.depth')" 2
	info "a watch on php finds nothing: there is no PHP executable"
	start_agent --watch-image-contains php --capture-argv=true
	curl_php "$(url81 shell)" > /dev/null; sleep 1; stop_agent > /dev/null
	check D3.6 "a php watch sees nothing of mod_php" "$(count '.event_type=="process.exec" and .process.image=="dash"')" 0
	;;

nginx-phpcgi)
	cat > /etc/nginx/sites-enabled/default <<'NG'
server { listen 8080 default_server; root /var/www/html;
  location ~ \.php$ { include snippets/fastcgi-php.conf; fastcgi_pass 127.0.0.1:9000; } }
NG
	PHP_FCGI_CHILDREN=3 PHP_FCGI_MAX_REQUESTS=0 setsid php-cgi -b 127.0.0.1:9000 > /dev/null 2>&1 &
	nginx; wait_port 8080; wait_port 9000
	show 'php-cgi|nginx: master'
	M=$(pgrep -o -x php-cgi || pgrep -o -f 'php-cgi -b')
	check D4.1 "the FastCGI daemon is php-cgi8.4" "$(exe "$M")" /usr/bin/php-cgi8.4
	start_agent --watch-image-contains php-cgi --capture-argv=true
	curl_php "$(url shell)" > /dev/null; curl_php "$(url direct)" > /dev/null
	sleep 1; stop_agent > /dev/null
	check D4.2 "the daemon is a root, its children are depth 1" "$(first ".event_type==\"process.discovered\" and .process.pid==$M" '[.lineage.role,.process.image]|join(" ")') $(count ".event_type==\"process.discovered\" and .lineage.depth==1 and .root.pid==$M")" "root php-cgi8.4 3"
	check D4.3 "the shell below a php-cgi child belongs to the daemon" "$(first '.event_type=="process.exec" and .process.image=="dash"' '[.root.pid, .lineage.depth]|join(" ")')" "$M 2"
	info "a watch on nginx does not see it either"
	start_agent --watch-image-contains nginx --capture-argv=true
	curl_php "$(url shell)" > /dev/null; sleep 1; stop_agent > /dev/null
	check D4.4 "an nginx-only watch misses php-cgi" "$(count '.event_type=="process.exec" and .process.image=="dash"')" 0
	;;

apache-fcgid)
	a2dismod -q php8.4 mpm_prefork 2> /dev/null; a2enmod -q mpm_event fcgid > /dev/null
	echo "ServerName localhost" > /etc/apache2/conf-available/servername.conf; a2enconf -q servername > /dev/null
	sed -i 's/^Listen 80$/Listen 8081/' /etc/apache2/ports.conf
	sed -i 's/<VirtualHost \*:80>/<VirtualHost *:8081>/' /etc/apache2/sites-enabled/000-default.conf
	cat > /etc/apache2/conf-enabled/fcgid-php.conf <<'AP'
<Directory /var/www/html>
  Options +ExecCGI
  AddHandler fcgid-script .php
  FcgidWrapper /usr/lib/cgi-bin/php8.4 .php
</Directory>
AP
	apache2ctl start > /dev/null 2>&1; wait_port 8081
	curl_php "$(url81 info)" > /dev/null   # mod_fcgid starts the wrapper on the first request
	sleep 0.5
	show 'apache2|php8.4|php-cgi'
	W=$(pgrep -o -f '/usr/lib/cgi-bin/php8.4')
	check D5.1 "the executable behind mod_fcgid is the CGI wrapper, named php8.4" "$(exe "$W")" /usr/lib/cgi-bin/php8.4
	info "a php-cgi watch does not match it"
	start_agent --watch-image-contains php-cgi --capture-argv=true
	curl_php "$(url81 shell)" > /dev/null; sleep 1; stop_agent > /dev/null
	check D5.2 "php-cgi misses the Debian wrapper (its name is php8.4)" "$(count '.event_type=="process.exec" and .process.image=="dash"')" 0
	info "apache2 covers it"
	start_agent --watch-image-contains apache2 --capture-argv=true
	curl_php "$(url81 shell)" > /dev/null; sleep 1; stop_agent > /dev/null
	check D5.3 "an apache2 watch sees the shell below the wrapper" "$(first '.event_type=="process.exec" and .process.image=="dash"' '[.lineage.depth, .parent.image]|join(" ")')" "3 php8.4"
	info "the wrapper's own name selects it"
	start_agent --watch-image-contains php8.4 --capture-argv=true
	curl_php "$(url81 shell)" > /dev/null; sleep 1; stop_agent > /dev/null
	check D5.4 "a php8.4 watch roots the tree at the wrapper" "$(first '.event_type=="process.exec" and .process.image=="dash"' '[.root.image, .lineage.depth]|join(" ")')" "php8.4 1"
	;;

cli)
	up_fpm; up_nginx_fpm
	check D6.1 "php (the alternatives link) runs php8.4" "$(readlink -f /usr/bin/php)" /usr/bin/php8.4
	info "agent watches the versioned CLI name"
	start_agent --watch-image-contains php8.4 --capture-argv=true
	setsid sh -c 'php /var/www/html/worker.php 2 100' > /dev/null 2>&1 &
	sleep 2; stop_agent > /dev/null
	check D6.2 "the CLI worker is a root with the versioned image" "$(first '.event_type=="process.exec" and .process.image=="php8.4"' '[.lineage.role,.process.argv[0],.process.argv[1]]|join(" ")')" "root php /var/www/html/worker.php"
	check D6.3 "the programs it starts are descendants" "$(count '.event_type=="process.exec" and .lineage.role=="descendant" and .root.image=="php8.4" and .process.image=="true"')" 2
	check D6.4 "php8.4 does not select the FPM master" "$(count '.event_type=="process.discovered" and .process.image=="php-fpm8.4"')" 0
	info "agent watches the generic php substring while FPM also runs"
	start_agent --watch-image-contains php --capture-argv=true
	sleep 0.5; stop_agent > /dev/null
	check D6.5 "php selects the FPM master as well" "$(first '.event_type=="process.discovered" and .lineage.role=="root"' '.process.image')" php-fpm8.4
	;;
*) echo "unknown deployment $D"; exit 2 ;;
esac
finish
