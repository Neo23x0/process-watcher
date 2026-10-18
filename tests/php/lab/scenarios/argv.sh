#!/bin/bash
# What an investigation gets of a command line: shapes of real shells and interpreters started by PHP, the
# 4096 byte boundary, and the configurable limits.
. /lab/lib.sh
prepare_fixture; up_fpm; up_nginx_fpm
sendcmd() { curl_php "$(url "$1")$2" > /dev/null; }

info "default limits (32 arguments, 4096 bytes)"
start_agent --watch-image-contains php-fpm --capture-argv=true
check A0 "agent.started reports the limits" "$(first '.event_type=="agent.started"' '.details.capture_argv_limits|[.max_args,.max_bytes]|join(" ")')" "32 4096"
sendcmd shell ''; sendcmd python ''; sendcmd phpr ''; sendcmd bash ''; sendcmd bashexec ''; sendcmd direct ''; sendcmd special ''; sendcmd deep ''; sendcmd phpnear ''
for n in 4080 4081 4082 6000; do sendcmd long "&n=$n"; done
for n in 30 31 32 33; do sendcmd args "&n=$n"; done
sleep 1.5; stop_agent > /dev/null

check A1 "shell_exec starts sh -c -- <command>: the command is the fourth element" "$(count '.event_type=="process.exec" and .process.image=="dash" and (.process.argv==["sh","-c","--","uname -s"])')" 1
check A2 "python3 -c: the interpreter's image is the real, versioned executable" "$(first '.event_type=="process.exec" and (.process.image|test("^python3"))' '[.process.image,.process.argv[0],.process.argv[1],.process.argv[2]]|join(" ")')" "python3.13 python3 -c print(40+2)"
check A3 "php -r keeps the inline code; the image is php8.4" "$(first '.event_type=="process.exec" and .process.image=="php8.4"' '[.process.argv[0],.process.argv[1],.process.argv[2]]|join(" ")')" "php -r echo 6*7;"
check A4 "bash -c keeps the inline command" "$(first '.event_type=="process.exec" and .process.image=="bash" and .process.argv[0]=="bash"' '.process.argv|join("|")')" "bash|-c|echo pw-bash-ok"
check A5 "a direct launch has the program as argv[0] and no shell parent" "$(first '.event_type=="process.exec" and .process.image=="uname" and .process.argv==["/usr/bin/uname","-s"]' '.parent.image')" php-fpm8.4
check A6 "empty, spaced, quoted, newline and tab arguments stay separate elements" "$(first '.event_type=="process.exec" and .process.image=="echo" and (.process.argv|length)==6' '.process.argv|@json')" '["/bin/echo","","a b","\"q\" '"'"'s'"'"'","line1\nline2","tab\tx"]'
check A7 "a same-PID exec: bash replaces itself with uname (exec_index 2, same process)" "$(first '.event_type=="process.exec" and .process.image=="uname" and .details.previous_image=="bash"' '[.details.exec_index,.details.previous_image]|join(" ")')" "2 bash"
check A8 "nested shells keep the chain (depth of the innermost program)" "$(first '.event_type=="process.exec" and .process.image=="id"' '.lineage.depth')" 4

# the boundary: command length L of "sh -c -- <command>" fits when 9 + L + 1 <= 4096, i.e. L <= 4086
cmdlen() { # cmdlen N: events of dash whose command has N + 5 bytes ("echo " + N x A)
	count ".event_type==\"process.exec\" and .process.image==\"dash\" and (.process.argv|length)==4 and (.process.argv[3]|length)==$(( $1 + 5 ))"
}
check A9 "a command of 4085 bytes is complete" "$(cmdlen 4080)" 1
check A10 "a command of 4086 bytes (the longest that fits) is complete" "$(cmdlen 4081)" 1
check A11 "a command of 4087 bytes is not in argv" "$(cmdlen 4082)" 0
check A12 "...the shell is still seen, with -c and -- only (three of them: 4087 and 6005 byte commands, and the shell that started php below)" "$(count '.event_type=="process.exec" and .process.image=="dash" and (.process.argv|length)==3 and .process.argv_complete==false')" 3
check A13 "...and says what it is missing" "$(first '.event_type=="process.exec" and .process.image=="dash" and .process.argv_complete==false and .process.argv_capture.total_bytes==4097' '.process.argv_capture|[.argc,.captured_args,.captured_bytes,.limit_bytes,.partial.index,(.partial.value|length)]|join(" ")')" "4 3 4096 4096 3 4087"
check A14 "...the cut command is kept apart: its first 4087 bytes of a 6005 byte command" "$(first '.event_type=="process.exec" and .process.image=="dash" and .process.argv_capture.total_bytes==6015' '.process.argv_capture|[.partial.index,(.partial.value|length),.partial.captured_bytes]|join(" ")')" "3 4087 4087"
check A15 "31 arguments (argv[0] and 31 more = 32) are complete" "$(count '.event_type=="process.exec" and .process.image=="echo" and (.process.argv|length)==32 and .process.argv_complete==true')" 1
check A16 "33 arguments are cut at 32 and flagged" "$(count '.event_type=="process.exec" and .process.image=="echo" and (.process.argv|length)==32 and .process.argv_complete==false and .process.argv_capture.argc==34')" 1
check A17 "the kernel's byte total is the size of the argument area that was sent (9 + 6005 + 1)" "$(first '.event_type=="process.exec" and .process.image=="dash" and .process.argv_capture.total_bytes==6015' '.process.argv_capture.argc')" 4

info "a short inline script that starts near the end of the capture is lost from argv, and kept as the partial argument"
check A18 "php -r after 4000 bytes of options: the code is not in argv (php, -d, <option>, -r)" "$(count '.event_type=="process.exec" and .process.image=="php8.4" and (.process.argv|length)==4 and .process.argv_complete==false')" 1
check A19 "...its first bytes are in the partial argument" "$(first '.event_type=="process.exec" and .process.image=="php8.4" and .process.argv_complete==false' '.process.argv_capture.partial.value')" "echo 123456;"

info "raised limits (--capture-argv-max-bytes 16383 --capture-argv-max-args 64)"
start_agent --watch-image-contains php-fpm --capture-argv=true --capture-argv-max-bytes 16383 --capture-argv-max-args 64
check A20 "agent.started reports them" "$(first '.event_type=="agent.started"' '.details.capture_argv_limits|[.max_args,.max_bytes]|join(" ")')" "64 16383"
for n in 6000 8000 20000; do sendcmd long "&n=$n"; done
sendcmd args "&n=50"; sendcmd args "&n=100"
sleep 1.5; stop_agent > /dev/null
check A21 "a 6005 byte command is complete" "$(count '.event_type=="process.exec" and .process.image=="dash" and (.process.argv|length)==4 and (.process.argv[3]|length)==6005')" 1
check A22 "an 8005 byte command is complete" "$(count '.event_type=="process.exec" and .process.image=="dash" and (.process.argv|length)==4 and (.process.argv[3]|length)==8005 and .process.argv_complete==true')" 1
check A23 "a 20005 byte command is cut at the limit and reported" "$(first '.event_type=="process.exec" and .process.image=="dash" and .process.argv_capture.total_bytes==20015' '.process.argv_capture|[.captured_bytes,.limit_bytes,(.partial.value|length)]|join(" ")')" "16383 16383 16374"
check A24 "51 arguments are complete with a limit of 64" "$(count '.event_type=="process.exec" and .process.image=="echo" and (.process.argv|length)==51 and .process.argv_complete==true')" 1
check A25 "101 arguments are cut at 64" "$(count '.event_type=="process.exec" and .process.image=="echo" and (.process.argv|length)==64 and .process.argv_complete==false and .process.argv_capture.limit_args==64')" 1

info "every event is valid JSON, one per line, whatever the arguments contained"
check A30 "the log parses completely" "$(jq -c . "$EVENTS" | wc -l | tr -d ' ')" "$(wc -l < "$EVENTS" | tr -d ' ')"
finish
