#!/bin/bash
# Guest side of tests/vm/run-systemd.sh: runs the process-watcher systemd unit
# under a REAL systemd (PID 1 of this VM) and checks what the unit claims.
#
# Runs as pw-vm-test.service (Type=oneshot, after multi-user.target), as root.
# Output goes to the serial console. Every verdict line starts with
# "PW-SYSTEMD: PASS|FAIL|INFO|WARN"; evidence lines start with "PW-SYSTEMD:   | ".
# The last line is PW-VM-EXIT=<number of failed checks>; then the VM powers off.
#
# Staged by the host into /pwtest: process-watcher (the agent binary),
# packaging/ (install.sh, config/, systemd/), this script, env.sh (defines
# PW_SCENARIOS: the scenarios to run, empty for all).
#
# Scenarios (see tests/vm/README.md):
#   S1 systemd-analyze verify + security      S5 kill feature, CAP_KILL dropped
#   S2 install.sh, files, modes, doctor       S6 clean stop
#   S3 start, capabilities, log directory     S7 failure behaviour: a bad configuration,
#   S4 observation under the hardened unit       b log path outside LogsDirectory, c SIGKILL,
#   S8 directive by directive                    d missing privileges
# S2 (the installation) always runs because everything else needs it.

set -u
export LC_ALL=C
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

PW_SCENARIOS=
# shellcheck disable=SC1091
[ -r /pwtest/env.sh ] && . /pwtest/env.sh

AGENT_SRC=/pwtest/process-watcher
PKG=/pwtest/packaging
BIN=/usr/local/bin/process-watcher
CFG=/etc/process-watcher/config.yaml
UNIT_NAME=process-watcher.service
UNIT_FILE=/etc/systemd/system/$UNIT_NAME
DROPIN_DIR=/etc/systemd/system/$UNIT_NAME.d
LOGDIR=/var/log/process-watcher
LOG=$LOGDIR/events.jsonl
T=/tmp/pwtest # test programs and scratch files (the host /tmp, not the service's PrivateTmp)
W=/run/pwwork # evidence and scratch that must survive between steps
SCALE=${PW_TIME_SCALE:-1}

NPASS=0
NFAIL=0
declare -A RESULT

# --- output -----------------------------------------------------------------------
say() { printf 'PW-SYSTEMD: %s\n' "$*"; }
pass() {
	NPASS=$((NPASS + 1))
	say "PASS $*"
}
fail() {
	NFAIL=$((NFAIL + 1))
	say "FAIL $*"
}
info() { say "INFO $*"; }
warn() { say "WARN $*"; }
# ev: text on stdin as indented evidence lines; evn N: the first N lines only
ev() { sed 's/^/PW-SYSTEMD:   | /'; }
evn() { head -n "$1" | ev; }

up() { cut -d' ' -f1 /proc/uptime; }
since() { awk -v a="$1" -v b="$(up)" 'BEGIN { printf "%.1f", b - a }'; }

selected() { # selected S3: true if the scenario was asked for (all when nothing was)
	local s=$1 i
	[ -z "$PW_SCENARIOS" ] && return 0
	for i in $PW_SCENARIOS; do
		case $s in "$i"*) return 0 ;; esac
		case $i in "$s"*) return 0 ;; esac
	done
	return 1
}

SC=
SC_FAIL0=0
begin() {
	SC=$1
	SC_FAIL0=$NFAIL
	say "== $1 $2"
}
end() {
	if [ "$NFAIL" -eq "$SC_FAIL0" ]; then
		RESULT[$SC]=PASS
		say "RESULT $SC PASS"
	else
		RESULT[$SC]=FAIL
		say "RESULT $SC FAIL ($((NFAIL - SC_FAIL0)) failed check(s))"
	fi
}

# assert_eq ID "what" got want
assert_eq() {
	if [ "$3" = "$4" ]; then pass "$1 $2: $3"; else fail "$1 $2: got '$3', want '$4'"; fi
}
# assert_true ID "what" command...   (passes when the command succeeds)
assert_true() {
	local id=$1 what=$2
	shift 2
	if "$@" > /dev/null 2>&1; then pass "$id $what"; else fail "$id $what"; fi
}

# --- waiting ----------------------------------------------------------------------
# wait_until <seconds> <command...>: polls twice a second; the limit is scaled by PW_TIME_SCALE
wait_until() {
	local limit=$(($1 * SCALE)) t0
	shift
	t0=$(date +%s)
	while :; do
		"$@" > /dev/null 2>&1 && return 0
		[ $(($(date +%s) - t0)) -ge "$limit" ] && return 1
		sleep 0.5
	done
}

# --- systemd helpers --------------------------------------------------------------
prop() { systemctl show -p "$1" --value "$UNIT_NAME" 2> /dev/null; }
svc_running() { [ "$(prop ActiveState)/$(prop SubState)" = active/running ]; }
svc_state() {
	printf 'ActiveState=%s SubState=%s Result=%s ExecMainStatus=%s NRestarts=%s MainPID=%s' \
		"$(prop ActiveState)" "$(prop SubState)" "$(prop Result)" "$(prop ExecMainStatus)" "$(prop NRestarts)" "$(prop MainPID)"
}
journal() { journalctl -u "$UNIT_NAME" --no-pager -o short-monotonic "$@" 2> /dev/null; }
journal_tail() { journal -n "${1:-25}" | ev; }

# --- the event log ------------------------------------------------------------------
MARK=0
mark() { if [ -f "$LOG" ]; then MARK=$(wc -l < "$LOG"); else MARK=0; fi; }
# slice <file>: the lines written since mark(), copied so that jq reads a stable file
slice() { tail -n +$((MARK + 1)) "$LOG" 2> /dev/null > "$1"; }
log_has() { tail -n +$((MARK + 1)) "$LOG" 2> /dev/null | grep -q "$1"; }
# exit_logged <pid>: a process.exit event of that process is in the log since the mark
exit_logged() { tail -n +$((MARK + 1)) "$LOG" 2> /dev/null | grep -qE "\"event_type\":\"process.exit\".*\"process\":\{\"process_id\":\"[^\"]*\",\"pid\":$1,"; }
log_count() { tail -n +$((MARK + 1)) "$LOG" 2> /dev/null | grep -c "$1"; }
# jl <file> [-r] <filter>: jq over a JSONL file; tolerates a torn last line
jl() {
	local f=$1 opt=-c
	shift
	if [ "$1" = -r ]; then
		opt=-cr
		shift
	fi
	jq -R "$opt" "fromjson? | ($1)" "$f"
}

# a compact one-line rendering of process events
ROWS='[.sequence, .event_type, (.process.image // "-"), "pid=\(.process.pid // "-")", "uid=\(.process.uid // "-")", (.lineage.role // "-"), "depth=\(.lineage.depth // "-")", (.process.image_path // "-")] | join(" ")'

# --- test processes ---------------------------------------------------------------
# Names that only the test processes have: "pwwatch" is what the agent watches,
# the pwkill* names are what the kill rules match.
as1000() { setpriv --reuid=1000 --regid=1000 --clear-groups "$@"; }

make_programs() {
	mkdir -p "$T"
	chmod 0755 "$T"
	cp /usr/bin/sleep "$T/pwwatch-sleep"
	cp /usr/bin/bash "$T/pwwatch-bash"
	cp /usr/bin/sleep "$T/pwkillstr-victim"
	cp /usr/bin/sleep "$T/pwkillre7"
	cp /usr/bin/sleep "$T/pwwatch-pwkillstr" # matches the watch pattern AND the kill string: a root, never a target
	mkdir -p /root
	cp /usr/bin/sleep /root/pwwatch-home
	# the watched root of S4: a tree of children and grandchildren
	cat > "$T/workload1.sh" << 'EOF'
# Runs as a watched root (image pwwatch-bash, root) and starts children and grandchildren.
T=/tmp/pwtest
/usr/bin/true
/usr/bin/sh -c '/usr/bin/uname -s > /dev/null; /usr/bin/id -u > /dev/null'
/usr/bin/setpriv --reuid=1000 --regid=1000 --clear-groups /usr/bin/id -u > /dev/null
( /usr/bin/true ) &
wait
/usr/bin/sh -c "exec $T/pwwatch-sleep 1"
i=0
while [ $i -lt 100 ]; do /usr/bin/true; i=$((i + 1)); done
EOF
	# the watched root of S5: starts the victims as another user
	cat > "$T/workload-kill.sh" << 'EOF'
# Runs as a watched root (image pwwatch-bash, root). The victims run as uid 1000 beneath it.
T=/tmp/pwtest
for v in "$@"; do
	/usr/bin/setpriv --reuid=1000 --regid=1000 --clear-groups "$T/$v" 600 &
	echo $! > "$T/$v.pid"
done
# a descendant that no rule matches
/usr/bin/sleep 600 &
echo $! > "$T/survivor.pid"
wait
EOF
}

proc_gone() { # no such process, or only a zombie that its parent has not reaped yet
	local st
	[ -r "/proc/$1/stat" ] || return 0
	st=$(sed -n 's/^State:[[:space:]]*\(.\).*/\1/p' "/proc/$1/status" 2> /dev/null)
	[ -z "$st" ] || [ "$st" = Z ]
}

# --- configurations ---------------------------------------------------------------
CONFIG_IN_USE=
write_config() { # write_config <name> [log path]
	local name=$1 path=${2:-$LOG}
	{
		echo 'config_version: 1'
		echo 'watch:'
		echo '  image_contains: ["pwwatch"]'
		echo 'capture:'
		echo '  argv: true'
		case $name in
		kill)
			echo 'kill:'
			echo '  enabled: true'
			echo '  fields: [image]'
			echo '  strings: ["pwkillstr"]'
			echo "  regex: ['^pwkillre[0-9]+\$']"
			;;
		esac
		echo 'outputs:'
		echo '  file:'
		echo "    path: $path"
		echo 'runtime:'
		echo '  health_interval: 5s'
		case $name in
		badkey) echo 'bogus_key: 1' ;;
		esac
	} > "$CFG.new"
	chmod 0600 "$CFG.new"
	mv "$CFG.new" "$CFG"
	CONFIG_IN_USE=$name
}

# --- service control ----------------------------------------------------------------
dropin() { # dropin <name> <content>
	mkdir -p "$DROPIN_DIR"
	printf '%s\n' "$2" > "$DROPIN_DIR/$1.conf"
	systemctl daemon-reload
}
remove_dropins() {
	rm -rf "${DROPIN_DIR:?}"
	systemctl daemon-reload
}
stop_service() {
	timeout 120 systemctl stop "$UNIT_NAME" > /dev/null 2>&1
	systemctl reset-failed "$UNIT_NAME" > /dev/null 2>&1
}
# start_service [restart]: start (or restart), wait for active and for agent.ready after the mark
start_service() {
	local verb=${1:-start}
	mark
	timeout 120 systemctl "$verb" "$UNIT_NAME" > /dev/null 2>&1
	wait_until 180 log_has '"event_type":"agent.ready"' || return 1
	svc_running
}
# fresh <config>: known state: service stopped, no drop-ins, the named configuration
fresh() {
	stop_service
	remove_dropins
	write_config "$1"
}

# ======================================================================================
# S2: installation exactly as a user does it (always runs: everything else needs it)
# ======================================================================================
scn_S2() {
	begin S2 "install.sh, files, modes, doctor"
	mkdir -p "$W"
	make_programs
	info "S2 guest: $(systemctl --version | head -n 1), kernel $(uname -sr) $(uname -m), virtualization: $(systemd-detect-virt)"
	local out rc m
	out=$("$PKG/install.sh" "$AGENT_SRC" 2>&1)
	rc=$?
	printf '%s\n' "$out" | ev
	assert_eq S2.1 "install.sh exit status" "$rc" 0
	m=$(stat -c '%a %U:%G' "$BIN")
	assert_eq S2.2 "binary $BIN mode and owner" "$m" "755 root:root"
	m=$(stat -c '%a %U:%G' /etc/process-watcher)
	assert_eq S2.3 "directory /etc/process-watcher" "$m" "755 root:root"
	m=$(stat -c '%a %U:%G' "$CFG")
	assert_eq S2.4 "configuration $CFG" "$m" "600 root:root"
	m=$(stat -c '%a %U:%G' "$UNIT_FILE")
	assert_eq S2.5 "unit file $UNIT_FILE" "$m" "644 root:root"
	if cmp -s "$PKG/systemd/process-watcher.service" "$UNIT_FILE" && cmp -s "$AGENT_SRC" "$BIN"; then
		pass "S2.6 installed unit and binary are the staged ones"
	else
		fail "S2.6 installed unit or binary differ from the staged files"
	fi
	assert_eq S2.7 "NeedDaemonReload after install.sh (daemon-reload was run)" "$(prop NeedDaemonReload)" no
	assert_eq S2.8 "FragmentPath" "$(prop FragmentPath)" "$UNIT_FILE"
	assert_eq S2.9 "install.sh does not start the service (ActiveState)" "$(prop ActiveState)" inactive
	assert_eq S2.10 "install.sh does not enable the service (UnitFileState)" "$(prop UnitFileState)" disabled
	# a second run keeps the edited configuration
	echo '# edited by the user' >> "$CFG"
	out=$("$PKG/install.sh" "$AGENT_SRC" 2>&1)
	assert_true S2.11 "second install.sh run says it keeps the existing configuration" grep -q 'keeping the existing' <<< "$out"
	assert_true S2.12 "the user's edit survived" grep -q '^# edited by the user' "$CFG"
	assert_eq S2.13 "configuration mode after the second run" "$(stat -c '%a' "$CFG")" 600

	write_config base
	assert_true S2.14 "check-config accepts the test configuration" "$BIN" check-config --config "$CFG"
	out=$("$BIN" doctor --config "$CFG" 2>&1)
	rc=$?
	printf '%s\n' "$out" | ev
	assert_eq S2.15 "doctor outside the service (root, no sandbox): exit status" "$rc" 0
	end
}

# ======================================================================================
# S1: systemd-analyze
# ======================================================================================
scn_S1() {
	begin S1 "systemd-analyze verify and security"
	local out rc
	out=$(systemd-analyze verify "$UNIT_FILE" 2>&1)
	rc=$?
	if [ -z "$out" ] && [ "$rc" -eq 0 ]; then
		pass "S1.1 systemd-analyze verify: no output, exit status 0"
	else
		fail "S1.2 systemd-analyze verify printed warnings (exit status $rc)"
		printf '%s\n' "$out" | ev
	fi
	out=$(systemd-analyze security "$UNIT_NAME" --no-pager 2>&1)
	rc=$?
	if [ "$rc" -ne 0 ]; then
		fail "S1.2 systemd-analyze security failed (exit status $rc)"
		printf '%s\n' "$out" | ev
	else
		local score exposures
		score=$(printf '%s\n' "$out" | sed -n 's/.*Overall exposure level for [^:]*: *\(.*\)$/\1/p')
		exposures=$(printf '%s\n' "$out" | grep -c '^- ')
		pass "S1.2 systemd-analyze security: overall exposure level $score, $exposures exposure(s) listed"
		info "S1 systemd-analyze security $UNIT_NAME (full output):"
		printf '%s\n' "$out" | ev
	fi
	end
}

# ======================================================================================
# S3: start, capabilities, log directory
# ======================================================================================
# cap_names <hex>: the names of a capability mask, lower case, sorted, blank separated
cap_names() {
	capsh --decode="$1" 2> /dev/null | sed 's/^[^=]*=//' | tr ',' '\n' | sort | tr '\n' ' ' | sed 's/ $//'
}
unit_caps() { # the names in the unit's CapabilityBoundingSet=, lower case, sorted
	sed -n 's/^CapabilityBoundingSet=//p' "$UNIT_FILE" | tr ' ' '\n' | tr 'A-Z' 'a-z' | grep -v '^$' | sort | tr '\n' ' ' | sed 's/ $//'
}
status_field() { sed -n "s/^$2:[[:space:]]*//p" "/proc/$1/status"; }

PRE_ROOT=
PRE_USER=
start_preexisting() {
	# processes that exist before the agent starts: found by the startup snapshot
	"$T/pwwatch-bash" -c '/usr/bin/sleep 3600; :' &
	PRE_ROOT=$!
	setpriv --reuid=1000 --regid=1000 --clear-groups "$T/pwwatch-sleep" 3600 &
	PRE_USER=$!
	sleep 1
}

scn_S3() {
	begin S3 "start under systemd, capabilities, log directory"
	fresh base
	rm -rf "${LOGDIR:?}"
	start_preexisting
	local t0
	t0=$(up)
	mark
	timeout 120 systemctl start "$UNIT_NAME" > "$W/start.out" 2>&1
	assert_eq S3.1 "systemctl start exit status" "$?" 0
	if wait_until 60 svc_running; then
		pass "S3.2 service is active (running) $(since "$t0") s after the start command"
	else
		fail "S3.2 service did not reach active (running): $(svc_state)"
		journal_tail 40
		end
		return
	fi
	if wait_until 180 log_has '"event_type":"agent.ready"'; then
		pass "S3.3 agent.ready is in the log $(since "$t0") s after the start command"
	else
		fail "S3.3 no agent.ready within the limit: $(svc_state)"
		journal_tail 40
		tail -n 5 "$LOG" 2> /dev/null | cut -c1-300 | ev
	fi
	local f="$W/s3.jsonl" seq1 seq2 id1 id2 t1 t2
	slice "$f"
	seq1=$(jl "$f" -r 'select(.event_type=="agent.started") | .sequence' | head -n 1)
	seq2=$(jl "$f" -r 'select(.event_type=="agent.ready") | .sequence' | head -n 1)
	id1=$(jl "$f" -r 'select(.event_type=="agent.started") | .agent_instance_id' | head -n 1)
	id2=$(jl "$f" -r 'select(.event_type=="agent.ready") | .agent_instance_id' | head -n 1)
	t1=$(jl "$f" -r 'select(.event_type=="agent.started") | .timestamp' | head -n 1)
	t2=$(jl "$f" -r 'select(.event_type=="agent.ready") | .timestamp' | head -n 1)
	if [ -n "$seq1" ] && [ -n "$seq2" ] && [ "$seq1" -lt "$seq2" ] && [ "$id1" = "$id2" ]; then
		pass "S3.4 agent.started (sequence $seq1, $t1) precedes agent.ready (sequence $seq2, $t2), same agent_instance_id $id1"
	else
		fail "S3.4 agent.started/agent.ready missing or out of order (started=$seq1 ready=$seq2 ids=$id1/$id2)"
	fi
	assert_eq S3.5 "agent.started reports kill.enabled" "$(jl "$f" -r 'select(.event_type=="agent.started") | .details.kill.enabled' | head -n 1)" false
	assert_eq S3.6 "agent.started reports the configuration source" "$(jl "$f" -r 'select(.event_type=="agent.started") | .details.config_source' | head -n 1)" "$CFG"
	jl "$f" -r 'select(.event_type=="agent.ready") | "agent.ready: snapshot_processes=\(.details.snapshot_processes) discovered_roots=\(.details.discovered_roots) discovered_descendants=\(.details.discovered_descendants)"' | head -n 1 | ev

	# --- the running process ---
	local pid caps_bnd caps_eff nn want got
	pid=$(prop MainPID)
	info "S3 MainPID=$pid"
	caps_bnd=$(status_field "$pid" CapBnd)
	caps_eff=$(status_field "$pid" CapEff)
	nn=$(status_field "$pid" NoNewPrivs)
	{
		grep -E '^(Name|Uid|Gid|CapInh|CapPrm|CapEff|CapBnd|CapAmb|NoNewPrivs|Seccomp|Seccomp_filters|Umask|NSpid):' "/proc/$pid/status"
		echo "ns/pid: $(readlink "/proc/$pid/ns/pid") (init: $(readlink /proc/1/ns/pid))"
		echo "ns/mnt: $(readlink "/proc/$pid/ns/mnt") (init: $(readlink /proc/1/ns/mnt))"
		echo "cgroup: $(cat "/proc/$pid/cgroup")"
	} | ev
	want=$(unit_caps)
	got=$(cap_names "$caps_bnd")
	assert_eq S3.7 "CapBnd ($caps_bnd) equals the unit's CapabilityBoundingSet" "$got" "$want"
	got=$(cap_names "$caps_eff")
	assert_eq S3.8 "CapEff ($caps_eff) equals the bounding set (root keeps what the set allows)" "$got" "$want"
	assert_eq S3.9 "NoNewPrivs" "$nn" 1
	assert_eq S3.10 "Uid (real, effective, saved, fs) of the service" "$(status_field "$pid" Uid)" $'0\t0\t0\t0'
	assert_eq S3.11 "Umask of the service (UMask=0077)" "$(status_field "$pid" Umask)" 0077
	if [ "$(status_field "$pid" Seccomp)" = 2 ]; then
		pass "S3.12 a seccomp filter is installed ($(status_field "$pid" Seccomp_filters) filter(s))"
	else
		fail "S3.12 no seccomp filter on the service although the unit asks for syscall restrictions"
	fi
	assert_eq S3.13 "the service lives in the host PID namespace" "$(readlink "/proc/$pid/ns/pid")" "$(readlink /proc/1/ns/pid)"
	assert_eq S3.14 "NSpid lists exactly one id (initial PID namespace)" "$(status_field "$pid" NSpid | wc -w | tr -d ' ')" 1
	if [ "$(readlink "/proc/$pid/ns/mnt")" != "$(readlink /proc/1/ns/mnt)" ]; then
		pass "S3.15 the service has its own mount namespace (the sandbox is active)"
	else
		fail "S3.15 the service shares the mount namespace of init: ProtectSystem/ProtectHome/PrivateTmp are not in effect"
	fi
	if grep ' /proc ' "/proc/$pid/mountinfo" | grep -q 'hidepid\|subset=pid'; then
		fail "S3.16 /proc is mounted with hidepid or subset=pid in the service"
		grep ' /proc ' "/proc/$pid/mountinfo" | ev
	else
		pass "S3.16 /proc in the service has no hidepid and no subset=pid (host process view)"
	fi

	# --- the log directory ---
	assert_eq S3.17 "$LOGDIR mode and owner (LogsDirectory=, LogsDirectoryMode=0700)" "$(stat -c '%a %U:%G' "$LOGDIR")" "700 root:root"
	assert_eq S3.18 "$LOG mode and owner" "$(stat -c '%a %U:%G' "$LOG")" "600 root:root"
	if [ -e "$LOG.lock" ]; then
		assert_eq S3.19 "$LOG.lock mode" "$(stat -c '%a %U:%G' "$LOG.lock")" "600 root:root"
	fi

	# --- journal ---
	local jtxt
	jtxt=$(journal)
	printf '%s\n' "$jtxt" | evn 30
	if printf '%s\n' "$jtxt" | grep -qE 'level=(ERROR|WARN)'; then
		fail "S3.20 the agent logged warnings or errors while starting"
	else
		pass "S3.20 no warnings or errors from the agent in the journal"
	fi
	end
}

# ======================================================================================
# S4: observation under the hardened unit
# ======================================================================================
scn_S4() {
	begin S4 "observation under the hardened unit (BPF, host process view, other users)"
	if ! { svc_running && [ "$CONFIG_IN_USE" = base ]; }; then
		fresh base
		rm -rf "${LOGDIR:?}"
		start_preexisting
		start_service || {
			fail "S4.0 service did not start: $(svc_state)"
			journal_tail 30
			end
			return
		}
	fi
	local f="$W/s4.jsonl" root1 t0 user_root home_root
	mark
	t0=$(up)
	# (1) a watched root with children and grandchildren
	"$T/pwwatch-bash" "$T/workload1.sh" &
	root1=$!
	# (2) a watched root of another user
	setpriv --reuid=1000 --regid=1000 --clear-groups "$T/pwwatch-sleep" 2 &
	user_root=$!
	# (3) a watched root that runs below /root (ProtectHome=yes hides /root from the service)
	/root/pwwatch-home 1 &
	home_root=$!
	wait "$root1" "$user_root" "$home_root"
	info "S4 workload finished after $(since "$t0") s; roots: $root1 (root), $user_root (uid 1000), $home_root (/root)"
	# wait until the exit events of all three roots are in the log
	wait_until 120 exit_logged "$root1" && wait_until 120 exit_logged "$user_root" && wait_until 120 exit_logged "$home_root"
	sleep 2
	slice "$f"
	info "S4 events written since the workload started: $(wc -l < "$f")"
	jl "$f" -r "select(.root.pid==$root1 and .process.image != \"true\") | $ROWS" | sed -n 1,40p | ev
	info "S4 (the 102 executions of /usr/bin/true are counted below, not listed)"

	local n got want
	# root: exec event with role root, uid 0, right image and path
	n=$(jl "$f" -r "select(.event_type==\"process.exec\" and .process.pid==$root1 and .lineage.role==\"root\" and .process.image==\"pwwatch-bash\" and .process.image_path==\"$T/pwwatch-bash\" and .process.uid==0 and .process.euid==0) | .event_type" | wc -l | tr -d ' ')
	assert_eq S4.1 "root: one process.exec (role root, image pwwatch-bash, image_path $T/pwwatch-bash, uid 0)" "$n" 1
	# exec counts of the descendants by image
	got=$(jl "$f" -r "select(.event_type==\"process.exec\" and .root.pid==$root1 and .lineage.role==\"descendant\") | .process.image" | sort | uniq -c | awk '{printf "%s=%s ", $2, $1}' | sed 's/ $//')
	want="dash=2 id=2 pwwatch-sleep=1 setpriv=1 true=102 uname=1"
	assert_eq S4.2 "descendant exec events by image (children and grandchildren of the root)" "$got" "$want"
	got=$(jl "$f" -r "select(.event_type==\"process.exec\" and .root.pid==$root1 and .lineage.role==\"descendant\") | \"\(.process.image)=\(.process.image_path)\"" | sort -u | tr '\n' ' ' | sed 's/ $//')
	want="dash=/usr/bin/dash id=/usr/bin/id pwwatch-sleep=$T/pwwatch-sleep setpriv=/usr/bin/setpriv true=/usr/bin/true uname=/usr/bin/uname"
	assert_eq S4.3 "image_path of every descendant (the symlink sh is resolved to dash)" "$got" "$want"
	got=$(jl "$f" -r "select(.event_type==\"process.exec\" and .root.pid==$root1) | .lineage.depth" | sort -n | uniq -c | awk '{printf "depth%s=%s ", $2, $1}' | sed 's/ $//')
	info "S4 exec events by lineage depth: $got"
	n=$(jl "$f" -r "select(.event_type==\"process.exec\" and .root.pid==$root1 and .lineage.depth==2) | .process.image" | sort -u | tr '\n' ' ')
	if [ -n "$n" ]; then pass "S4.4 grandchildren (depth 2) were observed: $n"; else fail "S4.4 no grandchildren (depth 2) observed"; fi
	# another user's process inside the tree
	got=$(jl "$f" -r "select(.event_type==\"process.exec\" and .root.pid==$root1 and .process.image==\"id\") | \"uid=\(.process.uid)\"" | sort | uniq -c | awk '{printf "%s x%s ", $2, $1}' | sed 's/ $//')
	assert_eq S4.5 "id executed by root (below dash) and by uid 1000 (below setpriv): uid per exec" "$got" "uid=0 x1 uid=1000 x1"
	got=$(jl "$f" -r "select(.event_type==\"process.exec\" and .root.pid==$root1 and .process.image==\"id\" and .process.uid==1000) | \"previous=\(.details.previous_image) exec_index=\(.details.exec_index)\"" | head -n 1)
	assert_eq S4.6 "the uid 1000 exec continues the process that was setpriv (same instance, second exec)" "$got" "previous=setpriv exec_index=2"
	# every process has one exit
	local procs exits dups
	procs=$(jl "$f" -r "select(.root.pid==$root1 and (.event_type|test(\"^process\\\\.(fork|exec|discovered)\$\")) and .process.pid!=$root1) | .process.process_id" | sort -u | wc -l | tr -d ' ')
	exits=$(jl "$f" -r "select(.root.pid==$root1 and .event_type==\"process.exit\" and .process.pid!=$root1) | .process.process_id" | sort | uniq -c | awk '$1==1' | wc -l | tr -d ' ')
	dups=$(jl "$f" -r "select(.root.pid==$root1 and .event_type==\"process.exit\") | .process.process_id" | sort | uniq -d | wc -l | tr -d ' ')
	assert_eq S4.7 "every observed descendant ($procs) has exactly one process.exit ($exits)" "$exits" "$procs"
	assert_eq S4.8 "no process.exit is reported twice" "$dups" 0
	n=$(jl "$f" -r "select(.root.pid==$root1 and .event_type==\"process.exit\" and .process.image==\"true\") | (.details.exit_code|tostring) + \"/\" + (.details.signal|tostring)" | sort | uniq -c | awk '{printf "%s x%s ", $2, $1}' | sed 's/ $//')
	assert_eq S4.9 "the 102 true processes exited with code 0 and no signal" "$n" "0/null x102"
	got=$(jl "$f" -r "select(.root.pid==$root1 and .event_type==\"process.fork\") | .process.process_id" | sort -u | wc -l | tr -d ' ')
	info "S4 fork events (distinct children) under the root: $got"
	n=$(jl "$f" -r "select(.event_type==\"process.exit\" and .process.pid==$root1) | .details.exit_code" | head -n 1)
	assert_eq S4.10 "the root's process.exit carries its exit code" "$n" 0
	n=$(jl "$f" -r '.sequence' | awk 'NR>1 && $1<=prev {bad++} {prev=$1} END {print bad+0}')
	assert_eq S4.11 "sequence numbers are strictly increasing" "$n" 0

	# other users
	got=$(jl "$f" -r "select(.event_type==\"process.exec\" and .process.pid==$user_root and .lineage.role==\"root\") | \"image=\(.process.image) uid=\(.process.uid) euid=\(.process.euid) gid=\(.process.gid) path=\(.process.image_path)\"" | head -n 1)
	assert_eq S4.12 "a watched root of another user is visible with its identity" "$got" "image=pwwatch-sleep uid=1000 euid=1000 gid=1000 path=$T/pwwatch-sleep"
	n=$(jl "$f" -r "select(.event_type==\"process.exit\" and .process.pid==$user_root) | .details.exit_code" | head -n 1)
	assert_eq S4.13 "...and its exit" "$n" 0
	got=$(jl "$f" -r "select(.event_type==\"process.exec\" and .process.pid==$home_root) | \"image=\(.process.image) uid=\(.process.uid) path=\(.process.image_path)\"" | head -n 1)
	assert_eq S4.14 "a program below /root (ProtectHome=yes hides /root from the service) is observed with its path" "$got" "image=pwwatch-home uid=0 path=/root/pwwatch-home"

	# missing fields: any /proc read that the hardened service could not do shows up here
	n=$(jl "$f" -r 'select(.data_quality.missing_fields|length>0) | "\(.event_type) \(.process.image) \(.data_quality.missing_fields|join(","))"' | sort | uniq -c | head -n 5)
	if [ -z "$n" ]; then pass "S4.15 no event has missing_fields (no /proc read failed)"; else fail "S4.15 events with missing_fields"; printf '%s\n' "$n" | ev; fi

	# processes that existed before the agent started (snapshot, /proc reads of other users' processes)
	if [ -n "$PRE_ROOT" ] && kill -0 "$PRE_ROOT" 2> /dev/null; then
		local fa="$W/s4-all.jsonl"
		cp "$LOG" "$fa"
		got=$(jl "$fa" -r "select(.event_type==\"process.discovered\" and .process.pid==$PRE_USER) | \"image=\(.process.image) uid=\(.process.uid) path=\(.process.image_path) role=\(.lineage.role) discovery=\(.details.discovery) missing=\(.data_quality.missing_fields|length)\"" | head -n 1)
		assert_eq S4.16 "a process of uid 1000 that existed before the start is discovered by the snapshot" "$got" "image=pwwatch-sleep uid=1000 path=$T/pwwatch-sleep role=root discovery=startup missing=0"
		got=$(jl "$fa" -r "select(.event_type==\"process.discovered\" and .process.pid==$PRE_ROOT) | \"image=\(.process.image) uid=\(.process.uid) role=\(.lineage.role) discovery=\(.details.discovery)\"" | head -n 1)
		assert_eq S4.17 "a root that existed before the start is discovered" "$got" "image=pwwatch-bash uid=0 role=root discovery=startup"
		got=$(jl "$fa" -r "select(.event_type==\"process.discovered\" and .root.pid==$PRE_ROOT and .lineage.role==\"descendant\") | \"image=\(.process.image) path=\(.process.image_path)\"" | head -n 1)
		assert_eq S4.18 "its living child (sleep) is discovered as a descendant" "$got" "image=sleep path=/usr/bin/sleep"
	else
		info "S4 the processes that S3 starts before the agent are gone; the snapshot checks (S4.16-18) need S3 in the same run"
	fi

	# nothing lost
	sleep 6
	n=$(grep -c '"event_type":"agent.gap"' "$LOG")
	assert_eq S4.19 "no agent.gap in the log" "$n" 0
	got=$(jq -r 'select(.event_type=="agent.health") | .details.collector.lost_total' "$LOG" | sort -u | tr '\n' ' ' | sed 's/ $//')
	assert_eq S4.20 "agent.health: collector.lost_total in every health event" "$got" 0
	jq -r 'select(.event_type=="agent.health") | "last agent.health: records fork=\(.details.collector.records.fork) exec=\(.details.collector.records.exec) exit=\(.details.collector.records.exit) lost=\(.details.collector.lost_total) tracked=\(.details.tracked.instances) roots=\(.details.tracked.roots)"' "$LOG" | tail -n 1 | ev
	assert_true S4.21 "the service is still active (running)" svc_running
	end
}

# ======================================================================================
# S5: kill feature under the hardened unit, then without CAP_KILL
# ======================================================================================
KROOT=
# kill_victims <victim>...: a watched root (root) starts the victims as uid 1000 and a
# harmless survivor (sleep, root); returns when all pid files exist
kill_victims() {
	rm -f "${T:?}"/*.pid
	"$T/pwwatch-bash" "$T/workload-kill.sh" "$@" 2> /dev/null &
	KROOT=$!
	local v
	for v in "$@" survivor; do
		wait_until 30 test -s "$T/$v.pid" || return 1
	done
}
kill_results_ge() { [ "$(log_count '"event_type":"response.kill_result"')" -ge "$1" ]; }

# sandbox_lines: the [Service] settings of the unit and its drop-ins that sandbox the process
# (no commands, no restart policy); used to run other programs inside the very same sandbox
sandbox_lines() {
	{
		cat "$UNIT_FILE"
		local d
		for d in "$DROPIN_DIR"/*.conf; do [ -f "$d" ] && cat "$d"; done
	} | awk '/^\[/ { insvc = ($0 == "[Service]"); next } insvc && !/^#/ && NF' \
		| grep -vE '^(Type|ExecStartPre|ExecStart|ExecStop|ExecReload|Restart|RestartSec|RestartPreventExitStatus|RestartForceExitStatus|TimeoutStopSec|TimeoutStartSec|User)='
}

# probe <name> [Property=value]... -- <script>: runs the script (bash) as root in a oneshot unit with
# the given properties; its output (stdout and stderr) is left in PROBE_OUT
PROBE_OUT=
probe() {
	local name=$1 props=() p
	shift
	while [ $# -gt 0 ] && [ "$1" != -- ]; do
		props+=("$1")
		shift
	done
	shift
	mkdir -p /run/systemd/system
	printf '%s\n' "$1" > "$W/probe-$name.sh"
	{
		echo '[Service]'
		echo 'Type=oneshot'
		for p in "${props[@]}"; do printf '%s\n' "$p"; done
		echo "StandardOutput=file:$W/probe-$name.out"
		echo "StandardError=file:$W/probe-$name.out"
		echo "ExecStart=/bin/bash $W/probe-$name.sh"
	} > "/run/systemd/system/pwprobe-$name.service"
	systemctl daemon-reload
	: > "$W/probe-$name.out"
	timeout 180 systemctl start "pwprobe-$name.service" > /dev/null 2>&1
	PROBE_OUT=$(cat "$W/probe-$name.out")
	rm -f "/run/systemd/system/pwprobe-$name.service"
}

scn_S5() {
	begin S5 "kill feature under the hardened unit; CAP_KILL dropped"
	fresh kill
	if ! start_service; then
		fail "S5.0 service did not start with kill.enabled: $(svc_state)"
		journal_tail 30
		end
		return
	fi
	local f="$W/s5.jsonl" v1 v2 sv n got t0 pid typ ref a1 a2 want
	slice "$f"
	got=$(jl "$f" -r 'select(.event_type=="agent.started") | "enabled=\(.details.kill.enabled) rules=\(.details.kill.rules) fields=\(.details.kill.fields|join(","))"' | sed -n 1p)
	assert_eq S5.1 "agent.started: kill configuration" "$got" "enabled=true rules=2 fields=image"

	# --- part A: victims of uid 1000 beneath a watched root of uid 0
	mark
	t0=$(up)
	kill_victims pwkillstr-victim pwkillre7 || fail "S5.2 the victims did not start"
	v1=$(cat "$T/pwkillstr-victim.pid")
	v2=$(cat "$T/pwkillre7.pid")
	sv=$(cat "$T/survivor.pid")
	# one more watched root that also matches the kill string: roots are never killed
	"$T/pwwatch-pwkillstr" 3 &
	local rootmatch=$!
	if wait_until 60 proc_gone "$v1" && wait_until 60 proc_gone "$v2"; then
		pass "S5.2 both victims (uid 1000, pids $v1 and $v2) are gone $(since "$t0") s after their tree started"
	else
		fail "S5.2 a victim is still alive after 60 s: $(ps -o pid=,uid=,stat=,comm= -p "$v1,$v2" | tr '\n' ';')"
	fi
	wait_until 30 kill_results_ge 2
	wait "$rootmatch" 2> /dev/null
	sleep 2
	slice "$f"
	for n in "$v1:string:kill.strings[0]" "$v2:regex:kill.regex[0]"; do
		pid=${n%%:*}
		typ=${n#*:}
		ref=${typ#*:}
		typ=${typ%%:*}
		got=$(jl "$f" -r "select(.event_type==\"response.kill_requested\" and .process.pid==$pid) | \"\(.details.outcome) \(.details.action) \(.details.signal) \(.details.rules[0].type) \(.details.rules[0].field) \(.details.rules[0].ref) uid=\(.process.uid)\"" | sed -n 1p)
		assert_eq S5.3 "victim $pid: response.kill_requested" "$got" "pending kill SIGKILL $typ image $ref uid=1000"
		got=$(jl "$f" -r "select(.event_type==\"response.kill_result\" and .process.pid==$pid) | \"\(.details.outcome) \(.details.reason) \(.process.image)\"" | sed -n 1p)
		case $typ in string) want="signal_sent null pwkillstr-victim" ;; *) want="signal_sent null pwkillre7" ;; esac
		assert_eq S5.4 "victim $pid: response.kill_result outcome" "$got" "$want"
		a1=$(jl "$f" -r "select(.event_type==\"response.kill_requested\" and .process.pid==$pid) | .details.action_id" | sed -n 1p)
		a2=$(jl "$f" -r "select(.event_type==\"response.kill_result\" and .process.pid==$pid) | .details.action_id" | sed -n 1p)
		if [ -n "$a1" ] && [ "$a1" = "$a2" ]; then pass "S5.5 victim $pid: request and result share action_id $a1"; else fail "S5.5 victim $pid: action_id request=$a1 result=$a2"; fi
		n=$(jl "$f" -r "select(.event_type==\"response.kill_requested\" or .event_type==\"response.kill_result\") | select(.process.pid==$pid) | .sequence" | tr '\n' ' ')
		# shellcheck disable=SC2086
		set -- $n
		if [ $# -eq 2 ] && [ "$1" -lt "$2" ]; then pass "S5.6 victim $pid: kill_requested (sequence $1) was written before kill_result ($2)"; else fail "S5.6 victim $pid: audit order/count wrong: $n"; fi
		got=$(jl "$f" -r "select(.event_type==\"process.exit\" and .process.pid==$pid) | \"signal=\(.details.signal) action=\(.details.response_action_id)\"" | sed -n 1p)
		assert_eq S5.7 "victim $pid: process.exit shows SIGKILL and the action id" "$got" "signal=9 action=$a1"
		jl "$f" -r "select(.event_type==\"response.kill_result\" and .process.pid==$pid) | \"latency: kernel exec event to signal \(((.details.attempt_latency_ns|tonumber)/1000000)|floor) ms (decision \(((.details.decision_latency_ns|tonumber)/1000000)|floor) ms)\"" | sed -n 1p | ev
	done
	if proc_gone "$sv"; then fail "S5.8 the unmatched descendant (sleep, pid $sv) was killed"; else pass "S5.8 an unmatched descendant (sleep, pid $sv) was left alone"; fi
	kill "$sv" 2> /dev/null
	wait "$KROOT" 2> /dev/null
	wait_until 30 exit_logged "$KROOT"
	slice "$f"
	got=$(jl "$f" -r "select(.event_type==\"process.exit\" and .process.pid==$KROOT) | \"exit_code=\(.details.exit_code) signal=\(.details.signal)\"" | sed -n 1p)
	assert_eq S5.9 "the watched root itself ends by its own: process.exit" "$got" "exit_code=0 signal=null"
	n=$(jl "$f" -r "select(.event_type|startswith(\"response.\")) | select(.process.pid==$rootmatch) | .event_type" | wc -l | tr -d ' ')
	got=$(jl "$f" -r "select(.event_type==\"process.exit\" and .process.pid==$rootmatch) | \"exit_code=\(.details.exit_code) signal=\(.details.signal) responses=$n\"" | sed -n 1p)
	assert_eq S5.10 "a root that matches the kill string is never a target (no response events, exits by itself)" "$got" "exit_code=0 signal=null responses=0"
	assert_true S5.11 "the service is still active (running)" svc_running

	# --- part B: CAP_KILL dropped by a drop-in
	dropin cap-merge $'[Service]\nCapabilityBoundingSet=CAP_BPF CAP_PERFMON CAP_SYS_RESOURCE CAP_SYS_PTRACE'
	got=$(systemctl show -p CapabilityBoundingSet --value "$UNIT_NAME")
	if grep -q cap_kill <<< "$got"; then
		pass "S5.12 a drop-in that only lists capabilities ADDS to the unit's set (CAP_KILL stays); the empty assignment is needed first"
	else
		fail "S5.12 expected CAP_KILL to stay in the set after a drop-in without the empty reset assignment, got: $got"
	fi
	rm -f "$DROPIN_DIR/cap-merge.conf"
	dropin nokill $'[Service]\nCapabilityBoundingSet=\nCapabilityBoundingSet=CAP_BPF CAP_PERFMON CAP_SYS_RESOURCE CAP_SYS_PTRACE'
	if ! start_service restart; then
		fail "S5.13 service did not restart without CAP_KILL: $(svc_state)"
		journal_tail 30
		remove_dropins
		end
		return
	fi
	pid=$(prop MainPID)
	got=$(cap_names "$(status_field "$pid" CapBnd)")
	assert_eq S5.13 "CapBnd after the drop-in" "$got" "cap_bpf cap_perfmon cap_sys_ptrace cap_sys_resource"
	mark
	kill_victims pwkillstr-victim || fail "S5.14 the victim did not start"
	v1=$(cat "$T/pwkillstr-victim.pid")
	sv=$(cat "$T/survivor.pid")
	wait_until 30 kill_results_ge 1
	sleep 1
	slice "$f"
	got=$(jl "$f" -r "select(.event_type==\"response.kill_result\" and .process.pid==$v1) | \"\(.details.outcome) errno=\(.details.error.errno) op=\(.details.error.op) uid=\(.process.uid)\"" | sed -n 1p)
	assert_eq S5.14 "victim $v1 (uid 1000): response.kill_result without CAP_KILL" "$got" "permission_denied errno=EPERM op=pidfd_send_signal uid=1000"
	if proc_gone "$v1"; then fail "S5.15 the victim is gone although the agent has no CAP_KILL"; else pass "S5.15 the victim of another user is still alive (the kernel refused the signal)"; fi
	# the observation continues
	local mid
	mark
	"$T/pwwatch-bash" -c '/usr/bin/true; /usr/bin/uname -s > /dev/null' &
	mid=$!
	wait "$mid"
	sleep 2
	slice "$f"
	got=$(jl "$f" -r "select(.event_type==\"process.exec\" and .root.pid==$mid and .lineage.role==\"descendant\") | .process.image" | sort | tr '\n' ' ' | sed 's/ $//')
	assert_eq S5.16 "observation continues after the denied kill: exec events of a new tree" "$got" "true uname"
	wait_until 20 bash -c "grep '\"event_type\":\"agent.health\"' '$LOG' | tail -n 1 | grep -q '\"permission_denied\":[1-9]'"
	got=$(jq -r 'select(.event_type=="agent.health") | .details.response | "permission_denied=\(.permission_denied) signal_attempts=\(.signal_attempts) signals_accepted=\(.signals_accepted)"' "$LOG" | tail -n 1)
	info "S5 last agent.health response counters: $got"
	assert_true S5.17 "the service is still active (running)" svc_running
	# doctor inside the same sandbox, without CAP_KILL, with --kill-enabled
	local props
	mapfile -t props < <(sandbox_lines)
	probe doctor-nokill "${props[@]}" -- "$BIN doctor --config $CFG --kill-enabled; echo RC=\$?"
	printf '%s\n' "$PROBE_OUT" | grep -E 'CAP_KILL|pidfd|RC=' | ev
	if grep -q 'CAP_KILL.*permitted' <<< "$PROBE_OUT"; then
		warn "S5.18 doctor --kill-enabled reports CAP_KILL as permitted although CAP_KILL is not in the capability set (it only checks euid 0): doctor cannot warn about a missing CAP_KILL when running as root"
	else
		pass "S5.18 doctor --kill-enabled notices the missing CAP_KILL"
	fi
	kill -9 "$v1" "$sv" 2> /dev/null
	wait "$KROOT" 2> /dev/null
	stop_service
	remove_dropins
	end
}

# ======================================================================================
# S6: clean stop
# ======================================================================================
scn_S6() {
	begin S6 "systemctl stop: clean exit, agent.stopped, no restart"
	fresh base
	if ! start_service; then
		fail "S6.0 service did not start: $(svc_state)"
		journal_tail 30
		end
		return
	fi
	# a watched root that is still running when the agent stops
	"$T/pwwatch-bash" -c '/usr/bin/sleep 600; :' &
	local live=$! pid t0 dt rc jb jtxt got
	sleep 2
	pid=$(prop MainPID)
	jb=$(journal | wc -l)
	t0=$(up)
	timeout 120 systemctl stop "$UNIT_NAME"
	rc=$?
	dt=$(since "$t0")
	info "S6 systemctl stop took $dt s: $(svc_state)"
	assert_eq S6.1 "systemctl stop exit status" "$rc" 0
	assert_eq S6.2 "ActiveState" "$(prop ActiveState)" inactive
	assert_eq S6.3 "Result" "$(prop Result)" success
	assert_eq S6.4 "ExecMainStatus (exit status of the agent)" "$(prop ExecMainStatus)" 0
	assert_eq S6.6 "NRestarts" "$(prop NRestarts)" 0
	if [ ! -d "/proc/$pid" ]; then pass "S6.7 the agent process (pid $pid) is gone"; else fail "S6.7 the agent process (pid $pid) still exists"; fi
	if awk -v d="$dt" 'BEGIN { exit !(d < 25) }'; then
		pass "S6.8 stopped in $dt s, far below TimeoutStopSec=30s"
	else
		fail "S6.8 stop took $dt s (TimeoutStopSec=30s)"
	fi
	jtxt=$(journal | tail -n +$((jb + 1)))
	printf '%s\n' "$jtxt" | evn 12
	if grep -q 'Deactivated successfully' <<< "$jtxt"; then pass "S6.5 the journal says the unit deactivated successfully (the agent exited with status 0 after SIGTERM)"; else fail "S6.5 no 'Deactivated successfully' in the journal"; fi
	if grep -qiE 'timed out|Killing process|SIGKILL|Failed with result' <<< "$jtxt"; then
		fail "S6.9 the journal shows a timeout, a kill or a failed result during the stop"
	else
		pass "S6.9 no timeout, kill or failure in the journal during the stop"
	fi
	got=$(tail -n 1 "$LOG" | jq -r '"\(.event_type) reason=\(.details.reason) error=\(.details.error) lost=\(.details.collector.lost_total)"')
	assert_eq S6.10 "the last line of the log" "$got" "agent.stopped reason=signal error=null lost=0"
	if jq -e . "$LOG" > /dev/null 2>&1; then pass "S6.11 every line of the log is valid JSON (no torn line)"; else fail "S6.11 the log contains an invalid line"; fi
	sleep 8
	assert_eq S6.12 "still inactive 8 s later, no restart pending (ActiveState/NRestarts)" "$(prop ActiveState)/$(prop NRestarts)" inactive/0
	kill "$live" 2> /dev/null
	wait "$live" 2> /dev/null
	end
}

# ======================================================================================
# S7: failure behaviour
# ======================================================================================
# restart_gaps: seconds between the "Scheduled restart job" lines of the journal
# journal_since <uptime>: the journal lines of the unit that are newer than that uptime
journal_since() { journal | awk -v t0="$1" '{ t = $0; sub(/^\[ */, "", t); sub(/\].*/, "", t); if (t + 0 >= t0) print }'; }
# restart_gaps [uptime]: seconds between the scheduled restarts, since that uptime (default: boot)
restart_gaps() {
	journal_since "${1:-0}" | sed -n 's/^\[ *\([0-9.]*\)\].*Scheduled restart job.*/\1/p' | awk 'NR>1 {printf "%.1f ", $1-prev} {prev=$1}' | sed 's/ $//'
}
# pause_snapshot: succeeds while the unit waits for its scheduled restart and leaves its properties in SNAP
# (snap_prop <name> reads one). Only in that pause is ExecMainStatus the exit status of the last run; once the
# restarted agent runs again it reads 0. It is ONE systemctl call, so that SubState, NRestarts and
# ExecMainStatus belong to the same moment: separate calls can straddle the restart, which is slow under
# emulation (a check that read them one by one failed on amd64 under TCG).
pause_snapshot() {
	SNAP=$(systemctl show -p SubState -p Result -p ExecMainStatus -p NRestarts "$UNIT_NAME" 2> /dev/null)
	grep -q '^SubState=auto-restart$' <<< "$SNAP"
}
snap_prop() { sed -n "s/^$1=//p" <<< "$SNAP"; }

scn_S7a() {
	begin S7a "invalid configuration (unknown key): exit code 2, no flapping"
	fresh badkey
	rm -f "$LOG"
	local t0 n gaps
	t0=$(up)
	timeout 120 systemctl start "$UNIT_NAME" > "$W/s7a.start" 2>&1
	info "S7a systemctl start: exit status $?; $(tr '\n' ' ' < "$W/s7a.start")"
	sleep 30
	n=$(prop NRestarts)
	info "S7a after $(since "$t0") s: $(svc_state)"
	journal | evn 14
	gaps=$(restart_gaps)
	[ -n "$gaps" ] && info "S7a seconds between restarts: $gaps"
	assert_eq S7a.1 "NRestarts after about 30 s" "$n" 0
	assert_eq S7a.2 "ActiveState (the unit stays failed)" "$(prop ActiveState)" failed
	assert_eq S7a.3 "Result" "$(prop Result)" exit-code
	assert_true S7a.4 "exit status 2 (INVALIDARGUMENT) in the journal" bash -c "journalctl -u $UNIT_NAME --no-pager | grep -q 'status=2/INVALIDARGUMENT'"
	assert_true S7a.5 "the journal names the offending key (bogus_key)" bash -c "journalctl -u $UNIT_NAME --no-pager | grep -q bogus_key"
	if [ ! -e "$LOG" ]; then pass "S7a.6 the agent never touched the log (it stopped before starting)"; else fail "S7a.6 a log file exists: $(wc -l < "$LOG") line(s)"; fi

	# control: the same bad configuration with ExecStartPre=check-config
	stop_service
	dropin execstartpre "[Service]
ExecStartPre=$BIN check-config --config $CFG"
	t0=$(up)
	timeout 120 systemctl start "$UNIT_NAME" > "$W/s7a.start2" 2>&1
	info "S7a control (ExecStartPre=check-config): systemctl start exit status $?; $(tr '\n' ' ' < "$W/s7a.start2" | cut -c1-200)"
	sleep 20
	n=$(prop NRestarts)
	gaps=$(restart_gaps)
	info "S7a control after $(since "$t0") s: $(svc_state); seconds between restarts: $gaps"
	if [ "$n" -ge 3 ]; then
		pass "S7a.7 control: with ExecStartPre=check-config the bad configuration is restarted $n times in 20 s although RestartPreventExitStatus=2 3 is set (it only looks at the main process); this is why the unit has no ExecStartPre="
	else
		warn "S7a.7 control: ExecStartPre=check-config did not flap here (NRestarts=$n); the reason for omitting ExecStartPre= may be obsolete on this systemd"
	fi
	stop_service
	remove_dropins
	# recovery after the configuration is fixed
	write_config base
	rm -f "$LOG"
	if start_service; then
		pass "S7a.8 after the configuration is fixed, systemctl start brings the service up again"
	else
		fail "S7a.8 the service did not start after the configuration was fixed: $(svc_state)"
	fi
	stop_service
	end
}

scn_S7b() {
	begin S7b "outputs.file.path outside /var/log/process-watcher"
	local p t0 n st el max gaps jtxt min
	mkdir -p /srv/pwlogs
	for p in /root/events.jsonl /srv/pwlogs/events.jsonl; do
		fresh base
		write_config base "$p"
		rm -f "$p"
		t0=$(up)
		timeout 120 systemctl start "$UNIT_NAME" > /dev/null 2>&1
		sleep 22
		# sample in the pause before a restart, in one call: a restarted agent that is running again
		# would read ExecMainStatus=0 (that made this check flaky on slow CPUs)
		wait_until 15 pause_snapshot
		n=$(snap_prop NRestarts)
		st=$(snap_prop ExecMainStatus)
		el=$(since "$t0")
		gaps=$(restart_gaps "$t0")
		jtxt=$(journal_since "$t0") # this path only, not what the previous one left in the journal
		info "S7b path $p after $el s: SubState=$(snap_prop SubState) Result=$(snap_prop Result) ExecMainStatus=$st NRestarts=$n; seconds between restarts: $gaps"
		printf '%s\n' "$jtxt" | grep -E 'process-watcher\[|Scheduled restart|Main process exited|Failed with' | sed -n 1,8p | ev
		assert_eq S7b.1 "$p: exit status of the agent" "$st" 1
		if grep -q 'status=1/FAILURE' <<< "$jtxt"; then pass "S7b.2 $p: the journal shows status=1/FAILURE"; else fail "S7b.2 $p: no status=1/FAILURE in the journal"; fi
		if grep -E 'process-watcher\[' <<< "$jtxt" | grep -q "open local log"; then
			pass "S7b.3 $p: the journal message names the cause: $(grep -E 'process-watcher\[' <<< "$jtxt" | sed -n 's/.*error="\(.*\)"$/\1/p' | sed -n 1p)"
		else
			fail "S7b.3 $p: no understandable 'open local log' message in the journal"
		fi
		max=$(awk -v e="$el" 'BEGIN { printf "%d", e / 5 }') # one restart per RestartSec at most
		if [ "$n" -ge 2 ] && [ "$n" -le "$max" ]; then
			pass "S7b.4 $p: bounded restart loop, NRestarts=$n in $el s (RestartSec=5s)"
		else
			fail "S7b.4 $p: NRestarts=$n in $el s is outside 2..$max"
		fi
		min=$(printf '%s\n' "$gaps" | tr ' ' '\n' | grep -v '^$' | sort -n | sed -n 1p)
		if [ -n "$min" ] && awk -v m="$min" 'BEGIN { exit !(m >= 5.0) }'; then
			pass "S7b.5 $p: the restarts are at least RestartSec=5s apart (shortest gap $min s)"
		else
			fail "S7b.5 $p: restarts closer than RestartSec (gaps: $gaps)"
		fi
		stop_service
	done
	# the documented fix: ReadWritePaths= for the other log directory
	fresh base
	dropin logdir $'[Service]\nReadWritePaths=/srv/pwlogs'
	LOG=/srv/pwlogs/events.jsonl
	write_config base "$LOG"
	rm -f "$LOG" "$LOG.lock"
	if start_service; then
		pass "S7b.6 with the drop-in ReadWritePaths=/srv/pwlogs the agent starts and logs to /srv/pwlogs/events.jsonl"
	else
		fail "S7b.6 the drop-in did not fix it: $(svc_state)"
		journal_tail 20
	fi
	assert_eq S7b.7 "/srv/pwlogs/events.jsonl mode" "$(stat -c '%a %U:%G' "$LOG" 2> /dev/null)" "600 root:root"
	stop_service
	LOG=$LOGDIR/events.jsonl
	remove_dropins
	rm -rf /srv/pwlogs
	end
}

scn_S7c() {
	begin S7c "SIGKILL of the main process: restart after RestartSec with a new agent_instance_id"
	fresh base
	if ! start_service; then
		fail "S7c.0 service did not start: $(svc_state)"
		journal_tail 30
		end
		return
	fi
	local pid1 pid2 id1 id2 t0 dt n f="$W/s7c.jsonl"
	pid1=$(prop MainPID)
	id1=$(jq -r 'select(.event_type=="agent.started") | .agent_instance_id' "$LOG" | tail -n 1)
	mark
	t0=$(up)
	kill -KILL "$pid1"
	wait_until 90 bash -c "[ \"\$(systemctl show -p MainPID --value $UNIT_NAME)\" != $pid1 ] && [ \"\$(systemctl show -p ActiveState --value $UNIT_NAME)\" = active ]"
	dt=$(since "$t0")
	wait_until 60 log_has '"event_type":"agent.ready"'
	pid2=$(prop MainPID)
	slice "$f"
	id2=$(jl "$f" -r 'select(.event_type=="agent.started") | .agent_instance_id' | sed -n 1p)
	info "S7c killed pid $pid1 (instance $id1); restarted as pid $pid2 (instance $id2) $dt s later; $(svc_state)"
	journal | grep -E 'Main process exited|Failed with|Scheduled restart|Started|Stopped' | tail -n 6 | ev
	if [ "$pid2" != "$pid1" ] && [ "$pid2" != 0 ] && svc_running; then pass "S7c.1 the service was restarted (new main pid $pid2, active (running))"; else fail "S7c.1 no restart: $(svc_state)"; fi
	if [ -n "$id2" ] && [ "$id2" != "$id1" ]; then pass "S7c.2 a new agent.started with a new agent_instance_id ($id2, before: $id1)"; else fail "S7c.2 no agent.started with a new instance id (before=$id1 after=$id2)"; fi
	if awk -v d="$dt" 'BEGIN { exit !(d >= 4.5) }'; then pass "S7c.3 the restart came $dt s after the kill (RestartSec=5s)"; else fail "S7c.3 the restart came after only $dt s"; fi
	assert_eq S7c.4 "NRestarts" "$(prop NRestarts)" 1
	n=$(jq -r "select(.event_type==\"agent.stopped\" and .agent_instance_id==\"$id1\") | .event_type" "$LOG" | wc -l | tr -d ' ')
	assert_eq S7c.5 "the killed run wrote no agent.stopped (it had no chance to)" "$n" 0
	if jq -e . "$LOG" > /dev/null 2>&1; then pass "S7c.6 every line of the log is valid JSON after the kill, and the new run opened the log (no stale lock)"; else fail "S7c.6 the log contains an invalid line after the kill"; fi
	stop_service
	end
}

scn_S7d() {
	begin S7d "missing privileges: exit code 3, no restart"
	fresh base
	rm -f "$LOG"
	dropin nobpf $'[Service]\nCapabilityBoundingSet=\nCapabilityBoundingSet=CAP_SYS_RESOURCE CAP_SYS_PTRACE CAP_KILL'
	local t0 jtxt
	t0=$(up)
	timeout 120 systemctl start "$UNIT_NAME" > "$W/s7d.start" 2>&1
	sleep 14
	jtxt=$(journal)
	info "S7d after $(since "$t0") s: $(svc_state)"
	printf '%s\n' "$jtxt" | grep -E 'process-watcher\[|Main process exited|Failed with|Scheduled restart|Started' | sed -n 1,8p | ev
	assert_eq S7d.1 "exit status of the agent" "$(prop ExecMainStatus)" 3
	assert_eq S7d.2 "NRestarts (RestartPreventExitStatus=3)" "$(prop NRestarts)" 0
	assert_eq S7d.3 "ActiveState" "$(prop ActiveState)" failed
	assert_eq S7d.4 "Result" "$(prop Result)" exit-code
	if grep -q 'status=3/NOTIMPLEMENTED' <<< "$jtxt"; then pass "S7d.5 the journal shows status=3/NOTIMPLEMENTED"; else fail "S7d.5 no status=3 in the journal"; fi
	if grep -E 'process-watcher\[' <<< "$jtxt" | grep -qi 'privileges'; then
		pass "S7d.6 the journal names the cause: $(grep -E 'process-watcher\[' <<< "$jtxt" | sed -n 's/.*error="\(.*\)"$/\1/p' | sed -n 1p | cut -c1-160)"
	else
		fail "S7d.6 the journal does not mention privileges"
	fi
	if [ ! -s "$LOG" ] || ! grep -q '"event_type":"agent.started"' "$LOG"; then pass "S7d.7 no agent.started was logged (the agent never ran)"; else fail "S7d.7 the agent logged agent.started"; fi
	stop_service
	remove_dropins
	end
}

# ======================================================================================
# S8: the hardening directives one by one: in effect, and compatible with the agent
# ======================================================================================
declare -A EFF COMPAT

case $(uname -m) in
x86_64)
	SYS_DELETE_MODULE=176
	SYS_CLOCK_SETTIME=227
	;;
aarch64)
	SYS_DELETE_MODULE=106
	SYS_CLOCK_SETTIME=112
	;;
*)
	SYS_DELETE_MODULE=0
	SYS_CLOCK_SETTIME=0
	;;
esac

hex2bin() {
	local h=$1 i
	for ((i = 0; i < ${#h}; i += 2)); do printf "\\x${h:i:2}"; done
}

# make_foreign_elf <file>: a 96 byte static executable of the OTHER word size (i386 on an
# x86-64 guest, 32 bit ARM on an arm64 guest) that exits with status 0; used to show that
# SystemCallArchitectures=native refuses system calls of a non-native ABI
make_foreign_elf() {
	case $(uname -m) in
	x86_64)
		{
			hex2bin 7f454c46010101000000000000000000   # e_ident: ELF32, little endian
			hex2bin 02000300 01000000 54800408 34000000 # EXEC, i386, version, entry 0x08048054, phoff
			hex2bin 00000000 00000000 3400 2000 0100 0000 0000 0000
			hex2bin 01000000 00000000 00800408 00800408 60000000 60000000 05000000 00100000
			hex2bin b801000000 bb00000000 cd80          # mov eax,1; mov ebx,0; int 0x80
		} > "$1"
		;;
	aarch64)
		{
			hex2bin 7f454c46010101000000000000000000
			hex2bin 02002800 01000000 54000100 34000000 # EXEC, ARM, version, entry 0x10054, phoff
			hex2bin 00000000 00000005 3400 2000 0100 0000 0000 0000 # e_flags: EABI5
			hex2bin 01000000 00000000 00000100 00000100 60000000 60000000 05000000 00100000
			hex2bin 0170a0e3 0000a0e3 000000ef          # mov r7,#1; mov r0,#0; svc #0
		} > "$1"
		;;
	esac
	chmod 0755 "$1"
}

# effect <name> <Property=value> <what> <script printing RC=<n>>: the action succeeds (RC=0) in a
# plain oneshot unit and is refused (RC!=0) in one with the property
effect() {
	local name=$1 propv=$2 what=$3 script=$4 c h cd hd
	probe "ctl-$name" -- "$script"
	cd=$PROBE_OUT
	c=$(sed -n 's/^RC=//p' <<< "$cd" | tail -n 1)
	probe "on-$name" "$propv" -- "$script"
	hd=$PROBE_OUT
	h=$(sed -n 's/^RC=//p' <<< "$hd" | tail -n 1)
	if [ "$c" = 0 ] && [ -n "$h" ] && [ "$h" != 0 ]; then
		EFF[$name]="enforced ($what: allowed without, refused with: RC=$h)"
		pass "S8.$name $propv is enforced: $what is allowed without it (RC=0) and refused with it (RC=$h)"
		return 0
	fi
	EFF[$name]="NOT shown (control RC=$c, with RC=$h)"
	fail "S8.$name $propv: $what: control RC='$c', with the property RC='$h'"
	printf '%s\n' "control:" "$cd" "with $propv:" "$hd" | ev
	return 1
}

scn_S8() {
	begin S8 "the hardening directives one by one: in effect and compatible"
	if ! { svc_running && [ "$CONFIG_IN_USE" = base ] && [ ! -d "$DROPIN_DIR" ]; }; then
		fresh base
		start_service || {
			fail "S8.0 service did not start: $(svc_state)"
			journal_tail 30
			end
			return
		}
	fi
	local pid out
	pid=$(prop MainPID)
	local d
	d=$(sed -n 's/^\([A-Za-z]*\)=.*/\1/p' "$UNIT_FILE" | sort -u | tr '\n' ' ')
	info "S8 directives in the unit: $d"
	nsx() { nsenter -t "$pid" -m -- "$@"; }

	# --- in the mount namespace of the running agent ---
	out=$(nsx sh -c 'for d in /etc /usr /var/lib /opt /boot; do touch $d/pwprobe 2>&1 && echo "$d is writable"; done')
	printf '%s\n' "$out" | ev
	if ! grep -q 'writable' <<< "$out" && [ "$(grep -c 'Read-only file system' <<< "$out")" -ge 4 ]; then
		EFF[ProtectSystem]="enforced (touch in /etc /usr /var/lib /opt: Read-only file system)"
		pass "S8.ProtectSystem ProtectSystem=strict is enforced in the agent's mount namespace: /etc /usr /var/lib /opt are read-only"
	else
		EFF[ProtectSystem]="NOT shown"
		fail "S8.ProtectSystem a system directory is writable for the agent"
	fi
	if nsx sh -c "touch '$LOGDIR/pwprobe' && rm -f '$LOGDIR/pwprobe'" > /dev/null 2>&1; then
		pass "S8.LogsDirectory $LOGDIR stays writable for the agent although the rest is read-only"
		EFF[LogsDirectory]="enforced (writable exception inside ProtectSystem=strict, mode 0700 by S3.17)"
	else
		fail "S8.LogsDirectory $LOGDIR is not writable in the agent's mount namespace"
		EFF[LogsDirectory]="NOT shown"
	fi
	out=$(nsx sh -c 'a=$(ls -A /root 2> /dev/null | wc -l); b=$(ls -A /home 2> /dev/null | wc -l); echo $((a + b)); stat -c "/root mode %a" /root')
	if [ "$(sed -n 1p <<< "$out")" = 0 ] && [ -n "$(ls -A /root)" ]; then
		EFF[ProtectHome]="enforced (/root and /home are empty and inaccessible for the agent, $(ls -A /root | wc -l) entries on the host)"
		pass "S8.ProtectHome ProtectHome=yes is enforced: /root is empty for the agent ($(sed -n 2p <<< "$out")), the host sees $(ls -A /root | wc -l) entries"
	else
		EFF[ProtectHome]="NOT shown"
		fail "S8.ProtectHome the agent can see /root or /home: $out"
	fi
	if [ -e "$T/pwwatch-sleep" ] && ! nsx test -e "$T/pwwatch-sleep"; then
		EFF[PrivateTmp]="enforced (the host's $T is not visible to the agent)"
		pass "S8.PrivateTmp PrivateTmp=yes is enforced: $T exists on the host and is invisible to the agent"
		nsx grep ' /tmp ' /proc/self/mountinfo | cut -c1-200 | ev
	else
		EFF[PrivateTmp]="NOT shown"
		fail "S8.PrivateTmp the agent sees the host's /tmp"
	fi
	if nsx mkdir /sys/fs/cgroup/pwprobe > /dev/null 2>&1; then
		rmdir /sys/fs/cgroup/pwprobe 2> /dev/null
		EFF[ProtectControlGroups]="NOT shown"
		fail "S8.ProtectControlGroups the agent can create a cgroup"
	elif ! mkdir /sys/fs/cgroup/pwprobe 2> /dev/null; then
		EFF[ProtectControlGroups]="control failed"
		fail "S8.ProtectControlGroups cannot create a cgroup on the host either (control failed)"
	else
		rmdir /sys/fs/cgroup/pwprobe
		EFF[ProtectControlGroups]="enforced (mkdir in /sys/fs/cgroup: Read-only file system; allowed on the host)"
		pass "S8.ProtectControlGroups ProtectControlGroups=yes is enforced: /sys/fs/cgroup is read-only for the agent, writable on the host"
	fi

	# --- one directive at a time in a plain oneshot unit (full capabilities, no other sandbox) ---
	effect NoNewPrivileges NoNewPrivileges=yes "gaining privileges (NoNewPrivs flag 0)" \
		'[ "$(sed -n "s/^NoNewPrivs:[[:space:]]*//p" /proc/self/status)" = 0 ]; echo RC=$?'
	effect ProtectKernelModules ProtectKernelModules=yes "delete_module(2) reaching the module code" \
		"perl -e '\$m = \"pwnomodule\"; \$f = 0; \$r = syscall($SYS_DELETE_MODULE + 0, \$m, \$f); \$e = \$! + 0; print \"delete_module: ret=\$r errno=\$e\\n\"; exit(\$e == 2 ? 0 : \$e)'; echo RC=\$?"
	effect ProtectClock ProtectClock=yes "clock_settime(2) reaching the clock code" \
		"perl -e '\$ts = \"\\0\" x 16; \$r = syscall($SYS_CLOCK_SETTIME + 0, 99 + 0, \$ts); \$e = \$! + 0; print \"clock_settime(99): ret=\$r errno=\$e\\n\"; exit(\$e == 22 ? 0 : \$e)'; echo RC=\$?"
	effect RestrictNamespaces RestrictNamespaces=yes "unshare(CLONE_NEWUTS)" 'unshare -u true; echo RC=$?'
	effect RestrictRealtime RestrictRealtime=yes "SCHED_FIFO" 'chrt -f 1 true; echo RC=$?'
	effect RestrictSUIDSGID RestrictSUIDSGID=yes "chmod u+s" 'f=$(mktemp); chmod u+s "$f"; rc=$?; rm -f "$f"; echo RC=$rc'
	effect LockPersonality LockPersonality=yes "personality(ADDR_NO_RANDOMIZE)" 'setarch -R true; echo RC=$?'
	make_foreign_elf "$T/pwforeign"
	probe ctl-foreign -- "$T/pwforeign; echo RC=\$?"
	if [ "$(sed -n 's/^RC=//p' <<< "$PROBE_OUT" | tail -n 1)" = 0 ]; then
		effect SystemCallArchitectures SystemCallArchitectures=native "a system call of the non-native ABI ($(uname -m) guest, $([ "$(uname -m)" = x86_64 ] && echo i386 || echo AArch32) binary)" "$T/pwforeign; echo RC=\$?"
	else
		EFF[SystemCallArchitectures]="not testable (the guest cannot run a non-native binary: $(tr '\n' ' ' <<< "$PROBE_OUT" | cut -c1-100))"
		warn "S8.SystemCallArchitectures not testable: this guest cannot execute a binary of the non-native ABI"
	fi
	out=$(sed -n 's/^UMask=//p' "$UNIT_FILE")
	assert_eq S8.UMask "the agent's umask (UMask=$out)" "$(status_field "$pid" Umask)" "$out"
	EFF[UMask]="enforced (Umask: $(status_field "$pid" Umask) in /proc/$pid/status)"
	EFF[CapabilityBoundingSet]="enforced (CapBnd $(status_field "$pid" CapBnd) = $(cap_names "$(status_field "$pid" CapBnd)"))"
	EFF[NoNewPrivileges]="${EFF[NoNewPrivileges]:-}; NoNewPrivs: $(status_field "$pid" NoNewPrivs) in /proc/$pid/status"

	# --- the same sandbox around doctor: the check INSTALL.md recommends before adding a directive ---
	local props
	mapfile -t props < <(sandbox_lines)
	probe doctor "${props[@]}" -- "$BIN doctor --config $CFG --kill-enabled --kill-string pwx-none; echo RC=\$?"
	printf '%s\n' "$PROBE_OUT" | ev
	assert_eq S8.doctor "doctor --kill-enabled inside the unit's sandbox (all directives together): exit status" "$(sed -n 's/^RC=//p' <<< "$PROBE_OUT" | tail -n 1)" 0

	# --- verdict per directive ---
	local s all='' dir
	for s in S3 S4 S5 S6; do
		case ${RESULT[$s]:-notrun} in PASS) all+="$s " ;; FAIL) all+="$s(FAILED) " ;; *) all+="$s(not run) " ;; esac
	done
	COMPAT[NoNewPrivileges]="S3.9; $all"
	COMPAT[ProtectSystem]="S3.17-18 (log written), S7b (any other log directory needs ReadWritePaths=); $all"
	COMPAT[ProtectHome]="S4.14 (a program below /root is observed with its path); $all"
	COMPAT[PrivateTmp]="S4 and S5 (programs in the host's /tmp are observed, signalled and verified); $all"
	COMPAT[ProtectKernelModules]="$all"
	COMPAT[ProtectControlGroups]="$all"
	COMPAT[ProtectClock]="$all"
	COMPAT[RestrictNamespaces]="$all"
	COMPAT[RestrictRealtime]="$all"
	COMPAT[RestrictSUIDSGID]="$all"
	COMPAT[LockPersonality]="$all"
	COMPAT[SystemCallArchitectures]="$all"
	COMPAT[LogsDirectory]="S3.17-19 (0700 root, log 0600), S7b.6; $all"
	COMPAT[UMask]="S3.11; $all"
	COMPAT[CapabilityBoundingSet]="S3.7-8 (CapBnd = unit), S5.13-15 (CAP_KILL dropped: permission_denied, observation continues), S7d (BPF/PERFMON dropped: exit 3); $all"
	info "S8 table (directive: in effect | compatible with the agent in):"
	for dir in NoNewPrivileges ProtectSystem ProtectHome PrivateTmp ProtectKernelModules ProtectControlGroups ProtectClock RestrictNamespaces RestrictRealtime RestrictSUIDSGID LockPersonality SystemCallArchitectures LogsDirectory UMask CapabilityBoundingSet; do
		printf '%-24s | %s | %s\n' "$dir" "${EFF[$dir]:-not tested}" "${COMPAT[$dir]}"
	done | ev
	end
}

# ======================================================================================
main() {
	trap finish EXIT
	say "BEGIN process-watcher systemd test; scenarios: ${PW_SCENARIOS:-all}; $(systemctl --version | head -n 1); kernel $(uname -r) $(uname -m)"
	# this unit is part of the boot transaction: keep systemd's status lines out of the log
	kill -s RTMIN+21 1 2> /dev/null
	scn_S2
	selected S1 && scn_S1
	selected S3 && scn_S3
	selected S4 && scn_S4
	selected S5 && scn_S5
	selected S6 && scn_S6
	selected S7a && scn_S7a
	selected S7b && scn_S7b
	selected S7c && scn_S7c
	selected S7d && scn_S7d
	selected S8 && scn_S8
}

FINISHED=0
finish() {
	[ "$FINISHED" -eq 1 ] && return
	FINISHED=1
	stop_service > /dev/null 2>&1
	rm -rf "${DROPIN_DIR:?}"
	pkill -9 -f 'pwwatch|pwkill' 2> /dev/null
	wait 2> /dev/null
	local s
	for s in S1 S2 S3 S4 S5 S6 S7a S7b S7c S7d S8; do
		[ -n "${RESULT[$s]:-}" ] && say "SUMMARY $s ${RESULT[$s]}"
	done
	say "TOTAL: $NPASS passed, $NFAIL failed"
	echo
	echo "PW-VM-EXIT=$NFAIL"
	sync
	echo o > /proc/sysrq-trigger
	sleep 5
	echo b > /proc/sysrq-trigger
	sleep 5
}

main
exit 0
