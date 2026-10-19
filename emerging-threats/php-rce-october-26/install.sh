#!/bin/sh
# process-watcher PHP kit: installs process-watcher and watches what the PHP processes on this host start.
#
#   curl -fsSL https://raw.githubusercontent.com/Neo23x0/process-watcher/main/emerging-threats/php-rce-october-26/install.sh | sudo sh
#
# This script is short on purpose: read it before you run it (download it with curl -fsSLO and open it), and
# use "sh install.sh --plan" to see what it would do without changing anything.
#
# What it does:
#   1. finds the PHP processes that are running (PHP-FPM, Apache mod_php, php-cgi, PHP CLI) by the executable of
#      every process in /proc, the same name the agent matches on
#   2. downloads the release archive of process-watcher for this machine and checks it against the SHA256SUMS
#      of the same release (this protects against a damaged download, not against a compromised release)
#   3. unpacks it to /opt/process-watcher and starts it in the background with the matching configuration of the
#      archive, in OBSERVE mode: it logs what PHP starts and kills nothing
#
# What it touches: /opt/process-watcher (the unpacked release) and /var/log/process-watcher (the event log and
# the agent log). No service, no cron job, no sysctl or firewall change; while it runs, the agent loads its
# observation-only eBPF programs into the kernel, as it always does. Undo: sh install.sh --stop, then remove
# those two directories.
#
# A configuration that really sends SIGKILL is only started with --config NAME --allow-kill, never by detection.

set -eu
umask 022
PATH=$PATH:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

REPO=Neo23x0/process-watcher
SCRIPT_URL=https://raw.githubusercontent.com/$REPO/main/emerging-threats/php-rce-october-26/install.sh
BASE_URL=${PW_BASE_URL:-https://github.com/$REPO/releases/download}
VERSION=${PW_VERSION:-}
INSTALL_DIR=${PW_INSTALL_DIR:-/opt/process-watcher}
PROC=${PW_PROC:-/proc} # only tests point this elsewhere
LOG_DIR=/var/log/process-watcher
LOG=$LOG_DIR/events.jsonl
AGENT_LOG=$LOG_DIR/agent.log

usage() {
	cat <<'EOF'
Usage: sh install.sh [options]

Finds the PHP processes running on this host, installs process-watcher and starts it in the background, watching
what they start. Observe only: nothing is killed unless you ask for it with --config and --allow-kill.

  --plan            show what would happen and change nothing
  --stop            stop the agent that this script started
  --foreground      run the agent in the foreground instead of the background
  --version TAG     install this release (default: the latest)
  --config NAME     use php/NAME.yaml of the release (for example php-fpm-dry-run) instead of detection
  --allow-kill      required for a configuration that really sends SIGKILL
  --watch NAME      watch executables whose name contains NAME (repeatable); replaces detection

Environment: PW_VERSION, PW_BASE_URL (a mirror of the release downloads; needs PW_VERSION), PW_INSTALL_DIR
(default /opt/process-watcher).
EOF
}

die() {
	printf 'install.sh: %s\n' "$*" >&2
	exit 1
}
say() { printf '%s\n' "$*"; }
note() { printf '  %-14s %s\n' "$1" "$2"; }
nap() { sleep 0.2 2>/dev/null || sleep 1; }
valid_word() {
	case $1 in '' | *[!A-Za-z0-9._-]*) return 1 ;; esac
	return 0
}

PLAN=0 STOP=0 FOREGROUND=0 ALLOW_KILL=0 CONFIG='' WATCH=''
while [ $# -gt 0 ]; do
	case $1 in
	--plan) PLAN=1 ;;
	--stop) STOP=1 ;;
	--foreground) FOREGROUND=1 ;;
	--allow-kill) ALLOW_KILL=1 ;;
	--version | --config | --watch)
		[ $# -ge 2 ] || die "$1 needs a value (try --help)"
		valid_word "$2" || die "invalid value for $1: $2"
		case $1 in
		--version) VERSION=$2 ;;
		--config) CONFIG=${2%.yaml} ;;
		--watch) WATCH=${WATCH:+$WATCH }$2 ;;
		esac
		shift
		;;
	-h | --help)
		usage
		exit 0
		;;
	*) die "unknown option: $1 (try --help)" ;;
	esac
	shift
done
[ -z "$VERSION" ] || valid_word "$VERSION" || die "invalid version: $VERSION"

# PIDs of the agents started from INSTALL_DIR: the exe link of such a process points into it.
agent_pids() {
	for exe in "$PROC"/[0-9]*/exe; do
		target=$(readlink "$exe" 2>/dev/null) || continue
		target=${target%" (deleted)"}
		case $target in
		"$INSTALL_DIR"/process-watcher_*/process-watcher)
			pid=${exe#"$PROC"/}
			echo "${pid%/exe}"
			;;
		esac
	done
}

# the PIDs on one line
pids_joined() { agent_pids | awk 'NR > 1 {printf " "} {printf "%s", $0}'; }

stop_agents() {
	pids=$(agent_pids)
	if [ -z "$pids" ]; then
		say "process-watcher from $INSTALL_DIR is not running"
		return 0
	fi
	shown=$(pids_joined)
	for p in $pids; do kill -TERM "$p" 2>/dev/null || true; done
	i=0
	while [ $i -lt 100 ] && [ -n "$(agent_pids)" ]; do
		nap
		i=$((i + 1))
	done
	[ -z "$(agent_pids)" ] || die "the agent did not stop within 20 seconds (pid $shown); kill -KILL it if needed"
	say "stopped (pid $shown)"
}

if [ "$STOP" -eq 1 ]; then
	stop_agents
	exit 0
fi

# Which kinds of PHP run here? The name is the executable of the process (what the agent calls its image),
# not the process title that ps shows.
detect() {
	FPM='' CGI='' MODPHP='' CLI='' APACHE='' CLIPAT=''
	for exe in "$PROC"/[0-9]*/exe; do
		target=$(readlink "$exe" 2>/dev/null) || continue
		target=${target%" (deleted)"}
		name=${target##*/}
		pid=${exe#"$PROC"/}
		pid=${pid%/exe}
		case $name in
		php-fpm*) [ -n "$FPM" ] || FPM="$name (pid $pid)" ;;
		php-cgi*) [ -n "$CGI" ] || CGI="$name (pid $pid)" ;;
		apache2 | httpd)
			# mod_php has no php process: the module is mapped into Apache itself. Apache that forwards to
			# PHP-FPM is covered by watching php-fpm.
			if [ -z "$MODPHP" ] && grep -q libphp "$PROC/$pid/maps" 2>/dev/null; then
				MODPHP="$name with mod_php (pid $pid)"
				APACHE=$name
			fi
			;;
		php | php[0-9]*)
			if [ -z "$CLI" ]; then
				CLI="$name (pid $pid)"
				case $name in *.*) CLIPAT=${name%%.*}. ;; *) CLIPAT=$name ;; esac
			fi
			;;
		esac
	done
}

# What to watch, and which configuration of the release to start from.
choose() {
	WATCH_AUTO='' BASE=''
	if [ -n "$FPM" ]; then
		WATCH_AUTO=${WATCH_AUTO:+$WATCH_AUTO }php-fpm
		BASE=${BASE:-php-fpm-observe}
	fi
	if [ -n "$MODPHP" ]; then
		WATCH_AUTO=${WATCH_AUTO:+$WATCH_AUTO }$APACHE
		BASE=${BASE:-apache-mod-php}
	fi
	if [ -n "$CGI" ]; then
		WATCH_AUTO=${WATCH_AUTO:+$WATCH_AUTO }php-cgi
		BASE=${BASE:-php-cgi}
	fi
	if [ -n "$CLI" ]; then
		WATCH_AUTO=${WATCH_AUTO:+$WATCH_AUTO }$CLIPAT
		BASE=${BASE:-php-cli-workers}
	fi
}

detect
choose
if [ -n "$CONFIG" ]; then
	# an explicit configuration is used as it is, unless --watch replaces its list
	MODE="php/$CONFIG.yaml"
	WATCH_FINAL=$WATCH
	WATCH_SHOWN=${WATCH:-as listed in the configuration}
elif [ -n "$WATCH" ]; then
	MODE="php/php-fpm-observe.yaml with your --watch list"
	BASE=php-fpm-observe
	WATCH_FINAL=$WATCH
	WATCH_SHOWN=$WATCH
elif [ -n "$BASE" ]; then
	MODE="php/$BASE.yaml (observe only, nothing is killed)"
	WATCH_FINAL=$WATCH_AUTO
	WATCH_SHOWN=$WATCH_AUTO
else
	MODE="none"
	WATCH_FINAL=''
	WATCH_SHOWN=nothing
fi

show_plan() {
	say "process-watcher PHP kit"
	if [ -n "$VERSION" ]; then note "version" "$VERSION"; else note "version" "the latest release (looked up when you run it)"; fi
	case $(uname -m) in x86_64 | amd64) a=amd64 ;; aarch64 | arm64) a=arm64 ;; *) a="$(uname -m) (not supported)" ;; esac
	note "download" "$BASE_URL/${VERSION:-<version>}/process-watcher_${VERSION:-<version>}_linux_$a.tar.gz"
	note "install to" "$INSTALL_DIR/process-watcher_${VERSION:-<version>}_linux_$a (current points to it)"
	label="PHP found"
	for found in "$FPM" "$MODPHP" "$CGI" "$CLI"; do
		[ -z "$found" ] || {
			note "$label" "$found"
			label=""
		}
	done
	[ "$label" = "" ] || note "$label" "none"
	note "watching" "$WATCH_SHOWN"
	note "configuration" "$MODE"
	note "events" "$LOG"
}

if [ "$PLAN" -eq 1 ]; then
	show_plan
	[ "$(id -u)" -eq 0 ] || say "(not running as root: processes of other users may be missing from the list above)"
	[ -n "$WATCH_FINAL" ] || [ -n "$CONFIG" ] || say "A real run would stop here: no PHP process was found. Start PHP first, or use --watch NAME."
	say "Plan only: nothing was changed."
	exit 0
fi

[ "$(uname -s)" = Linux ] || die "Linux only"
[ "$(id -u)" -eq 0 ] || die "run as root: curl -fsSL $SCRIPT_URL | sudo sh"
for tool in curl tar sha256sum awk grep readlink mktemp install; do
	command -v "$tool" >/dev/null 2>&1 || die "missing tool: $tool"
done
case $(uname -m) in x86_64 | amd64) ARCH=amd64 ;; aarch64 | arm64) ARCH=arm64 ;; *) die "unsupported architecture $(uname -m): process-watcher supports amd64 and arm64" ;; esac
[ -n "$WATCH_FINAL" ] || [ -n "$CONFIG" ] || die "no PHP process found, nothing to watch. Start PHP first, or use --watch NAME (for example --watch php-fpm)."

running=$(agent_pids)
if [ -n "$running" ]; then
	say "process-watcher from $INSTALL_DIR is already running (pid $running)."
	say "Stop it first with: sh install.sh --stop"
	exit 0
fi

show_plan
say ""

if [ -z "$VERSION" ]; then
	[ -z "${PW_BASE_URL:-}" ] || die "PW_BASE_URL needs PW_VERSION (or --version)"
	url=$(curl --proto '=https' --tlsv1.2 -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest" </dev/null) ||
		die "cannot look up the latest release"
	VERSION=${url##*/}
	valid_word "$VERSION" || die "unexpected release tag: $VERSION"
	say "latest release: $VERSION"
fi
NAME=process-watcher_${VERSION}_linux_$ARCH

tmp=$(mktemp -d "${TMPDIR:-/tmp}/pw-install.XXXXXX") || die "cannot create a temporary directory"
trap 'rm -rf "$tmp"' EXIT INT TERM HUP
proto='=https'
case $BASE_URL in http://*)
	proto='=http,https'
	say "warning: downloading over plain http from $BASE_URL"
	;;
esac
get() { curl --proto "$proto" --tlsv1.2 -fsSL -o "$2" "$1" </dev/null || die "download failed: $1"; }
get "$BASE_URL/$VERSION/$NAME.tar.gz" "$tmp/$NAME.tar.gz"
get "$BASE_URL/$VERSION/SHA256SUMS" "$tmp/SHA256SUMS"

awk -v n="$NAME.tar.gz" '$2 == n' "$tmp/SHA256SUMS" >"$tmp/one.sum"
[ "$(wc -l <"$tmp/one.sum")" -eq 1 ] || die "$NAME.tar.gz is not listed exactly once in SHA256SUMS"
(cd "$tmp" && sha256sum -c one.sum >/dev/null 2>&1) || die "checksum mismatch for $NAME.tar.gz: nothing was installed"
say "checksum ok"

mkdir "$tmp/x"
tar -xzf "$tmp/$NAME.tar.gz" -C "$tmp/x" || die "cannot unpack $NAME.tar.gz"
[ -x "$tmp/x/$NAME/process-watcher" ] || die "the archive has no $NAME/process-watcher"
[ -d "$tmp/x/$NAME/php" ] || die "release $VERSION has no php/ directory of configurations (try a newer release with --version)"

mkdir -p "$INSTALL_DIR"
chmod 755 "$INSTALL_DIR"
DEST=$INSTALL_DIR/$NAME
if [ -e "$DEST" ]; then
	case $DEST in "$INSTALL_DIR"/process-watcher_v*_linux_*) rm -rf "$DEST" ;; *) die "refusing to replace $DEST" ;; esac
fi
mv "$tmp/x/$NAME" "$DEST"
ln -sfn "$DEST" "$INSTALL_DIR/current"
say "installed: $DEST"

if ! out=$("$DEST/process-watcher" doctor 2>&1 </dev/null); then
	printf '%s\n' "$out" >&2
	die "doctor found a problem (see above); the agent was not started"
fi
say "doctor: all required checks passed"

[ -n "$CONFIG" ] || CONFIG=$BASE
CFG=$DEST/php/$CONFIG.yaml
[ -f "$CFG" ] || die "this release has no php/$CONFIG.yaml (see $DEST/php/)"
if awk '/^kill:/ {k = 1; next} /^[^ #]/ {k = 0} k && /^[ ]+enabled:[ ]*true/ {e = 1} k && /^[ ]+dry_run:[ ]*false/ {d = 1} END {exit !(e && d)}' "$CFG"; then
	[ "$ALLOW_KILL" -eq 1 ] || die "php/$CONFIG.yaml really sends SIGKILL to what matches its rules. Run php-fpm-dry-run first and read the guide, then add --allow-kill."
	say "warning: php/$CONFIG.yaml sends SIGKILL to matching processes (--allow-kill)"
fi

set -- --config "$CFG" --log-file "$LOG"
for w in $WATCH_FINAL; do set -- "$@" --watch-image-contains "$w"; done
"$DEST/process-watcher" check-config "$@" >/dev/null </dev/null || die "the configuration check failed: $DEST/process-watcher check-config $*"

install -d -m 0700 "$LOG_DIR"
if [ "$FOREGROUND" -eq 1 ]; then
	say "starting in the foreground, stop with Ctrl-C"
	rm -rf "$tmp"
	exec "$DEST/process-watcher" "$@"
fi

before=0
[ ! -f "$LOG" ] || before=$(wc -c <"$LOG")
nohup "$DEST/process-watcher" "$@" >>"$AGENT_LOG" 2>&1 </dev/null &
pid=$!
READY=0 i=0
while [ $i -lt 150 ] && kill -0 "$pid" 2>/dev/null; do
	if [ -f "$LOG" ] && tail -c "+$((before + 1))" "$LOG" 2>/dev/null | grep -q '"event_type":"agent.ready"'; then
		READY=1
		break
	fi
	nap
	i=$((i + 1))
done
if [ "$READY" -ne 1 ]; then
	say "the agent did not become ready; the end of $AGENT_LOG:"
	tail -n 20 "$AGENT_LOG" 2>/dev/null || true
	die "not started"
fi

say ""
say "process-watcher is running (pid $(pids_joined)), watching: ${WATCH_FINAL:-the list in the configuration}"
note "events" "$LOG"
note "agent log" "$AGENT_LOG"
note "stop" "sh install.sh --stop    (or: curl -fsSL $SCRIPT_URL | sudo sh -s -- --stop)"
