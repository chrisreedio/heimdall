#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Install the Heimdall collector on a Linux server, in one step.
#
#   curl -fsSLO https://github.com/chrisreedio/heimdall/releases/download/vX.Y.Z/install.sh &&
#     sudo sh install.sh --hub https://ingest.example.com
#   (then paste the token when asked; it's never echoed, logged or put on a
#   command line)
#
# What it does (as root):
#   1. downloads collect.sh and the systemd units from the SAME GitHub
#      release and verifies them against SHA256SUMS (and SHA256SUMS'
#      Sigstore signature when cosign is installed). Never from the hub.
#   2. creates the unprivileged `heimdall` user, installs the token (0400)
#      and /etc/heimdall/collect.env
#   3. schedules an hourly push (systemd timer, or cron without systemd), a
#      push a minute after packages change (a systemd path unit, or apk/apt
#      hooks) and, with systemd, one 3 minutes after boot. Then it runs the
#      first push. Re-running it (as `heimdall-collect upgrade` does)
#      refreshes all of this.
set -eu
umask 022
export LC_ALL=C
PATH=/usr/sbin:/usr/bin:/sbin:/bin

HEIMDALL_VERSION=dev # set by `make dist`
RELEASES=${HEIMDALL_RELEASES:-https://github.com/chrisreedio/heimdall/releases/download}

die() { printf 'heimdall install: %s\n' "$*" >&2; exit 1; }
say() { printf '==> %s\n' "$*" >&2; }
have() { command -v "$1" >/dev/null 2>&1; }

usage() {
	cat >&2 <<'EOF'
usage: install.sh --hub https://ingest.example.com [--token-stdin | --token-file FILE]
                  [--version vX.Y.Z] [--from-dir DIR] [--no-push]
                  [--sites "/srv/app ..."] [--lockfiles "/srv/app/package-lock.json ..."]
                  [--watch-privilege [--watch-privilege-users] | --no-watch-privilege]

  --hub          the hub's ingest URL (https://)
  (default)      prompt for the ingest token on the terminal, without echo
  --token-stdin  read the ingest token from stdin (for automation, e.g. cloud-init)
  --token-file   read the ingest token from a file
  --version      release to install (default: the release this script came from)
  --from-dir     install from a local directory holding the release files (air-gapped)
  --no-push      don't push a first snapshot
  --watch-privilege        record when sudo, su or a root SSH login happens (time
                           and kind only; never commands); see docs/collector.md
  --watch-privilege-users  also record who (implies --watch-privilege)
  --no-watch-privilege     remove the privilege watch
  (re-running keeps the current privilege watch choice)
EOF
	exit 2
}

token_given=0 hub='' token='' version=$HEIMDALL_VERSION from_dir='' push=1 sites='' lockfiles='' privilege=''
while [ $# -gt 0 ]; do
	case $1 in
	--hub) hub=${2:-}; shift ;;
	--token-stdin) IFS= read -r token || [ -n "$token" ]; token_given=1 ;;
	--token-file) [ -r "${2:-}" ] || die "cannot read ${2:-}"; token=$(tr -d ' \t\r\n' <"$2"); token_given=1; shift ;;
	--version) version=${2:-}; shift ;;
	--from-dir) from_dir=${2:-}; shift ;;
	--no-push) push=0 ;;
	--sites) sites=${2:-}; shift ;;
	--lockfiles) lockfiles=${2:-}; shift ;;
	--watch-privilege) [ "$privilege" = users ] || privilege=on ;;
	--watch-privilege-users) privilege=users ;;
	--no-watch-privilege) privilege=off ;;
	-h | --help) usage ;;
	*) usage ;;
	esac
	shift
done

[ "$(id -u)" -eq 0 ] || die "run as root (sudo)"
if [ "$token_given" = 0 ]; then
	[ -t 0 ] || die "no terminal to ask for the token; use --token-stdin or --token-file"
	printf 'Ingest token (from "heimdall host add" or the Add host page): ' >&2
	stty -echo 2>/dev/null || true
	IFS= read -r token || true
	stty echo 2>/dev/null || true
	printf '\n' >&2
fi
case $hub in
https://*) ;;
http://127.0.0.1[:/]* | http://localhost[:/]*) ;; # tests and local proxies
*) die "--hub must be an https:// URL" ;;
esac
token=$(printf '%s' "$token" | tr -d ' \t\r\n')
case $token in
hmd_ingest_*) ;;
*) die "missing or malformed token (--token-stdin or --token-file)" ;;
esac
case $token in *[!A-Za-z0-9_-]*) die "malformed token" ;; esac
case $version in v[0-9]*.[0-9]*.[0-9]* | dev) ;; *) die "bad --version $version" ;; esac
[ -n "$from_dir" ] || [ "$version" != dev ] || die "this script isn't from a release; pass --version vX.Y.Z or --from-dir"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fetch() { # fetch NAME into $work
	if [ -n "$from_dir" ]; then
		cp "$from_dir/$1" "$work/$1" || die "missing $from_dir/$1"
	elif have curl; then
		curl -fsSL --proto '=https' --tlsv1.2 -o "$work/$1" "$RELEASES/$version/$1" || die "download failed: $1"
	elif have wget; then
		wget -q -O "$work/$1" "$RELEASES/$version/$1" || die "download failed: $1"
	else
		die "need curl or wget"
	fi
}

say "Fetching Heimdall collector $version"
units='heimdall-collect.service heimdall-collect.timer heimdall-collect-soon.timer heimdall-collect-changes.service heimdall-collect-changes.path'
for f in SHA256SUMS collect.sh $units privilege-watch.sh privilege-hook; do fetch "$f"; done
if fetch_sig=$(fetch SHA256SUMS.sigstore.json 2>/dev/null && echo ok) && [ "$fetch_sig" = ok ] && have cosign; then
	say "Verifying the Sigstore signature on SHA256SUMS"
	cosign verify-blob "$work/SHA256SUMS" --bundle "$work/SHA256SUMS.sigstore.json" \
		--certificate-identity-regexp '^https://github.com/chrisreedio/heimdall/\.github/workflows/release\.yml@refs/tags/v' \
		--certificate-oidc-issuer https://token.actions.githubusercontent.com >/dev/null 2>&1 ||
		die "SHA256SUMS signature verification FAILED"
fi
say "Verifying checksums"
# Check exactly the files fetched above; each one must be listed.
for f in collect.sh $units; do
	awk -v f="$f" '$2 == f { print; found = 1 } END { exit !found }' "$work/SHA256SUMS" ||
		die "$f isn't in SHA256SUMS; not installing"
done >"$work/check"
(cd "$work" && sha256sum -c check >/dev/null) || die "checksum verification FAILED; not installing"

say "Installing"
# On the hub's own box /etc/heimdall belongs to the hub; never touch it.
conf=/etc/heimdall
[ ! -e /etc/heimdall/heimdall.toml ] || conf=/etc/heimdall-collect
# Re-runs (and `heimdall-collect upgrade`) keep the privilege watch choice.
[ -n "$privilege" ] || privilege=$(sed -n 's/^HEIMDALL_PRIVILEGE_WATCH=//p' "$conf/collect.env" 2>/dev/null | tail -n 1)
case $privilege in on | users | off) ;; *) privilege='' ;; esac
install -m 0755 "$work/collect.sh" /usr/local/bin/heimdall-collect
if ! id heimdall >/dev/null 2>&1; then
	if have useradd; then
		useradd --system --no-create-home --shell /usr/sbin/nologin heimdall
	else
		adduser -S -D -H -s /sbin/nologin heimdall # Alpine/busybox
	fi
fi
install -d -m 0700 -o heimdall "$conf"
old_umask=$(umask)
umask 077
printf '%s\n' "$token" >"$conf/token"
umask "$old_umask"
chown heimdall "$conf/token"
chmod 0400 "$conf/token"
{
	printf 'HEIMDALL_URL=%s\n' "$hub"
	printf 'HEIMDALL_TOKEN_FILE=%s\n' "$conf/token"
	[ -z "$sites" ] || printf "HEIMDALL_SITES='%s'\n" "$sites"
	[ -z "$lockfiles" ] || printf "HEIMDALL_LOCKFILES='%s'\n" "$lockfiles"
	[ -z "$privilege" ] || printf 'HEIMDALL_PRIVILEGE_WATCH=%s\n' "$privilege"
} >"$conf/collect.env"
chmod 0644 "$conf/collect.env"

# Root runs these, so they live in a root-owned directory, not in $conf
# (which the heimdall user owns). The push itself reads collect.env as heimdall.
lib=/usr/local/lib/heimdall-collect
apt_hook=/etc/apt/apt.conf.d/80heimdall-collect
apk_hook=/etc/apk/commit_hooks.d/heimdall-collect
if [ -d /run/systemd/system ] && have systemctl; then
	sed "s#/etc/heimdall/collect.env#$conf/collect.env#" "$work/heimdall-collect.service" >/etc/systemd/system/heimdall-collect.service
	for f in heimdall-collect.timer heimdall-collect-soon.timer heimdall-collect-changes.service; do
		install -m 0644 "$work/$f" /etc/systemd/system/
	done
	# Report after package changes: watch only the databases this box has.
	# (A comment line right above a PathChanged= line goes with it.)
	watching=0 note=
	while IFS= read -r line; do
		case $line in
		'# '*) [ -z "$note" ] || printf '%s\n' "$note"; note=$line; continue ;;
		PathChanged=*)
			if [ ! -e "${line#PathChanged=}" ]; then note=; continue; fi
			watching=1
			;;
		esac
		[ -z "$note" ] || printf '%s\n' "$note"
		note=
		printf '%s\n' "$line"
	done <"$work/heimdall-collect-changes.path" >"$work/changes.path"
	if [ "$watching" = 1 ]; then
		install -m 0644 "$work/changes.path" /etc/systemd/system/heimdall-collect-changes.path
	else
		systemctl disable --now heimdall-collect-changes.path >/dev/null 2>&1 || true
		rm -f /etc/systemd/system/heimdall-collect-changes.path
	fi
	# Left from a non-systemd install:
	rm -rf "$apt_hook" "$apk_hook" "$lib" /etc/periodic/daily/heimdall-collect /etc/cron.daily/heimdall-collect \
		/etc/periodic/hourly/heimdall-collect /etc/cron.hourly/heimdall-collect
	systemctl daemon-reload
	systemctl enable --now heimdall-collect.timer >/dev/null 2>&1
	scheduler="systemd timer (hourly, and 3 minutes after boot)"
	if [ "$watching" = 1 ]; then
		systemctl enable heimdall-collect-changes.path >/dev/null 2>&1
		systemctl restart heimdall-collect-changes.path # picks up a changed watch list
		scheduler="$scheduler, and a minute after packages change"
	fi
	run_now() { systemctl start heimdall-collect.service; }
else
	# No systemd (e.g. Alpine/OpenRC, containers): an hourly cron job, plus
	# apk/apt hooks that report a minute after packages change.
	install -d -m 0755 "$lib"
	cat >"$lib/cron.sh" <<EOF
#!/bin/sh
# Heimdall: push a report as the heimdall user. Run as root by cron (hourly,
# after a random delay of up to 15 minutes) and by soon.sh (--now). Written by install.sh.
[ "\${1:-}" = --now ] || sleep "\$(awk 'BEGIN { srand(); print int(rand() * 900) }')"
exec su -s /bin/sh heimdall -c 'set -a; . $conf/collect.env; set +a; exec /usr/local/bin/heimdall-collect --push'
EOF
	cat >"$lib/soon.sh" <<'EOF'
#!/bin/sh
# Heimdall: push a report about a minute after the LAST package change, in
# the background. Run as root by the apk and apt hooks (and deploy scripts).
# It returns at once and never fails, so it can't block or break them.
# Written by install.sh.
lock=/run/heimdall-collect-soon
quiet=60
if [ "${1:-}" = --wait ]; then
	echo $$ >"$lock/pid"
	while :; do
		last=$(cat "$lock/last" 2>/dev/null) || last=0
		case $last in '' | *[!0-9]*) last=0 ;; esac
		age=$(($(date +%s) - last))
		[ "$age" -lt "$quiet" ] || break
		sleep $((quiet - age))
	done
	# Unlock first: a change during the push starts a new countdown.
	rm -rf "$lock"
	if command -v logger >/dev/null 2>&1; then
		/usr/local/lib/heimdall-collect/cron.sh --now 2>&1 | logger -t heimdall-collect
	else
		/usr/local/lib/heimdall-collect/cron.sh --now
	fi
	exit 0
fi
{
	if ! mkdir "$lock"; then
		pid=$(cat "$lock/pid") || pid=
		if [ -n "$pid" ] && kill -0 "$pid"; then
			date +%s >"$lock/last" # a countdown is running: push it back
			exit 0
		fi
		if [ -z "$pid" ] && [ -z "$(find "$lock" -maxdepth 0 -mmin +1)" ]; then
			date +%s >"$lock/last" # a countdown is just starting
			exit 0
		fi
		rm -rf "$lock" # left by a countdown that died
		mkdir "$lock" || exit 0
	fi
	date +%s >"$lock/last"
	if command -v setsid >/dev/null; then
		setsid /usr/local/lib/heimdall-collect/soon.sh --wait &
	else
		/usr/local/lib/heimdall-collect/soon.sh --wait &
	fi
} </dev/null >/dev/null 2>&1
exit 0
EOF
	chmod 0755 "$lib/cron.sh" "$lib/soon.sh"
	rm -f "$conf/cron.sh" # before 0.4.12 it lived here
	rm -f /etc/periodic/daily/heimdall-collect /etc/cron.daily/heimdall-collect # daily before 0.4.13
	if [ -d /etc/periodic/hourly ]; then
		ln -sf "$lib/cron.sh" /etc/periodic/hourly/heimdall-collect
	elif [ -d /etc/cron.hourly ]; then
		ln -sf "$lib/cron.sh" /etc/cron.hourly/heimdall-collect
	else
		die "no systemd and no cron.hourly directory; schedule $lib/cron.sh yourself"
	fi
	scheduler="cron (hourly)"
	if [ -d /etc/apk ]; then
		install -d -m 0755 /etc/apk/commit_hooks.d
		cat >"$apk_hook" <<EOF
#!/bin/sh
# Heimdall: report about a minute after packages change. Written by install.sh.
[ "\$1" = post-commit ] || exit 0
[ ! -x $lib/soon.sh ] || $lib/soon.sh
exit 0
EOF
		chmod 0755 "$apk_hook"
		scheduler="$scheduler, and a minute after apk changes packages"
	fi
	if [ -d /etc/apt/apt.conf.d ]; then
		cat >"$apt_hook" <<EOF
// Heimdall: report about a minute after packages change. Written by install.sh.
DPkg::Post-Invoke { "[ ! -x $lib/soon.sh ] || $lib/soon.sh || true"; };
EOF
		chmod 0644 "$apt_hook"
		scheduler="$scheduler, and a minute after apt changes packages"
	fi
	run_now() { "$lib/cron.sh" --now; }
fi
case $privilege in
on | users) sh "$work/privilege-watch.sh" install "$work/privilege-hook" "$privilege" ;;
off) sh "$work/privilege-watch.sh" remove ;;
esac
have curl || say "WARNING: curl is required for pushing; install it (e.g. apk add curl)"

if [ "$push" = 1 ]; then
	say "Sending the first snapshot"
	run_now || die "first push failed; check the hub URL and token (see docs/collector.md)"
fi
say "Done: reporting to $hub via $scheduler."
