#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Install the Heimdall collector on a Linux server, in one step.
#
#   curl -fsSLO https://github.com/realmwatch/heimdall/releases/download/vX.Y.Z/install.sh &&
#     sudo sh install.sh --hub https://ingest.example.com
#   (then paste the token when asked; it's never echoed, logged or put on a
#   command line). For many servers, use an enrollment key instead of a
#   token: --enroll (prompt) or --enroll-stdin. Each server gets its own
#   token from the hub.
#
# What it does (as root):
#   1. downloads collect.sh and the systemd units from the SAME GitHub
#      release and verifies them against SHA256SUMS (and SHA256SUMS'
#      Sigstore signature, checked with a pinned cosign). Never from the hub.
#   2. creates the unprivileged `heimdall` user, installs the token (0400)
#      and /etc/heimdall/collect.env
#   3. schedules an hourly push (systemd timer, or cron without systemd), a
#      push a minute after packages change (a systemd path unit, or apk/apt
#      hooks), with systemd one a minute after a site deploys (the sites it
#      finds now, and `heimdall-collect deployed`) and one 3 minutes after
#      boot. Then it runs the
#      first push. Re-running it (as `heimdall-collect upgrade` does)
#      refreshes all of this.
set -eu
umask 022
export LC_ALL=C
PATH=/usr/sbin:/usr/bin:/sbin:/bin

HEIMDALL_VERSION=dev # set by `make dist`
RELEASES=${HEIMDALL_RELEASES:-https://github.com/realmwatch/heimdall/releases/download}

die() { printf 'heimdall install: %s\n' "$*" >&2; exit 1; }
say() { printf '==> %s\n' "$*" >&2; }
have() { command -v "$1" >/dev/null 2>&1; }

# ── Release signature ── (keep this block the same in collect.sh, install.sh
# and install-hub.sh; the pins are also in cmd/heimdall/signature.go and
# install-windows.ps1, and TestSignaturePinsMatch checks they agree.)
# A release's SHA256SUMS must carry a Sigstore signature made by this repo's
# release workflow for a v* tag. cosign checks it: a pinned build, fetched
# once into /usr/local/lib/heimdall and checked against its hash each use.
COSIGN_VERSION=v3.1.4
RELEASE_SIGNER='^https://github.com/realmwatch/heimdall/\.github/workflows/release\.yml@refs/tags/v'

# cosign_bin: print the path of the cosign to check signatures with,
# fetching the pinned build first if it's missing or doesn't match.
cosign_bin() {
	case $(uname -m) in
	x86_64 | amd64) c=amd64 s=424e2c97d0b45fd7a6b608a87f090f35633f4c23ece5f092d48bba11aaf4bbfa ;;
	aarch64 | arm64) c=arm64 s=ade83b7aac62e131cacfe96d958948b2150cc9efec46a570a2649b8e27dedad2 ;;
	armv7l) c=arm s=09e77a313910cf5c4774508d85d017d9c60983f41bf657f83ecbd3892f7952cb ;;
	*) command -v cosign; return ;; # no pinned build: an installed cosign, if any
	esac
	b=/usr/local/lib/heimdall/cosign-$COSIGN_VERSION-$c
	if [ ! -x "$b" ] || ! printf '%s  %s\n' "$s" "$b" | sha256sum -c - >/dev/null 2>&1; then
		printf '==> Fetching cosign %s (once) to check the release signature\n' "$COSIGN_VERSION" >&2
		u=https://github.com/sigstore/cosign/releases/download/$COSIGN_VERSION/cosign-linux-$c
		install -d -m 0755 /usr/local/lib/heimdall
		if command -v curl >/dev/null 2>&1; then
			curl -fsSL --proto '=https' --tlsv1.2 -o "$b.tmp" "$u" || return 1
		else
			wget -q -O "$b.tmp" "$u" || return 1
		fi
		if ! printf '%s  %s\n' "$s" "$b.tmp" | sha256sum -c - >/dev/null 2>&1; then
			rm -f "$b.tmp"
			echo "the cosign download doesn't match its pinned hash" >&2
			return 1
		fi
		chmod 0755 "$b.tmp" && mv "$b.tmp" "$b"
	fi
	echo "$b"
}

# verify_release DIR: check DIR/SHA256SUMS against its Sigstore signature
# (DIR/SHA256SUMS.sigstore.json), or exit.
verify_release() {
	[ -s "$1/SHA256SUMS.sigstore.json" ] || die "the release has no signature (SHA256SUMS.sigstore.json); not installing it"
	cosign=$(cosign_bin) || cosign=''
	[ -n "$cosign" ] || die "can't check the release signature: no cosign for $(uname -m); install cosign, or pass --skip-signature-check"
	HOME=$1 "$cosign" verify-blob "$1/SHA256SUMS" --bundle "$1/SHA256SUMS.sigstore.json" \
		--certificate-identity-regexp "$RELEASE_SIGNER" \
		--certificate-oidc-issuer https://token.actions.githubusercontent.com >"$1/cosign.log" 2>&1 ||
		die "SHA256SUMS signature verification FAILED; not installing it: $(tail -n 1 "$1/cosign.log")"
	printf '==> Sigstore signature verified\n' >&2
}

usage() {
	cat >&2 <<'EOF'
usage: install.sh --hub https://ingest.example.com [--token-stdin | --token-file FILE |
                                                    --enroll | --enroll-stdin]
                  [--version vX.Y.Z] [--from-dir DIR] [--no-push]
                  [--sites "/srv/app ..."] [--lockfiles "/srv/app/package-lock.json ..."]
                  [--watch-privilege [--watch-privilege-users] | --no-watch-privilege]
                  [--watch-logins | --no-watch-logins] [--skip-signature-check]

  --hub          the hub's ingest URL (https://)
  (default)      prompt for the ingest token on the terminal, without echo
  --token-stdin  read the ingest token from stdin (for automation, e.g. cloud-init)
  --token-file   read the ingest token from a file
  --enroll       prompt for an enrollment key (from "heimdall enroll create" or
                 the Add servers page), without echo; the hub adds this server
                 and gives it its own token. A server that already has a token
                 keeps it.
  --enroll-stdin read the enrollment key from stdin (ssh loops, cloud-init)
  --version      release to install (default: the release this script came from)
  --from-dir     install from a local directory holding the release files (air-gapped)
  --no-push      don't push a first snapshot
  --watch-privilege        record when sudo, su or a root SSH login happens (time
                           and kind only; never commands); see docs/collector.md
  --watch-privilege-users  also record who, and the IP the session came from
                           (implies --watch-privilege)
  --no-watch-privilege     remove the privilege watch
  --watch-logins           count failed SSH logins per source address (counts
                           only; never usernames); see docs/failed-logins.md
  --no-watch-logins        remove the login watch
  --skip-signature-check   don't check the release's Sigstore signature, only
                           its checksums (where cosign can't run; not advised)
  (re-running keeps the current privilege and login watch choices)
EOF
	exit 2
}

token_given=0 hub='' token='' enroll='' awaiting=0 name='' version=$HEIMDALL_VERSION from_dir='' push=1 sites='' lockfiles='' privilege='' logins='' sigcheck=1
while [ $# -gt 0 ]; do
	case $1 in
	--hub) hub=${2:-}; shift ;;
	--token-stdin) IFS= read -r token || [ -n "$token" ]; token_given=1 ;;
	--token-file) [ -r "${2:-}" ] || die "cannot read ${2:-}"; token=$(tr -d ' \t\r\n' <"$2"); token_given=1; shift ;;
	--enroll) enroll=prompt ;;
	--enroll-stdin) IFS= read -r token || [ -n "$token" ]; enroll=stdin ;;
	--version) version=${2:-}; shift ;;
	--from-dir) from_dir=${2:-}; shift ;;
	--no-push) push=0 ;;
	--sites) sites=${2:-}; shift ;;
	--lockfiles) lockfiles=${2:-}; shift ;;
	--watch-privilege) [ "$privilege" = users ] || privilege=on ;;
	--watch-privilege-users) privilege=users ;;
	--no-watch-privilege) privilege=off ;;
	--watch-logins) logins=on ;;
	--no-watch-logins) logins=off ;;
	--skip-signature-check) sigcheck=0 ;;
	-h | --help) usage ;;
	*) usage ;;
	esac
	shift
done

[ "$(id -u)" -eq 0 ] || die "run as root (sudo)"
[ -z "$enroll" ] || [ "$token_given" = 0 ] || die "use either a token or an enrollment key, not both"
ask() { # ask PROMPT: read a secret from the terminal, without echo
	printf '%s: ' "$1" >&2
	stty -echo 2>/dev/null || true
	IFS= read -r token || true
	stty echo 2>/dev/null || true
	printf '\n' >&2
}
if [ "$enroll" = prompt ]; then
	[ -t 0 ] || die "no terminal to ask for the enrollment key; use --enroll-stdin"
	ask 'Enrollment key (from "heimdall enroll create" or the Add servers page)'
elif [ -z "$enroll" ] && [ "$token_given" = 0 ]; then
	[ -t 0 ] || die "no terminal to ask for the token; use --token-stdin or --token-file"
	ask 'Ingest token (from "heimdall host add" or the Add host page)'
fi
case $hub in
https://*) ;;
http://127.0.0.1[:/]* | http://localhost[:/]*) ;; # tests and local proxies
*) die "--hub must be an https:// URL" ;;
esac
token=$(printf '%s' "$token" | tr -d ' \t\r\n')
case $enroll:$token in
:hmd_ingest_* | ?*:hmd_enroll_*) ;;
:*) die "missing or malformed token (--token-stdin or --token-file)" ;;
*) die "missing or malformed enrollment key (it starts with hmd_enroll_)" ;;
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

# machine_hash: a hash of this server's machine ID (never the ID itself),
# so the hub enrolls each server once. The same as collect.sh's.
machine_hash() {
	id=$(cat /etc/machine-id 2>/dev/null || cat /var/lib/dbus/machine-id 2>/dev/null || true)
	case $id in *[!0-9a-f]* | '') return 0 ;; esac
	[ ${#id} -eq 32 ] && have sha256sum || return 0
	printf 'heimdall-machine:%s' "$id" | sha256sum | cut -c1-64
}

# enroll_now trades the enrollment key for this server's own ingest token.
# The key goes to curl on stdin, never in process arguments.
enroll_now() {
	have curl || die "enrolling needs curl"
	say "Enrolling this server with the hub"
	hn=$(uname -n 2>/dev/null | tr -cd 'A-Za-z0-9._-' | cut -c1-253)
	hn_header='' machine_header=''
	[ -z "$hn" ] || hn_header="header = \"X-Heimdall-Hostname: $hn\""
	machine=$(machine_hash)
	[ -z "$machine" ] || machine_header="header = \"X-Heimdall-Machine: $machine\""
	status=$(printf '%s\n' "header = \"Authorization: Bearer $token\"" "$hn_header" "$machine_header" |
		curl --config - --silent --show-error --proto '=https,http' --tlsv1.2 \
			--connect-timeout 10 --max-time 60 --data-binary '' \
			--dump-header "$work/enroll.headers" --output "$work/enroll.body" --write-out '%{http_code}' \
			"${hub%/}/api/v1/ingest") || die "could not reach $hub"
	answer=$(head -c 300 "$work/enroll.body" | tr -cd 'A-Za-z0-9 ._,:;()/-')
	case $status:$answer in
	201:*) ;;
	401:*enrollment*) die "the hub rejected the enrollment key (mistyped or revoked)" ;;
	401:*) die "this hub can't enroll servers yet; upgrade it to the release this installer came from" ;;
	403:* | 409:*) die "$answer" ;;
	429:*) die "rate limited by the hub (HTTP 429); try again in a minute" ;;
	*) die "the hub returned HTTP $status" ;;
	esac
	token=$(tr -d ' \t\r\n' <"$work/enroll.body")
	case $token in hmd_ingest_*) ;; *) die "the hub's answer isn't an ingest token" ;; esac
	case $token in *[!A-Za-z0-9_-]*) die "the hub's answer isn't an ingest token" ;; esac
	name=$(tr -d '\r' <"$work/enroll.headers" | sed -n 's/^[Xx]-[Hh]eimdall-[Hh]ost: *\([A-Za-z0-9._-]*\)$/\1/p' | tail -n 1)
	awaiting_in "$work/enroll.headers"
	[ "$awaiting" = 1 ] || say "Enrolled as ${name:-a new host}" # else said at the end
}

# awaiting_in HEADERS: did the hub say this host waits for an admin's
# approval (X-Heimdall-Pending)? Sets $awaiting.
awaiting_in() {
	! tr -d '\r' <"$1" | grep -qi '^x-heimdall-pending: *1$' || awaiting=1
}

# token_works TOKEN: ask the hub (GET, which only checks the token) whether
# an existing token is still valid. Only a clear "no" (401) counts as no.
token_works() {
	code=$(printf 'header = "Authorization: Bearer %s"\n' "$1" |
		curl --config - --silent --proto '=https,http' --tlsv1.2 --connect-timeout 10 --max-time 30 \
			--dump-header "$work/check.headers" --output /dev/null --write-out '%{http_code}' \
			"${hub%/}/api/v1/ingest") || return 0
	[ "$code" != 401 ] || return 1
	awaiting_in "$work/check.headers"
}

say "Fetching Heimdall collector $version"
units='heimdall-collect.service heimdall-collect.timer heimdall-collect-boot.timer heimdall-collect-soon.timer heimdall-collect-changes.service heimdall-collect-changes.path'
for f in SHA256SUMS collect.sh $units privilege-watch.sh privilege-hook login-watch.sh; do fetch "$f"; done
# The event report cap's unit. A release from before it has none, and its
# soon timer starts the report directly. (Checked against SHA256SUMS below.)
if grep -qx 'Unit=heimdall-collect-soon.service' "$work/heimdall-collect-soon.timer"; then
	fetch heimdall-collect-soon.service
	units="$units heimdall-collect-soon.service"
fi
if [ "$sigcheck" = 1 ]; then
	fetch SHA256SUMS.sigstore.json
	verify_release "$work"
else
	say "WARNING: not checking the release's signature (--skip-signature-check); only its checksums"
fi
say "Verifying checksums"
# Check exactly the files fetched above; each one must be listed.
for f in collect.sh $units privilege-watch.sh privilege-hook login-watch.sh; do
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
[ -n "$logins" ] || logins=$(sed -n 's/^HEIMDALL_LOGIN_WATCH=//p' "$conf/collect.env" 2>/dev/null | tail -n 1)
case $logins in on | off) ;; *) logins='' ;; esac
if [ -n "$enroll" ]; then
	# Re-running on a server that already reports (e.g. an ssh loop over the
	# whole fleet) keeps its token: it's an upgrade, not a second host.
	old=$(tr -d ' \t\r\n' 2>/dev/null <"$conf/token" || true)
	case $old in
	hmd_ingest_*[!A-Za-z0-9_-]* | '') ;;
	hmd_ingest_*)
		if ! have curl || token_works "$old"; then
			say "This server already has a token; keeping it (not enrolling it again)"
			token=$old enroll=
		else
			say "This server's token no longer works on the hub (was the host removed?); enrolling it again"
		fi
		;;
	esac
fi
[ -z "$enroll" ] || enroll_now
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
	[ -z "$logins" ] || printf 'HEIMDALL_LOGIN_WATCH=%s\n' "$logins"
} >"$conf/collect.env"
chmod 0644 "$conf/collect.env"

# Root runs these, so they live in a root-owned directory, not in $conf
# (which the heimdall user owns). The push itself reads collect.env as heimdall.
lib=/usr/local/lib/heimdall-collect
apt_hook=/etc/apt/apt.conf.d/80heimdall-collect
apk_hook=/etc/apk/commit_hooks.d/heimdall-collect
if [ -d /run/systemd/system ] && have systemctl; then
	sed "s#/etc/heimdall/collect.env#$conf/collect.env#" "$work/heimdall-collect.service" >/etc/systemd/system/heimdall-collect.service
	for f in heimdall-collect.timer heimdall-collect-boot.timer heimdall-collect-soon.timer heimdall-collect-changes.service; do
		install -m 0644 "$work/$f" /etc/systemd/system/
	done
	if [ -f "$work/heimdall-collect-soon.service" ]; then
		install -m 0644 "$work/heimdall-collect-soon.service" /etc/systemd/system/
	else
		rm -f /etc/systemd/system/heimdall-collect-soon.service # nothing starts it
	fi
	# Report after deploys: `heimdall-collect deployed` touches this file
	# as the deploy user, so anyone may write it. Its content is never read.
	install -d -m 0755 -o root -g root /var/lib/heimdall-collect
	trigger=/var/lib/heimdall-collect/deployed
	if [ -L "$trigger" ] || [ ! -f "$trigger" ]; then
		rm -rf "$trigger"
		: >"$trigger"
	fi
	# Only when needed: a chmod is a change, and would send a report.
	if [ "$(stat -c '%u:%g %a' "$trigger")" != '0:0 666' ]; then
		chown root:root "$trigger"
		chmod 0666 "$trigger"
	fi
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
	# ...and each site's deploys: the first 50 sites (collect.sh's
	# deploy_sites says what's watched and why). `upgrade` refreshes these
	# lines the same way when there's nothing newer to install.
	unit=/etc/systemd/system/heimdall-collect-changes.path
	if HEIMDALL_ALLOW_ROOT=1 HEIMDALL_SITES=$sites /usr/local/bin/heimdall-collect --deploy-unit "$work/changes.path" >"$work/sites.path" 2>/dev/null; then
		mv -f "$work/sites.path" "$work/changes.path"
	else
		say "WARNING: couldn't list the sites to watch for deploys"
	fi
	# From the block's "# Site deploys: <watched> of <found> sites" line.
	watched() { sed -n 's/^# Site deploys: \([0-9][0-9]*\) of .*/\1/p' "$1" 2>/dev/null | head -n 1; }
	found_sites() { sed -n 's/^# Site deploys: [0-9]* of \([0-9][0-9]*\) .*/\1/p' "$1" 2>/dev/null | head -n 1; }
	was=$(watched "$unit") now=$(watched "$work/changes.path") found=$(found_sites "$work/changes.path")
	deploy_note="Watching ${now:-0} sites for deploys"
	[ -z "$was" ] || [ "$was" = "${now:-0}" ] || deploy_note="$deploy_note (was $was)"
	if [ "${found:-0}" -gt 50 ]; then
		say "WARNING: watching deploys of the first 50 of $found sites; use 'heimdall-collect deployed' for the rest"
	fi
	if [ "$watching" = 1 ]; then
		install -m 0644 "$work/changes.path" "$unit"
	else
		systemctl disable --now heimdall-collect-changes.path >/dev/null 2>&1 || true
		rm -f "$unit"
	fi
	# Left from a non-systemd install:
	rm -rf "$apt_hook" "$apk_hook" "$lib" /etc/periodic/daily/heimdall-collect /etc/cron.daily/heimdall-collect \
		/etc/periodic/hourly/heimdall-collect /etc/cron.hourly/heimdall-collect
	systemctl daemon-reload
	systemctl enable --now heimdall-collect.timer >/dev/null 2>&1
	# Enabled for the next boot only: started now it would fire at once.
	systemctl enable heimdall-collect-boot.timer >/dev/null 2>&1
	scheduler="systemd timer (hourly, and 3 minutes after boot)"
	if [ "$watching" = 1 ]; then
		systemctl enable heimdall-collect-changes.path >/dev/null 2>&1
		systemctl restart heimdall-collect-changes.path # picks up a changed watch list
		scheduler="$scheduler, and a minute after packages change or a deploy"
		say "$deploy_note, and 'heimdall-collect deployed' (upgrade picks up new sites)"
	fi
	run_now() { systemctl start heimdall-collect.service; }
else
	# No systemd (e.g. Alpine/OpenRC, containers): an hourly cron job, plus
	# apk/apt hooks that report a minute after packages change. Nothing
	# watches deploys: `heimdall-collect deployed` says so, and exits 0.
	rm -rf /var/lib/heimdall-collect # a deploy trigger left from systemd
	install -d -m 0755 "$lib"
	cat >"$lib/cron.sh" <<EOF
#!/bin/sh
# Heimdall: push a report as the heimdall user. Run as root by cron (hourly,
# after a random delay of up to 15 minutes) and by soon.sh (--now). Written by install.sh.
[ "\${1:-}" = --now ] || sleep "\$(awk 'BEGIN { srand(); print int(rand() * 900) }')"
# The login watch (--watch-logins) counts failed SSH logins first, as root.
[ ! -x /usr/local/lib/heimdall/login-watch ] || /usr/local/lib/heimdall/login-watch run >/dev/null 2>&1 || true
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
case $logins in
on) sh "$work/login-watch.sh" install "$work/login-watch.sh" ;;
off) sh "$work/login-watch.sh" remove ;;
esac
have curl || say "WARNING: curl is required for pushing; install it (e.g. apk add curl)"

if [ "$awaiting" = 1 ]; then
	# Its reports are discarded until then, so don't send one now.
	if [ -n "$name" ]; then wait_msg="Enrolled as $name; waiting"; else wait_msg="This server is waiting"; fi
	say "$wait_msg for an admin to approve it on the hub (Hosts > Add servers)."
	say "It reports on its next hourly run after that."
elif [ "$push" = 1 ]; then
	say "Sending the first snapshot"
	run_now || die "first push failed; check the hub URL and token (see docs/collector.md)"
fi
say "Done: reporting to $hub via $scheduler."
