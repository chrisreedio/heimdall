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
#   3. schedules a daily push (systemd timer, or cron without systemd) and
#      runs the first push.
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
for f in SHA256SUMS collect.sh heimdall-collect.service heimdall-collect.timer privilege-watch.sh privilege-hook; do fetch "$f"; done
if fetch_sig=$(fetch SHA256SUMS.sigstore.json 2>/dev/null && echo ok) && [ "$fetch_sig" = ok ] && have cosign; then
	say "Verifying the Sigstore signature on SHA256SUMS"
	cosign verify-blob "$work/SHA256SUMS" --bundle "$work/SHA256SUMS.sigstore.json" \
		--certificate-identity-regexp '^https://github.com/chrisreedio/heimdall/\.github/workflows/release\.yml@refs/tags/v' \
		--certificate-oidc-issuer https://token.actions.githubusercontent.com >/dev/null 2>&1 ||
		die "SHA256SUMS signature verification FAILED"
fi
say "Verifying checksums"
(cd "$work" && grep -E ' (collect\.sh|heimdall-collect\.service|heimdall-collect\.timer|privilege-watch\.sh|privilege-hook)$' SHA256SUMS | sha256sum -c - >/dev/null) ||
	die "checksum verification FAILED; not installing"

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

if [ -d /run/systemd/system ] && have systemctl; then
	sed "s#/etc/heimdall/collect.env#$conf/collect.env#" "$work/heimdall-collect.service" >/etc/systemd/system/heimdall-collect.service
	install -m 0644 "$work/heimdall-collect.timer" /etc/systemd/system/
	systemctl daemon-reload
	systemctl enable --now heimdall-collect.timer >/dev/null 2>&1
	scheduler="systemd timer (daily, random delay up to 1h)"
	run_now() { systemctl start heimdall-collect.service; }
else
	# No systemd (e.g. Alpine/OpenRC, containers): a daily cron job.
	cat >"$conf/cron.sh" <<EOF
#!/bin/sh
set -a; . $conf/collect.env; set +a
sleep "\$(awk 'BEGIN { srand(); print int(rand() * 3600) }')"
exec su -s /bin/sh heimdall -c 'HEIMDALL_URL=\$HEIMDALL_URL HEIMDALL_TOKEN_FILE=\$HEIMDALL_TOKEN_FILE HEIMDALL_SITES=\${HEIMDALL_SITES:-} HEIMDALL_LOCKFILES=\${HEIMDALL_LOCKFILES:-} /usr/local/bin/heimdall-collect --push'
EOF
	chmod 0755 "$conf/cron.sh"
	if [ -d /etc/periodic/daily ]; then
		ln -sf "$conf/cron.sh" /etc/periodic/daily/heimdall-collect
	elif [ -d /etc/cron.daily ]; then
		ln -sf "$conf/cron.sh" /etc/cron.daily/heimdall-collect
	else
		die "no systemd and no cron.daily directory; schedule $conf/cron.sh yourself"
	fi
	scheduler="cron (daily)"
	run_now() {
		set -a
		# shellcheck disable=SC1090,SC1091 # written above
		. "$conf/collect.env"
		set +a
		su -s /bin/sh heimdall -c "HEIMDALL_URL=$HEIMDALL_URL HEIMDALL_TOKEN_FILE=$HEIMDALL_TOKEN_FILE HEIMDALL_SITES='${HEIMDALL_SITES:-}' HEIMDALL_LOCKFILES='${HEIMDALL_LOCKFILES:-}' /usr/local/bin/heimdall-collect --push"
	}
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
