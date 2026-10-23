#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Install a Heimdall hub on a fresh Debian/Ubuntu VM, in one step.
#
#   curl -fsSLO https://github.com/chrisreedio/heimdall/releases/download/vX.Y.Z/install-hub.sh &&
#     sudo sh install-hub.sh --org acme --ingest-host ingest.acme.example.com --admin you@example.com
#
# Modes:
#   --ingest-host NAME   servers anywhere: Caddy serves ONLY the ingest path
#                        on NAME with an automatic certificate (ports 80/443)
#   --tailnet-only       every server is on your tailnet: ingest is published
#                        with `tailscale serve`, nothing is public
# The UI (and MCP with --mcp) is always tailnet-only via `tailscale serve`.
#
# Upgrading an existing hub: run the new release's script with just
#   sudo sh install-hub.sh
# (or --version vX.Y.Z). It stops the hub, keeps the previous binary and a
# pre-upgrade copy of the database, migrates, starts it again and rolls
# back automatically if the hub doesn't come up.
#
# Requires Tailscale to be installed and logged in first:
#   curl -fsSL https://tailscale.com/install.sh | sh && sudo tailscale up --ssh
set -eu
umask 022
export LC_ALL=C
PATH=/usr/sbin:/usr/bin:/sbin:/bin

HEIMDALL_VERSION=dev # set by `make dist`
RELEASES=${HEIMDALL_RELEASES:-https://github.com/chrisreedio/heimdall/releases/download}

die() { printf 'heimdall install-hub: %s\n' "$*" >&2; exit 1; }
say() { printf '==> %s\n' "$*" >&2; }
have() { command -v "$1" >/dev/null 2>&1; }

usage() {
	cat >&2 <<'EOF'
usage: install-hub.sh --org SLUG (--ingest-host NAME | --tailnet-only)
                      [--org-name "Acme Corp"] [--admin EMAIL] [--mcp]
                      [--version vX.Y.Z] [--from-dir DIR] [--no-tailscale]

  --no-tailscale   skip tailscale (UI stays on 127.0.0.1:8080; for testing or
                   if you'll put your own HTTPS proxy in front)
EOF
	exit 2
}

org='' org_name='' ingest_host='' tailnet_only=0 admin='' mcp=0 version=$HEIMDALL_VERSION from_dir='' use_ts=1
while [ $# -gt 0 ]; do
	case $1 in
	--org) org=${2:-}; shift ;;
	--org-name) org_name=${2:-}; shift ;;
	--ingest-host) ingest_host=${2:-}; shift ;;
	--tailnet-only) tailnet_only=1 ;;
	--admin) admin=${2:-}; shift ;;
	--mcp) mcp=1 ;;
	--version) version=${2:-}; shift ;;
	--from-dir) from_dir=${2:-}; shift ;;
	--no-tailscale) use_ts=0 ;;
	*) usage ;;
	esac
	shift
done

[ "$(id -u)" -eq 0 ] || die "run as root (sudo)"
upgrade=0
[ ! -e /etc/heimdall/heimdall.toml ] || upgrade=1
if [ "$upgrade" = 1 ]; then
	# Existing hub: networking (tailscale serve, Caddy) and the org stay as
	# they are; only the software is upgraded.
	# --ingest-host and --admin still finish those steps if given.
	org=${org:-existing} use_ts=0
fi
[ -n "$org" ] || usage
case $org in *[!a-z0-9-]* | -* | *-) die "--org must be lowercase letters, digits and '-'" ;; esac
if [ -n "$ingest_host" ]; then
	[ "$tailnet_only" = 0 ] || die "choose --ingest-host or --tailnet-only, not both"
	case $ingest_host in *[!a-z0-9.-]* | .* | *.) die "--ingest-host must be a DNS name" ;; esac
elif [ "$tailnet_only" = 0 ] && [ "$use_ts" = 1 ]; then
	die "choose --ingest-host NAME (servers anywhere) or --tailnet-only"
fi
case $version in v[0-9]*.[0-9]*.[0-9]* | dev) ;; *) die "bad --version $version" ;; esac
[ -n "$from_dir" ] || [ "$version" != dev ] || die "this script isn't from a release; pass --version vX.Y.Z or --from-dir"
[ -d /run/systemd/system ] || die "systemd is required"

case $(uname -m) in
x86_64 | amd64) arch=amd64 ;;
aarch64 | arm64) arch=arm64 ;;
*) die "unsupported architecture $(uname -m)" ;;
esac

# Tailscale gives the UI its private HTTPS address.
ts_name=''
if [ "$use_ts" = 1 ]; then
	have tailscale || die "install and log in to Tailscale first: curl -fsSL https://tailscale.com/install.sh | sh && tailscale up --ssh"
	ts_name=$(tailscale status --json 2>/dev/null | sed -n 's/.*"DNSName": *"\([^"]*\)\.".*/\1/p' | head -n 1)
	[ -n "$ts_name" ] || die "tailscale isn't logged in (run: tailscale up --ssh)"
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
fetch() {
	if [ -n "$from_dir" ]; then
		cp "$from_dir/$1" "$work/$1" || die "missing $from_dir/$1"
	else
		curl -fsSL --proto '=https' --tlsv1.2 -o "$work/$1" "$RELEASES/$version/$1" || die "download failed: $1"
	fi
}
say "Fetching Heimdall $version ($arch)"
for f in SHA256SUMS "heimdall-linux-$arch" heimdall.service collect.sh; do fetch "$f"; done
if have cosign && (fetch SHA256SUMS.sigstore.json) 2>/dev/null; then
	cosign verify-blob "$work/SHA256SUMS" --bundle "$work/SHA256SUMS.sigstore.json" \
		--certificate-identity-regexp '^https://github.com/chrisreedio/heimdall/\.github/workflows/release\.yml@refs/tags/v' \
		--certificate-oidc-issuer https://token.actions.githubusercontent.com >/dev/null 2>&1 ||
		die "SHA256SUMS signature verification FAILED"
	say "Sigstore signature verified"
fi
(cd "$work" && grep -E " (heimdall-linux-$arch|heimdall\.service|collect\.sh)\$" SHA256SUMS | sha256sum -c - >/dev/null) ||
	die "checksum verification FAILED; not installing"
say "Checksums verified"

hd() { (cd /var/lib/heimdall && runuser -u heimdall-hub -- /usr/local/bin/heimdall -c /etc/heimdall/heimdall.toml "$@"); }

# healthy waits for the service to stay up and the UI to answer.
healthy() {
	for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30; do
		sleep 1
		systemctl is-active --quiet heimdall || continue
		if have curl; then
			curl -fs -o /dev/null --max-time 2 http://127.0.0.1:8080/login && return 0
		else
			return 0
		fi
	done
	return 1
}

id heimdall-hub >/dev/null 2>&1 || useradd --system --home-dir /var/lib/heimdall --shell /usr/sbin/nologin heimdall-hub
install -d -m 0700 -o heimdall-hub -g heimdall-hub /etc/heimdall /var/lib/heimdall

if [ "$upgrade" = 1 ]; then
	old=$(/usr/local/bin/heimdall version 2>/dev/null || echo unknown)
	say "Upgrading the hub: $old -> $version"
	db=$(sed -n 's/^database *= *"\(.*\)"/\1/p' /etc/heimdall/heimdall.toml | head -n 1)
	case $db in /*) ;; *) db=/etc/heimdall/${db:-heimdall.db} ;; esac
	systemctl stop heimdall
	cp -p /usr/local/bin/heimdall /usr/local/bin/heimdall.previous
	cp -p /etc/systemd/system/heimdall.service "$work/heimdall.service.previous"
	# A consistent pre-upgrade copy, owner-only, next to the database.
	rm -f "$db.pre-upgrade"
	runuser -u heimdall-hub -- sh -c "umask 077 && cp -p '$db' '$db.pre-upgrade'"
	install -m 0755 "$work/heimdall-linux-$arch" /usr/local/bin/heimdall
	# Keep local additions to the unit (e.g. SSO's LoadCredential line).
	grep -E '^LoadCredential=' "$work/heimdall.service.previous" >"$work/creds" || true
	if [ -s "$work/creds" ]; then
		awk -v f="$work/creds" '{ if ($0 ~ /^#?LoadCredential=/) next; print } /^\[Service\]$/ { while ((getline l < f) > 0) print l }' \
			"$work/heimdall.service" >"$work/heimdall.service.new" && mv "$work/heimdall.service.new" "$work/heimdall.service"
	fi
	install -m 0644 "$work/heimdall.service" /etc/systemd/system/heimdall.service
	systemctl daemon-reload
	if ! hd migrate || ! systemctl start heimdall || ! healthy; then
		say "Upgrade failed; the new version's log:"
		journalctl -u heimdall -n 15 --no-pager -o cat >&2 2>/dev/null || true
		say "Rolling back to $old"
		systemctl stop heimdall 2>/dev/null || true
		install -m 0755 /usr/local/bin/heimdall.previous /usr/local/bin/heimdall
		install -m 0644 "$work/heimdall.service.previous" /etc/systemd/system/heimdall.service
		systemctl daemon-reload
		runuser -u heimdall-hub -- cp -p "$db.pre-upgrade" "$db"
		rm -f "$db-wal" "$db-shm"
		systemctl start heimdall
		die "upgrade to $version failed and was rolled back; see journalctl -u heimdall"
	fi
	say "Upgraded to $(/usr/local/bin/heimdall version)"
else
	say "Installing the hub"
	install -m 0755 "$work/heimdall-linux-$arch" /usr/local/bin/heimdall
	ui_url=http://127.0.0.1:8080
	[ -z "$ts_name" ] || ui_url=https://$ts_name
	set -- --database /var/lib/heimdall/heimdall.db --ui-base-url "$ui_url" --behind-proxy
	if [ -n "$ingest_host" ]; then
		set -- "$@" --ingest-public-url "https://$ingest_host"
	elif [ -n "$ts_name" ]; then
		set -- "$@" --ingest-public-url "https://$ts_name:8443"
	fi
	[ "$mcp" = 0 ] || [ -z "$ts_name" ] || set -- "$@" --mcp-base-url "https://$ts_name:8444"
	hd init "$@" 2>/dev/null
	hd org create "$org" --name "${org_name:-$org}" 2>/dev/null
	hd env create prod 2>/dev/null
	install -m 0644 "$work/heimdall.service" /etc/systemd/system/heimdall.service
	systemctl daemon-reload
	systemctl enable --now heimdall >/dev/null 2>&1
	healthy || die "heimdall didn't start; see journalctl -u heimdall"
fi

# Trust this release's collector, so servers upgrading to it don't raise
# "collector changed" anomalies.
collector_version=$(sed -n 's/^VERSION=//p' "$work/collect.sh" | head -n 1)
collector_sha=$(sha256sum "$work/collect.sh" | cut -d ' ' -f 1)
hd collector trust --version "$collector_version" --note "release $version" "$collector_sha" >/dev/null 2>&1 || true

# setup_caddy publishes only the ingest path (with --ingest-host).
setup_caddy() {
	if [ -n "$ingest_host" ]; then
		say "Installing Caddy for public ingest on $ingest_host"
		have caddy || { apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq caddy >/dev/null; }
		# Keep a certificate installed with `heimdall ingest cert` (e.g. a
		# Cloudflare Origin certificate).
		tls_line=''
		[ ! -e /etc/caddy/heimdall-origin.pem ] || [ ! -e /etc/caddy/heimdall-origin.key ] ||
			tls_line="	tls /etc/caddy/heimdall-origin.pem /etc/caddy/heimdall-origin.key"
		cat >/etc/caddy/Caddyfile <<EOF
# Written by Heimdall's install-hub.sh: only the ingest path is public.
$ingest_host {
$tls_line
	@ingest path /api/v1/ingest
	request_body @ingest {
		max_size 6MB
	}
	reverse_proxy @ingest 127.0.0.1:8443
	respond 404
}
EOF
		systemctl reload caddy 2>/dev/null || systemctl restart caddy
	fi
}

# setup_admin creates the first admin (with --admin) if missing.
setup_admin() {
	if [ -n "$admin" ] && ! hd user list 2>/dev/null | awk -v e="$admin" '$2 == e && $3 == "local" { f = 1 } END { exit !f }'; then
		if [ -t 0 ]; then
			say "Creating admin $admin (choose a password, then add the TOTP secret to your authenticator)"
			hd user create --admin "$admin"
		else
			say "No terminal: create the admin later with: sudo heimdall user create --admin $admin"
		fi
	fi
}

if [ "$upgrade" = 1 ]; then
	setup_caddy
	setup_admin
	say "Done. Previous binary: /usr/local/bin/heimdall.previous; pre-upgrade database: $db.pre-upgrade"
	say "Servers: re-run install.sh from $version to update their collectors."
	exit 0
fi

if [ -n "$ts_name" ]; then
	say "Publishing the UI on your tailnet"
	tailscale serve --bg 8080 >/dev/null
	[ "$mcp" = 0 ] || tailscale serve --bg --https 8444 http://127.0.0.1:8090 >/dev/null
	[ -n "$ingest_host" ] || tailscale serve --bg --https 8443 http://127.0.0.1:8443 >/dev/null
fi

setup_caddy
setup_admin

cat >&2 <<EOF

Heimdall hub is running.
  UI:      ${ts_name:+https://$ts_name}${ts_name:-http://127.0.0.1:8080 (put HTTPS in front)}
  Ingest:  ${ingest_host:+https://$ingest_host/api/v1/ingest}${ingest_host:-${ts_name:+https://$ts_name:8443/api/v1/ingest (tailnet only)}}${ingest_host:-${ts_name:-http://127.0.0.1:8443/api/v1/ingest (loopback; put HTTPS in front)}}
EOF
[ "$mcp" = 0 ] || [ -z "$ts_name" ] || printf '  MCP:     https://%s:8444/mcp\n' "$ts_name" >&2
cat >&2 <<EOF

Next:
  sudo heimdall user create --admin you@example.com   (if not done)
  Sign in to the UI, then Hosts → Add a host for each server.
EOF
[ -z "$ingest_host" ] || printf '  Point DNS for %s at this machine and allow inbound 80/443.\n' "$ingest_host" >&2
