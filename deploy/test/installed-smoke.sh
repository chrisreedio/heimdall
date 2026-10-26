#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# installed-smoke.sh DIST: install a hub and a collector from DIST (make
# dist) on this machine, as an operator would, and drive them through
# `sudo heimdall ...` and the real systemd units. For a throwaway systemd
# VM with passwordless sudo (CI's ubuntu runner); it changes the system.
#
# The last steps fetch a real signed release (and the pinned cosign) from
# GitHub. Unit tests stub root and systemd; these bugs only showed up installed:
# key commands that couldn't read their root-owned files under sudo, a
# relative config path after dropping privileges, and a login watch that
# failed on a server with no failed logins yet.
set -eu
dist=$(cd "${1:?usage: installed-smoke.sh DIST}" && pwd)
toml=/etc/heimdall/heimdall.toml
fail() { printf 'SMOKE FAIL: %s\n' "$*" >&2; sudo journalctl -u heimdall -u 'heimdall-*' --no-pager -n 80 >&2 || true; exit 1; }
step() { printf '\n== %s\n' "$*"; }
# refuse PATTERN CMD...: run CMD, which must fail and print PATTERN.
refuse() {
	pat=$1; shift
	if out=$("$@" 2>&1); then fail "$* succeeded: $out"; fi
	printf '%s\n' "$out" | tail -n 2
	printf '%s\n' "$out" | grep -q -- "$pat" || fail "$*: no \"$pat\" in the output"
}
# expect PATTERN CMD...: run CMD, which must succeed and print PATTERN.
expect() {
	pat=$1; shift
	out=$("$@" 2>&1) || fail "$* exited $?: $out"
	printf '%s\n' "$out"
	printf '%s\n' "$out" | grep -q -- "$pat" || fail "$*: no \"$pat\" in the output"
}
# section_set SECTION KEY VALUE: set KEY in [SECTION] of the hub's config.
section_set() {
	# shellcheck disable=SC2016 # awk program
	sudo awk -v s="[$1]" -v k="$2" -v v="$3" '
		function add() { if (in_s && !done) print k " = " v; done = done || in_s }
		$0 == s { in_s = 1; print; next }
		/^\[/ { add(); in_s = 0 }
		in_s && $1 == k { print k " = " v; done = 1; next }
		{ print }
		END { add() }' "$toml" | sudo tee "$toml.new" >/dev/null
	sudo chown --reference="$toml" "$toml.new" && sudo chmod --reference="$toml" "$toml.new" && sudo mv "$toml.new" "$toml"
}

step "An unsigned build is refused"
# make dist doesn't sign; only the release workflow does.
refuse 'SHA256SUMS.sigstore.json' sudo sh "$dist/install-hub.sh" --from-dir "$dist" --org acme --no-tailscale
[ ! -e /usr/local/bin/heimdall ] || fail "refused, but installed anyway"

step "Install the hub"
sudo sh "$dist/install-hub.sh" --from-dir "$dist" --org acme --no-tailscale --skip-signature-check
systemctl is-active --quiet heimdall || fail "hub not running"
curl -fs -o /dev/null http://127.0.0.1:8080/login || fail "UI not answering"
expect 'v' sudo heimdall version
expect 'acme' sudo heimdall org list
expect 'config' sudo heimdall config update

step "Key commands under sudo (stored as root, LoadCredential added)"
printf 'smoke-cloudflare-token-0123456789\n' | sudo heimdall cloudflare set-token --stdin
printf 'tskey-api-smoke0123456789\n' | sudo heimdall tailscale set-key --stdin
for f in /etc/heimdall/cloudflare-token /etc/heimdall/tailscale-key; do
	[ "$(sudo stat -c '%U %a' "$f")" = "root 600" ] || fail "$f is $(sudo stat -c '%U %a' "$f"), want root 600"
done
grep -q '^LoadCredential=heimdall-cloudflare:/etc/heimdall/cloudflare-token$' /etc/systemd/system/heimdall.service || fail "no cloudflare LoadCredential"
grep -q '^LoadCredential=heimdall-tailscale:/etc/heimdall/tailscale-key$' /etc/systemd/system/heimdall.service || fail "no tailscale LoadCredential"
expect 'running' sudo heimdall restart

step "status reads the root-owned key, then uses the hub's database"
# Turned on in the file only (no restart), so the running hub never calls
# out; the API base is a closed local port.
section_set cloudflare enabled true
section_set cloudflare api_base '"https://127.0.0.1:9"'
section_set tailscale enabled true
expect 'loaded from /etc/heimdall/cloudflare-token' sudo heimdall cloudflare status
expect 'loaded from /etc/heimdall/tailscale-key' sudo heimdall tailscale status
expect 'Mode' sudo heimdall bans status
section_set cloudflare enabled false
section_set tailscale enabled false
[ -z "$(sudo find /var/lib/heimdall -user root)" ] || fail "root-owned files in /var/lib/heimdall: $(sudo find /var/lib/heimdall -user root)"

step "Install a collector on the hub's box, with the login watch"
sudo heimdall host add --org acme --env prod web-01 2>/dev/null |
	sudo sh "$dist/install.sh" --hub http://127.0.0.1:8443 --token-stdin --from-dir "$dist" --watch-logins --skip-signature-check
expect 'web-01' sudo heimdall host list

step "Login watch: a first run with no failed logins"
sudo systemctl start heimdall-login-watch.service || fail "login watch failed with no failed logins"
sudo test -s /var/lib/heimdall-logins/counts || fail "no counts file"

step "Login watch: failures reach the hub"
for i in 1 2 3; do
	logger -t sshd -p auth.info "Failed password for invalid user smoke$i from 192.0.2.77 port 4000$i ssh2"
	logger -t sshd -p auth.info "Connection closed by invalid user smoke$i 192.0.2.77 port 4000$i [preauth]"
done
sleep 1
sudo systemctl start heimdall-login-watch.service || fail "login watch failed"
expect '192.0.2.77' sudo -u heimdall heimdall-collect --logins
sudo systemctl start heimdall-collect.service || fail "collector push failed"
expect '192.0.2.77' sudo heimdall offenders --json

step "Upgrade in place (hub first, then the collector)"
sudo sh "$dist/install-hub.sh" --from-dir "$dist" --skip-signature-check
systemctl is-active --quiet heimdall || fail "hub not running after upgrade"
refuse 'SHA256SUMS.sigstore.json' sudo sh "$dist/install.sh" --hub http://127.0.0.1:8443 --token-file /etc/heimdall-collect/token --from-dir "$dist"

# A real, signed release: the new code checks its signature with the
# pinned cosign, and refuses it once tampered with.
signed=v0.4.32
step "heimdall upgrade checks a real release's signature"
expect 'Sigstore signature verified' sudo heimdall upgrade --version "$signed"
systemctl is-active --quiet heimdall || fail "hub not running after upgrading to $signed"

step "heimdall-collect upgrade checks it too"
expect 'Sigstore signature verified' sudo heimdall-collect upgrade "$signed"

step "The installers check it, and refuse a tampered SHA256SUMS"
rel=$(mktemp -d)
for f in SHA256SUMS SHA256SUMS.sigstore.json heimdall-linux-amd64 heimdall.service collect.sh splash.html \
	heimdall-collect.service heimdall-collect.timer heimdall-collect-boot.timer heimdall-collect-soon.timer \
	heimdall-collect-changes.service heimdall-collect-changes.path privilege-watch.sh privilege-hook login-watch.sh; do
	curl -fsSL --proto '=https' -o "$rel/$f" "https://github.com/realmwatch/heimdall/releases/download/$signed/$f" || fail "download $f"
done
bad=$(mktemp -d)
cp "$rel"/* "$bad/"
echo "0000000000000000000000000000000000000000000000000000000000000000  evil" >>"$bad/SHA256SUMS"
refuse 'signature verification FAILED' sudo sh "$dist/install-hub.sh" --from-dir "$bad"
refuse 'signature verification FAILED' sudo sh "$dist/install.sh" --hub http://127.0.0.1:8443 --token-file /etc/heimdall-collect/token --from-dir "$bad"
expect 'Sigstore signature verified' sudo sh "$dist/install-hub.sh" --from-dir "$rel"
expect 'Sigstore signature verified' sudo sh "$dist/install.sh" --hub http://127.0.0.1:8443 --token-file /etc/heimdall-collect/token --from-dir "$rel"
systemctl is-active --quiet heimdall || fail "hub not running"
printf '\nSMOKE OK\n'
