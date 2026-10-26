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

# A real, signed release: the new code checks its signature with the
# pinned cosign, and refuses it once tampered with. Done first, on the
# empty machine: an older release can't run on this build's database once
# it has newer migrations, so it's never installed over it.
signed=v0.4.32
step "The hub installer checks a real release's signature, and refuses a tampered SHA256SUMS"
rel=$(mktemp -d)
for f in SHA256SUMS SHA256SUMS.sigstore.json heimdall-linux-amd64 heimdall.service collect.sh splash.html \
	heimdall-collect.service heimdall-collect.timer heimdall-collect-boot.timer heimdall-collect-soon.timer \
	heimdall-collect-changes.service heimdall-collect-changes.path privilege-watch.sh privilege-hook login-watch.sh; do
	curl -fsSL --proto '=https' -o "$rel/$f" "https://github.com/realmwatch/heimdall/releases/download/$signed/$f" || fail "download $f"
done
bad=$(mktemp -d)
cp "$rel"/* "$bad/"
echo "0000000000000000000000000000000000000000000000000000000000000000  evil" >>"$bad/SHA256SUMS"
refuse 'signature verification FAILED' sudo sh "$dist/install-hub.sh" --from-dir "$bad" --org acme --no-tailscale
[ ! -e /usr/local/bin/heimdall ] || fail "refused, but installed anyway"
expect 'Sigstore signature verified' sudo sh "$dist/install-hub.sh" --from-dir "$rel" --org acme --no-tailscale

step "heimdall upgrade checks it too"
# This build's binary, upgrading to (re-installing) the signed release.
sudo install -m 0755 "$dist/heimdall-linux-amd64" /usr/local/bin/heimdall
expect 'Sigstore signature verified' sudo heimdall upgrade --version "$signed"
systemctl is-active --quiet heimdall || fail "hub not running after upgrading to $signed"

step "Start over from an empty machine"
sudo systemctl disable --now heimdall >/dev/null 2>&1
sudo rm -rf /etc/heimdall /var/lib/heimdall /usr/local/bin/heimdall /usr/local/bin/heimdall.previous /etc/systemd/system/heimdall.service
sudo systemctl daemon-reload

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

step "Deploys are watched: a zero-downtime site and an in-place one"
# A Forge/Ploi zero-downtime layout (current -> releases/N, swapped at the
# end of a deploy) and an in-place checkout. Re-running install.sh finds them.
for r in /srv/zdt-site/releases/1 /srv/inplace-site/vendor/composer; do sudo mkdir -p "$r"; done
for d in /srv/zdt-site/releases/1 /srv/inplace-site; do
	printf '{"require": {"php": "^8.2"}}\n' | sudo tee "$d/composer.json" >/dev/null
	printf '{\n    "packages": [\n        {\n            "name": "laravel/framework",\n            "version": "v11.0.0"\n        }\n    ]\n}\n' |
		sudo tee "$d/composer.lock" >/dev/null
done
printf '<?php return array();\n' | sudo tee /srv/inplace-site/vendor/composer/installed.php >/dev/null
sudo ln -sfn /srv/zdt-site/releases/1 /srv/zdt-site/current
sudo sh "$dist/install.sh" --hub http://127.0.0.1:8443 --token-file /etc/heimdall-collect/token --from-dir "$dist" \
	--skip-signature-check --no-push --sites "/srv/zdt-site/current /srv/inplace-site"
unit=/etc/systemd/system/heimdall-collect-changes.path
cat "$unit"
for p in /var/lib/heimdall-collect/deployed /srv/zdt-site /srv/inplace-site/composer.lock /srv/inplace-site/vendor/composer/installed.php; do
	grep -qx "PathChanged=$p" "$unit" || fail "$unit doesn't watch $p"
done
! grep -q '^PathChanged=/srv/zdt-site/current' "$unit" || fail "$unit watches through the current symlink"
[ "$(stat -c '%U %a' /var/lib/heimdall-collect/deployed)" = "root 666" ] || fail "deploy trigger is $(stat -c '%U %a' /var/lib/heimdall-collect/deployed)"
systemctl is-active --quiet heimdall-collect-changes.path || fail "the path unit isn't running"

# reported_after LABEL CMD...: run CMD (a deploy), then wait for the debounced
# report: heimdall-collect.service must start again, about 60s after CMD,
# and succeed (a 2xx from the hub).
idle() { # no report running (a oneshot is "activating" while it runs)
	case $(systemctl show -P ActiveState heimdall-collect.service) in inactive | failed) ;; *) return 1 ;; esac
}
reported_after() {
	label=$1; shift
	n=0 quiet=0
	while [ "$quiet" -lt 3 ]; do # no countdown or report for 3s in a row
		if [ "$(systemctl show -P NextElapseUSecMonotonic heimdall-collect-soon.timer)" = infinity ] && idle; then
			quiet=$((quiet + 1))
		else
			quiet=0
		fi
		n=$((n + 1)); [ "$n" -lt 150 ] || fail "$label: the collector never went quiet"; sleep 1
	done
	before=$(systemctl show -P InvocationID heimdall-collect.service)
	t0=$(date +%s)
	"$@" || fail "$label: the deploy step failed"
	while :; do
		now=$(systemctl show -P InvocationID heimdall-collect.service)
		if [ "$now" != "$before" ] && idle; then break; fi
		[ $(($(date +%s) - t0)) -lt 100 ] || fail "$label: no report within 100s"
		sleep 1
	done
	took=$(($(date +%s) - t0))
	[ "$(systemctl show -P Result heimdall-collect.service)" = success ] || fail "$label: the report failed"
	[ "$took" -ge 55 ] || fail "$label: reported after ${took}s, before the 60s debounce"
	printf '%s: reported after %ss\n' "$label" "$took"
}
zdt_deploy() { # a new release, then swap the symlink (rename over it)
	sudo cp -a /srv/zdt-site/releases/1 /srv/zdt-site/releases/2 &&
		sudo sed -i 's/v11.0.0/v11.0.1/' /srv/zdt-site/releases/2/composer.lock &&
		sudo ln -sfn /srv/zdt-site/releases/2 /srv/zdt-site/current.new &&
		sudo mv -T /srv/zdt-site/current.new /srv/zdt-site/current
}
inplace_deploy() { sudo sed -i 's/v11.0.0/v11.0.2/' /srv/inplace-site/composer.lock; }
announced() { # as an unprivileged user, with no sudo
	out=$(sudo -u nobody /usr/local/bin/heimdall-collect deployed 2>&1) || return 1
	[ -z "$out" ] || { echo "deployed said: $out"; return 1; }
}
# The hourly report (at a random offset) mustn't pass for a deploy's.
sudo systemctl stop heimdall-collect.timer
reported_after "zero-downtime deploy" zdt_deploy
sudo -u heimdall sh -c 'set -a; . /etc/heimdall-collect/collect.env; exec heimdall-collect --print' |
	grep -q '"framework_version": "11.0.1"' || fail "the snapshot doesn't have the new release's packages"
reported_after "in-place deploy" inplace_deploy
reported_after "heimdall-collect deployed" announced

step "Event reports are capped at 12 an hour; past it, one line and no report"
before=$(systemctl show -P InvocationID heimdall-collect.service)
now=$(date +%s)
i=0
while [ $i -lt 12 ]; do echo "$((now - i))"; i=$((i + 1)); done | sudo tee /var/lib/heimdall-collect/events >/dev/null
sudo systemctl start heimdall-collect-soon.service || fail "the soon service failed past the cap (it should skip)"
sleep 2
[ "$(systemctl show -P InvocationID heimdall-collect.service)" = "$before" ] || fail "a report started past the cap"
sudo journalctl -u heimdall-collect-soon.service --no-pager | grep -q 'skipping this event report: 12 already' ||
	fail "no skip line in the soon service's journal"
sudo rm /var/lib/heimdall-collect/events
sudo systemctl start heimdall-collect-soon.service || fail "the soon service failed under the cap"
n=0
while [ "$(systemctl show -P InvocationID heimdall-collect.service)" = "$before" ]; do
	n=$((n + 1)); [ "$n" -lt 30 ] || fail "no report under the cap"; sleep 1
done

step "A plain upgrade, already current, picks up a new site for deploys"
sudo mkdir -p /srv/new-site
printf '{"packages": []}\n' | sudo tee /srv/new-site/composer.lock >/dev/null
sudo sed -i "s#^HEIMDALL_SITES=.*#HEIMDALL_SITES='/srv/zdt-site/current /srv/inplace-site /srv/new-site'#" /etc/heimdall-collect/collect.env
expect 'watching 3 sites for deploys (was 2)' sudo heimdall-collect upgrade
grep -qx 'PathChanged=/srv/new-site/composer.lock' "$unit" || fail "upgrade didn't add the new site"
systemctl is-active --quiet heimdall-collect-changes.path || fail "the path unit isn't running after the refresh"
out=$(sudo heimdall-collect upgrade 2>&1) || fail "upgrade failed: $out"
case $out in *watching*) fail "upgrade with nothing new still said: $out" ;; esac
sudo systemctl start heimdall-collect.timer
sudo rm -rf /srv/zdt-site /srv/inplace-site /srv/new-site

step "Upgrade in place (hub first, then the collector)"
sudo sh "$dist/install-hub.sh" --from-dir "$dist" --skip-signature-check
systemctl is-active --quiet heimdall || fail "hub not running after upgrade"
refuse 'SHA256SUMS.sigstore.json' sudo sh "$dist/install.sh" --hub http://127.0.0.1:8443 --token-file /etc/heimdall-collect/token --from-dir "$dist"

# The collector has no database, so the signed (older) release can go
# over this build's collector.
step "heimdall-collect upgrade checks the signed release's signature"
expect 'Sigstore signature verified' sudo heimdall-collect upgrade "$signed"

step "install.sh checks it, and refuses a tampered SHA256SUMS"
refuse 'signature verification FAILED' sudo sh "$dist/install.sh" --hub http://127.0.0.1:8443 --token-file /etc/heimdall-collect/token --from-dir "$bad"
expect 'Sigstore signature verified' sudo sh "$dist/install.sh" --hub http://127.0.0.1:8443 --token-file /etc/heimdall-collect/token --from-dir "$rel"
systemctl is-active --quiet heimdall || fail "hub not running"
printf '\nSMOKE OK\n'
