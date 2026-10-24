#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Run collect.sh --print as an unprivileged user in fresh distro containers
# and save each snapshot, then validate them with the hub's decoder:
#
#   collector/test/run-containers.sh OUTDIR
#   HEIMDALL_COLLECTOR_OUT=OUTDIR go test ./internal/snapshot -run Collector -v
#
# Setup steps run as root (refreshing package metadata, as apt-daily or
# dnf-makecache would on a real server); the collector itself never does.
# *-sites targets also lay out fake vhosts and Laravel apps
# (test/sites-fixture.sh), which may write collector settings to
# /tmp/collect.env.
set -eu

out=${1:?usage: $0 OUTDIR}
mkdir -p "$out"
here=$(cd "$(dirname "$0")/.." && pwd)

# name | image | package metadata refresh | root setup | collector shell
#
# The refresh gets $refresh_limit seconds: CI mirrors are sometimes slow,
# and the decoder test doesn't need update data (it only logs counts), so
# a slow mirror means fewer "updates available", not a slow run.
targets='
debian12|debian:12|apt-get update -qq|useradd -r heimdall|/bin/sh
ubuntu2204|ubuntu:22.04|apt-get update -qq|useradd -r heimdall|/bin/sh
ubuntu2404|ubuntu:24.04|apt-get update -qq|useradd -r heimdall|/bin/sh
ubuntu2404-bash|ubuntu:24.04|apt-get update -qq|useradd -r heimdall|/bin/bash
rocky9|rockylinux:9|dnf -q makecache|useradd -r heimdall|/bin/sh
alpine320|alpine:3.20|apk update -q|adduser -S -D heimdall|/bin/sh
arch|archlinux:latest|pacman -Sy --noconfirm|useradd -r heimdall|/bin/sh
ubuntu2204-sites|ubuntu:22.04|apt-get update -qq|useradd -r heimdall && sh /opt/heimdall/test/sites-fixture.sh|/bin/sh
alpine320-sites|alpine:3.20|apk update -q|adduser -S -D heimdall && sh /opt/heimdall/test/sites-fixture.sh|/bin/sh
'

# Every container runs at once (they're independent and mostly wait on the
# network). Each reports as soon as it finishes, and gets a time limit so
# one hung package mirror can't stall the whole run.
limit=${COLLECTOR_TEST_TIMEOUT:-480}
refresh_limit=${COLLECTOR_REFRESH_TIMEOUT:-20}
to=''
! command -v timeout >/dev/null 2>&1 || to="timeout $limit"

# run_target NAME DOCKER-RUN-ARGS...
run_target() {
	name=$1
	shift
	cname="heimdall-ctest-$name-$$"
	start=$(date +%s)
	rc=0
	$to docker run --rm --name "$cname" "$@" >"$out/$name.json" 2>"$out/$name.err" || rc=$?
	if [ "$rc" = 124 ]; then
		docker kill "$cname" >/dev/null 2>&1 || true
		echo "timed out after ${limit}s" >>"$out/$name.err"
	fi
	secs=$(($(date +%s) - start))
	if [ "$rc" = 0 ]; then
		printf '%-18s ok (%s bytes, %ss)\n' "$name" "$(wc -c <"$out/$name.json")" "$secs"
	else
		printf '%-18s FAILED after %ss (%s):\n%s\n' "$name" "$secs" "$out/$name.err" "$(tail -n 5 "$out/$name.err" | sed 's/^/    /')"
	fi
	echo "$rc" >"$out/$name.status"
}

names=''
while IFS='|' read -r name image refresh setup shell; do
	[ -n "$name" ] || continue
	names="$names $name"
	run_target "$name" -v "$here:/opt/heimdall:ro" "$image" sh -c "
		timeout $refresh_limit $refresh >/dev/null 2>&1 || echo 'package metadata refresh skipped (slow mirror)' >&2
		($setup) >/dev/null 2>&1
		su -s $shell heimdall -c 'set -a; [ ! -r /tmp/collect.env ] || . /tmp/collect.env; $shell /opt/heimdall/collect.sh --print && printf \"site-repos: %s\\n\" \"\$($shell /opt/heimdall/collect.sh --site-repos)\" >&2'
	" &
done <<EOF
$targets
EOF
# Windows: the document builder runs under pwsh on Linux against fixtures.
names="$names windows-fixture"
run_target windows-fixture -v "$here:/opt/heimdall:ro" -v "$out:/out" mcr.microsoft.com/powershell:lts-ubuntu-22.04 \
	pwsh -NoProfile -File /opt/heimdall/test/windows-selftest.ps1 /opt/heimdall/collect.ps1 &
echo "Running $(echo "$names" | wc -w | tr -d ' ') containers in parallel (limit ${limit}s each)..."
wait

status=0
for name in $names; do
	[ "$(cat "$out/$name.status" 2>/dev/null)" = 0 ] || status=1
	rm -f "$out/$name.status"
done
exit $status
