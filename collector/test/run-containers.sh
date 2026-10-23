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

# name | image | root setup | shell used to run the collector
targets='
debian12|debian:12|apt-get update -qq && useradd -r heimdall|/bin/sh
ubuntu2204|ubuntu:22.04|apt-get update -qq && useradd -r heimdall|/bin/sh
ubuntu2404|ubuntu:24.04|apt-get update -qq && useradd -r heimdall|/bin/sh
ubuntu2404-bash|ubuntu:24.04|apt-get update -qq && useradd -r heimdall|/bin/bash
rocky9|rockylinux:9|dnf -q makecache && useradd -r heimdall|/bin/sh
alma9|almalinux:9|dnf -q makecache && useradd -r heimdall|/bin/sh
alpine320|alpine:3.20|apk update -q && adduser -S -D heimdall|/bin/sh
arch|archlinux:latest|pacman -Sy --noconfirm >/dev/null && useradd -r heimdall|/bin/sh
ubuntu2204-sites|ubuntu:22.04|apt-get update -qq && useradd -r heimdall && sh /opt/heimdall/test/sites-fixture.sh|/bin/sh
alpine320-sites|alpine:3.20|apk update -q && adduser -S -D heimdall && sh /opt/heimdall/test/sites-fixture.sh|/bin/sh
'

status=0
while IFS='|' read -r name image setup shell; do
	[ -n "$name" ] || continue
	printf '%-18s ' "$name"
	if docker run --rm -v "$here:/opt/heimdall:ro" "$image" sh -c "
		($setup) >/dev/null 2>&1
		su -s $shell heimdall -c 'set -a; [ ! -r /tmp/collect.env ] || . /tmp/collect.env; $shell /opt/heimdall/collect.sh --print'
	" >"$out/$name.json" 2>"$out/$name.err"; then
		echo "ok ($(wc -c <"$out/$name.json") bytes)"
	else
		echo "FAILED (see $out/$name.err)"
		status=1
	fi
done <<EOF
$targets
EOF
# Windows: the document builder runs under pwsh on Linux against fixtures.
printf '%-18s ' windows-fixture
if docker run --rm -v "$here:/opt/heimdall:ro" -v "$out:/out" mcr.microsoft.com/powershell:lts-ubuntu-22.04 \
	pwsh -NoProfile -File /opt/heimdall/test/windows-selftest.ps1 /opt/heimdall/collect.ps1 >"$out/windows-fixture.json" 2>"$out/windows-fixture.err"; then
	echo "ok ($(wc -c <"$out/windows-fixture.json") bytes)"
else
	echo "FAILED (see $out/windows-fixture.err)"
	status=1
fi
exit $status
