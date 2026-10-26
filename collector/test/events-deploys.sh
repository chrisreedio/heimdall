#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# collector/test/events-deploys.sh [SHELL]: unit tests for collect.sh's
# event report cap (event-allowed) and deploy watch list (--deploy-unit),
# with no systemd and no root. Run by `make test-collector`, under dash,
# bash and busybox ash where they're installed.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
collect=$here/collect.sh
t=$(mktemp -d)
trap 'rm -rf "$t"' EXIT
fail() { printf 'FAIL (%s): %s\n' "$sh" "$*" >&2; exit 1; }

run() {
	sh=$1
	state=$t/events
	rm -f "$state"
	allowed() { HEIMDALL_EVENT_STATE=$state HEIMDALL_NOW=$1 $sh "$collect" event-allowed 2>"$t/err"; }

	# 12 event reports in an hour, then the 13th is skipped with one line.
	now=1800000000
	i=0
	while [ $i -lt 12 ]; do
		allowed $((now + i * 60)) || fail "event $((i + 1)) of 12 was refused: $(cat "$t/err")"
		[ ! -s "$t/err" ] || fail "an allowed event said: $(cat "$t/err")"
		i=$((i + 1))
	done
	if allowed $((now + 720)); then fail "a 13th event in the hour was allowed"; fi
	[ "$(wc -l <"$t/err")" -eq 1 ] || fail "a skip should log one line, got: $(cat "$t/err")"
	grep -q 'skipping this event report: 12 already in the last hour' "$t/err" || fail "skip message: $(cat "$t/err")"
	[ "$(wc -l <"$state")" -eq 12 ] || fail "a skipped event was counted"
	# An hour after the first, one slot is free again; old times are dropped.
	allowed $((now + 3600)) || fail "refused after the first event left the hour"
	if allowed $((now + 3601)); then fail "allowed a second one with only one slot free"; fi
	allowed $((now + 7300)) || fail "refused after two quiet hours"
	[ "$(wc -l <"$state")" -eq 1 ] || fail "old times were kept: $(cat "$state")"
	# Junk in the file is ignored; an unwritable file never blocks a report.
	printf 'junk\n-5\n\n' >"$state"
	allowed $((now + 9000)) || fail "junk in the state file blocked a report"
	HEIMDALL_EVENT_STATE=$t/missing/dir/events HEIMDALL_NOW=$now $sh "$collect" event-allowed 2>/dev/null ||
		fail "an unwritable state file blocked a report"

	# Deploy watch block: added before [Install], idempotent, removed when
	# no site is left.
	s=$t/sites
	rm -rf "$s"
	mkdir -p "$s/zdt/releases/2" "$s/inplace/vendor/composer" "$s/static"
	echo '{}' >"$s/zdt/releases/2/composer.json"
	ln -s "$s/zdt/releases/2" "$s/zdt/current"
	echo '{}' >"$s/inplace/composer.lock"
	echo '<?php' >"$s/inplace/vendor/composer/installed.php"
	unit=$t/changes.path
	printf '[Path]\nPathChanged=/var/lib/heimdall-collect/deployed\n\n[Install]\nWantedBy=paths.target\n' >"$unit"
	dunit() { HEIMDALL_ALLOW_ROOT=1 HEIMDALL_DISCOVER_SITES=0 HEIMDALL_SITES=$1 $sh "$collect" --deploy-unit "$2"; }
	dunit "$s/zdt/current $s/inplace $s/static" "$unit" >"$t/u1"
	cat >"$t/want" <<EOF
[Path]
PathChanged=/var/lib/heimdall-collect/deployed

# Site deploys: 2 of 3 sites (heimdall-collect --deploy-watches; install.sh and upgrade refresh it)
PathChanged=$s/zdt
PathChanged=$s/inplace/composer.lock
PathChanged=$s/inplace/vendor/composer/installed.php

[Install]
WantedBy=paths.target
EOF
	diff "$t/want" "$t/u1" >&2 || fail "--deploy-unit output"
	dunit "$s/zdt/current $s/inplace $s/static" "$t/u1" >"$t/u2"
	diff "$t/u1" "$t/u2" >&2 || fail "--deploy-unit isn't idempotent"
	dunit "$s/static" "$t/u1" >"$t/u3"
	diff "$unit" "$t/u3" >&2 || fail "--deploy-unit left a stale block"
	printf 'ok   %s\n' "$sh"
}

if [ $# -gt 0 ]; then
	for sh in "$@"; do run "$sh"; done
else
	for sh in dash bash 'busybox sh'; do
		command -v "${sh%% *}" >/dev/null 2>&1 || continue
		run "$sh"
	done
fi
