#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# collector/test/ssh-state.sh [SHELL]: unit tests for collect.sh's sshd
# settings (--ssh) read from files: Include, Match blocks, first value
# wins, every Port counts, sshd's defaults, and listening addresses from
# /proc/net fixtures. No root, no sshd. Run by `make test-collector`, under
# dash, bash and busybox ash where they're installed. The `sshd -G` road is
# tested against a real sshd in privilege-hook.sh.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
collect=$here/collect.sh
t=$(mktemp -d)
trap 'rm -rf "$t"' EXIT
fail() { printf 'FAIL (%s): %s\n' "$sh" "$*" >&2; exit 1; }

mkdir -p "$t/etc/sshd_config.d" "$t/net" "$t/empty"
cat >"$t/etc/sshd_config" <<'CFG'
# Debian's layout: drop-ins first, so they win.
Include sshd_config.d/*.conf
#Port 22
PasswordAuthentication yes
KbdInteractiveAuthentication no
UsePAM yes
Match User backup
	PasswordAuthentication yes
CFG
# A Match block ends with its file.
printf 'PasswordAuthentication no\nPort 2222\nMatch Address 10.0.0.0/8\n  PermitRootLogin yes\n' >"$t/etc/sshd_config.d/50-cloud.conf"
printf 'PermitRootLogin=no\nPort 2200\n' >"$t/etc/sshd_config.d/60-root.conf"
printf 'PermitRootLogin yes\n' >"$t/etc/sshd_config.d/ignored.txt"
# Nothing set at all: sshd's defaults.
: >"$t/etc/bare_config"
# Older spelling, Match all, an absolute Include.
printf 'Include %s/etc/extra.conf\nMatch all\nChallengeResponseAuthentication no\nPermitRootLogin without-password\n' "$t" >"$t/etc/old_config"
printf 'UsePAM yes\n' >"$t/etc/extra.conf"

# Listening: 0.0.0.0:2222, 127.0.0.1:22 (not sshd's port here), an
# established connection, 100.168.1.1:2222; [::]:2222 and [::1]:2200.
cat >"$t/net/tcp" <<'NET'
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:08AE 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0000000000000000 100 0 0 10 0
   1: 0100007F:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2 1 0000000000000000 100 0 0 10 0
   2: 0A01A8C0:08AE 0A01A8C0:D431 01 00000000:00000000 00:00000000 00000000     0        0 3 1 0000000000000000 100 0 0 10 0
   3: 0101A864:08AE 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 4 1 0000000000000000 100 0 0 10 0
NET
cat >"$t/net/tcp6" <<'NET'
  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:08AE 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 5 1 0000000000000000 100 0 0 10 0
   1: 00000000000000000000000001000000:0898 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 6 1 0000000000000000 100 0 0 10 0
NET

check() { # NAME CONFIG NET WANT
	# shellcheck disable=SC2086 # $sh may be "busybox sh"
	got=$(HEIMDALL_ALLOW_ROOT=1 HEIMDALL_SSHD=/nonexistent HEIMDALL_SSHD_CONFIG="$2" HEIMDALL_PROC_NET="$3" $sh "$collect" --ssh)
	[ "$got" = "$4" ] || fail "$1: got '$got', want '$4'"
	printf 'ok   %s (%s)\n' "$1" "$sh"
}

run() {
	check "drop-ins, Match, ports" "$t/etc/sshd_config" "$t/net" \
		'v1 src=files port=2222,2200 listen=0.0.0.0,100.168.1.1,0:0:0:0:0:0:0:0,0:0:0:0:0:0:0:1 password=no kbd=no pam=yes root=no'
	check "defaults" "$t/etc/bare_config" "$t/net" \
		'v1 src=files port=22 listen=127.0.0.1 password=yes kbd=yes pam=no root=prohibit-password'
	check "old spellings, Match all" "$t/etc/old_config" "$t/empty" \
		'v1 src=files port=22 listen=- password=yes kbd=no pam=yes root=prohibit-password'
	check "no sshd at all" "$t/etc/missing" "$t/net" 'v1 src=none'
}

if [ $# -gt 0 ]; then
	for sh in "$@"; do run; done
else
	for sh in dash bash 'busybox sh'; do
		command -v "${sh%% *}" >/dev/null 2>&1 || continue
		run
	done
fi
