#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# collector/test/privilege-hook.sh: the privilege watch's PAM hook end to
# end, run as root in a throwaway container: real sshd, sudo and su, a
# login over SSH as an unprivileged user, and the events file it leaves.
#
#   docker run --rm --cap-add SYS_PTRACE -v "$PWD/collector:/opt/heimdall:ro" debian:12 sh /opt/heimdall/test/privilege-hook.sh
#
# It installs openssh-server, sudo and tmux with the distro's package
# manager, so it needs the network.
set -eu
[ "$(id -u)" -eq 0 ] || { echo "privilege-hook.sh: run it as root in a container" >&2; exit 1; }
[ -f /.dockerenv ] || [ -n "${HEIMDALL_TEST_IN_CONTAINER:-}" ] || { echo "privilege-hook.sh: run it in a container; it rewrites PAM files" >&2; exit 1; }
dir=$(cd "$(dirname "$0")/.." && pwd)
fail() { printf 'FAIL (privilege-hook): %s\n' "$*" >&2; [ ! -f "$events" ] || sed 's/^/  events: /' "$events" >&2; exit 1; }
events=/var/lib/heimdall-privilege/events

if command -v apt-get >/dev/null 2>&1; then
	export DEBIAN_FRONTEND=noninteractive
	apt-get update -qq >/dev/null
	apt-get install -y -qq openssh-server openssh-client sudo tmux procps >/dev/null
elif command -v dnf >/dev/null 2>&1; then
	dnf install -y -q openssh-server openssh-clients sudo tmux procps-ng util-linux >/dev/null
fi

id alice >/dev/null 2>&1 || useradd -m -s /bin/sh alice
printf 'alice ALL=(ALL) NOPASSWD: ALL\n' >/etc/sudoers.d/alice
chmod 0440 /etc/sudoers.d/alice
mkdir -p /run/sshd ~alice/.ssh
ssh-keygen -A >/dev/null
rm -f /tmp/k /tmp/k.pub
ssh-keygen -q -t ed25519 -N '' -f /tmp/k
cp /tmp/k.pub ~alice/.ssh/authorized_keys
chown -R alice ~alice/.ssh
chmod 0700 ~alice/.ssh
# Root logins by key, for the root-ssh case.
mkdir -p /root/.ssh
cp /tmp/k.pub /root/.ssh/authorized_keys
# In the config rather than on sshd's command line, for collect.sh --ssh.
conf='PermitRootLogin prohibit-password\nUsePAM yes\nPasswordAuthentication no\nPort 2222\nListenAddress 127.0.0.1\nListenAddress ::1\n'
# shellcheck disable=SC2059 # the format is ours
printf "$conf" >/etc/ssh/sshd_config.d/00-test.conf 2>/dev/null || printf "$conf" >>/etc/ssh/sshd_config

sh "$dir/privilege-watch.sh" install "$dir/privilege-hook" users
"$(command -v sshd)"
sleep 1

# The collector's view of this sshd, unprivileged: its effective settings
# (sshd -G) where the config is readable, else only that it's unreadable.
got=$(su alice -s /bin/sh -c "sh '$dir/collect.sh' --ssh")
if su alice -s /bin/sh -c 'test -r /etc/ssh/sshd_config'; then
	want='v1 src=g port=2222 listen=127.0.0.1,0:0:0:0:0:0:0:1 password=no kbd=no pam=yes root=prohibit-password'
else
	want='v1 src=unreadable port=22 listen=- password=? kbd=? pam=? root=?'
fi
[ "$got" = "$want" ] || fail "collect.sh --ssh: got '$got', want '$want'"
printf 'ok   collect.sh --ssh: %s\n' "$got"

# run ADDR USER CMD: CMD in a login over SSH with a terminal, as sudo and
# su need for PAM_TTY.
run() {
	ssh -tt -q -i /tmp/k -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes \
		"$2@$1" "$3" </dev/null >/dev/null 2>&1 || true
}
# expect LABEL PATTERN: the newest event line matches PATTERN (a grep -E).
expect() {
	i=0
	while [ "$i" -lt 20 ]; do
		last=$(tail -n 1 "$events")
		printf '%s\n' "$last" | grep -Eq "^[0-9]+ $2\$" && { printf 'ok   %s: %s\n' "$1" "$last"; return 0; }
		i=$((i + 1))
		sleep 0.2
	done
	fail "$1: want '$2', got '$last'"
}

: >"$events"
run 127.0.0.1 alice 'sudo -n true'
expect "sudo over SSH (IPv4)" 'sudo alice 127\.0\.0\.1'
run ::1 alice 'sudo -n true'
expect "sudo over SSH (IPv6)" 'sudo alice ::1'
run 127.0.0.1 alice 'sudo -n su -c true'
expect "su from sudo over SSH" 'su (alice|root) 127\.0\.0\.1'
run 127.0.0.1 root 'true'
expect "root SSH" 'root-ssh root 127\.0\.0\.1'
# Inside tmux the shell's parent is the tmux server, not sshd, and utmp
# has no entry for tmux's terminals, so it records "-".
: >"$events"
run 127.0.0.1 alice 'tmux new-session -d -s t "sudo -n true; sleep 5" && sleep 3; tmux kill-server'
expect "sudo inside tmux" 'sudo alice -'
# A local session: no SSH anywhere.
: >"$events"
script -qc 'su alice -c "sudo -n true"' /dev/null </dev/null >/dev/null 2>&1 || true
expect "local sudo" 'sudo alice -'

sh "$dir/privilege-watch.sh" remove
echo "privilege-hook: all ok"
