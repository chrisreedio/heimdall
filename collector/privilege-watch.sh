#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Heimdall privilege watch: add or remove the pam_exec hook. Run as root
# by install.sh (--watch-privilege, --no-watch-privilege); see
# docs/collector.md.
#
#   sh privilege-watch.sh install HOOK_SOURCE [users]
#   sh privilege-watch.sh remove
#
# Only lines ending in "# heimdall" are added or removed; the rest of each
# PAM file stays byte for byte as it was. Files are rewritten through a
# temp file in the same directory (same owner and mode), then renamed.
set -eu
umask 022
export LC_ALL=C
PATH=/usr/sbin:/usr/bin:/sbin:/bin

HOOK=/usr/local/lib/heimdall/privilege-hook
EVENTS_DIR=/var/lib/heimdall-privilege
# seteuid: sudo opens its session with the caller's real uid, so without it
# the hook would run as the caller and couldn't write the root-owned file.
PAM_LINE="session optional pam_exec.so quiet seteuid $HOOK  # heimdall"
PAM_FILES="/etc/pam.d/sudo /etc/pam.d/su /etc/pam.d/sshd"

die() {
	printf 'heimdall privilege watch: %s\n' "$*" >&2
	exit 1
}
say() { printf '==> %s\n' "$*" >&2; }

# rewrite FILE: replace FILE's contents with stdin, keeping its owner and
# mode (and SELinux context, via restorecon).
rewrite() {
	tmp=$1.heimdall.$$
	cp -p "$1" "$tmp"
	if ! cat >"$tmp"; then
		rm -f "$tmp"
		die "could not write $tmp"
	fi
	mv -f "$tmp" "$1"
	if command -v restorecon >/dev/null 2>&1; then restorecon "$1" 2>/dev/null || true; fi
}

install_watch() {
	src=$1 users=${2:-}
	[ -r "$src" ] || die "missing $src"
	flag=0
	[ "$users" != users ] || flag=1
	install -d -m 0755 -o root -g 0 /usr/local/lib/heimdall
	sed "s/^RECORD_USERS=0 /RECORD_USERS=$flag /" "$src" >"$HOOK.new"
	chown root:0 "$HOOK.new"
	chmod 0755 "$HOOK.new"
	mv -f "$HOOK.new" "$HOOK"
	install -d -m 0755 -o root -g 0 "$EVENTS_DIR"
	[ -e "$EVENTS_DIR/events" ] || : >"$EVENTS_DIR/events"
	chown root:0 "$EVENTS_DIR/events"
	chmod 0644 "$EVENTS_DIR/events"
	if command -v restorecon >/dev/null 2>&1; then restorecon -R "$HOOK" "$EVENTS_DIR" 2>/dev/null || true; fi

	added=
	for f in $PAM_FILES; do
		[ -f "$f" ] || continue
		if [ -L "$f" ]; then
			say "WARNING: $f is a symlink, so it's left alone; add this line yourself: $PAM_LINE"
			continue
		fi
		! grep -F -x -q -- "$PAM_LINE" "$f" || continue
		{
			cat "$f"
			# A file without a final newline gets one before our line.
			[ -z "$(tail -c 1 "$f")" ] || printf '\n'
			printf '%s\n' "$PAM_LINE"
		} | rewrite "$f"
		added="$added ${f##*/}"
	done
	what="no usernames"
	[ "$flag" = 0 ] || what="with usernames"
	say "Privilege watch on ($what)${added:+; added the PAM line to:$added}"
}

remove_watch() {
	removed=
	for f in $PAM_FILES; do
		if [ ! -f "$f" ] || [ -L "$f" ]; then continue; fi
		grep -q -- 'privilege-hook.*# heimdall$' "$f" || continue
		grep -v -- 'pam_exec\.so.*/usr/local/lib/heimdall/privilege-hook.*# heimdall$' "$f" | rewrite "$f"
		removed="$removed ${f##*/}"
	done
	rm -f "$HOOK"
	rmdir /usr/local/lib/heimdall 2>/dev/null || true
	rm -rf "$EVENTS_DIR"
	say "Privilege watch off${removed:+; removed the PAM line from:$removed}"
}

[ "$(id -u)" -eq 0 ] || die "run as root"
case ${1:-} in
install) install_watch "${2:-}" "${3:-}" ;;
remove) remove_watch ;;
*) die "usage: privilege-watch.sh install HOOK_SOURCE [users] | remove" ;;
esac
