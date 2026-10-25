#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Heimdall login watch: count failed SSH logins per source address, for the
# collector to report. Opt-in (install.sh --watch-logins); see
# docs/failed-logins.md.
#
#   sh login-watch.sh install SELF   install as /usr/local/lib/heimdall/login-watch
#   sh login-watch.sh remove         remove it and its counts
#   login-watch run                  count what sshd logged since the last run
#   login-watch count DIR NOW TZ [SOURCE]
#                                    (tests) count log lines on stdin into DIR
#
# The collector runs as the unprivileged heimdall user and can't read auth
# logs, so this small part runs as root, just before each push (a systemd
# unit the collector's service pulls in, or cron.sh without systemd). It
# only reads: the journal (sshd), or /var/log/auth.log, /var/log/secure or
# /var/log/messages, from where it stopped last time, so each failure is
# counted once. It writes per address, per UTC day: failures, how many
# distinct usernames were tried, first and last seen, and whether a login
# from that address then succeeded. Never the usernames themselves (only a
# short hash in a root-only file, to count them) and never log lines. It
# makes no network requests and changes nothing else.
set -eu
umask 077
export LC_ALL=C
PATH=/usr/sbin:/usr/bin:/sbin:/bin

BIN=/usr/local/lib/heimdall/login-watch
STATE=${HEIMDALL_LOGIN_STATE:-/var/lib/heimdall-logins}
UNIT=/etc/systemd/system/heimdall-login-watch.service
DROPIN_DIR=/etc/systemd/system/heimdall-collect.service.d
DROPIN=$DROPIN_DIR/heimdall-login-watch.conf

die() {
	printf 'heimdall login watch: %s\n' "$*" >&2
	exit 1
}
say() { printf '==> %s\n' "$*" >&2; }
have() { command -v "$1" >/dev/null 2>&1; }

# ── Parsing ─────────────────────────────────────────────────────────────────
# PARSE_AWK turns sshd log lines into one record per connection (sshd's
# PID and the address) and one per successful login:
#
#   C <epoch-first> <epoch-last> <ip> <attempts> <user-hash>...
#   A <epoch> <ip>
#
# Lines come from the journal (short-iso, UTC), RFC 3339 syslog (Debian 12
# rsyslog) or traditional syslog ("Oct 25 06:12:01", local time, no year:
# -v now and -v tz, the local offset in seconds, fill it in).
#
# A connection's attempts are its "Failed <method>" lines, or its PAM
# failure count, whichever is more, and at least 1 if it only probed a
# username ("Invalid user"), ran out of tries or closed while
# authenticating. Usernames are attacker-supplied and may hold spaces or
# look like "x from 192.0.2.1 port 22", so every line is read from the
# right, where sshd puts the real address.
# shellcheck disable=SC2016 # awk program, not shell
PARSE_AWK='
function days(y, m, d,   era, yoe, doy) { # days since 1970-01-01 (proleptic Gregorian)
	y -= (m <= 2)
	era = int((y >= 0 ? y : y - 399) / 400); yoe = y - era * 400
	doy = int((153 * (m + (m > 2 ? -3 : 9)) + 2) / 5) + d - 1
	return era * 146097 + yoe * 365 + int(yoe / 4) - int(yoe / 100) + doy - 719468
}
function hash(s,   h, i) { h = 5381; for (i = 1; i <= length(s); i++) h = (h * 33 + ord[substr(s, i, 1)]) % 2147483647; return h }
function stamp(   y, m, d, t, off, rest, s) { # the line timestamp as epoch seconds, or -1
	if ($1 ~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]/) {
		y = substr($1, 1, 4) + 0; m = substr($1, 6, 2) + 0; d = substr($1, 9, 2) + 0
		t = substr($1, 12, 2) * 3600 + substr($1, 15, 2) * 60 + substr($1, 18, 2)
		rest = substr($1, 20); sub(/^\.[0-9]*/, "", rest); off = 0
		if (rest ~ /^[+-][0-9][0-9]:?[0-9][0-9]$/) {
			s = rest; gsub(/:/, "", s)
			off = substr(s, 2, 2) * 3600 + substr(s, 4, 2) * 60
			if (substr(s, 1, 1) == "-") off = -off
		} else if (rest != "Z" && rest != "") return -1
		return days(y, m, d) * 86400 + t - off
	}
	if (($1 in mon) && $2 ~ /^[0-9][0-9]?$/ && $3 ~ /^[0-9][0-9]:[0-9][0-9]:[0-9][0-9]$/) {
		t = substr($3, 1, 2) * 3600 + substr($3, 4, 2) * 60 + substr($3, 7, 2)
		s = days(year, mon[$1], $2 + 0) * 86400 + t - tz
		if (s > now + 86400) s = days(year - 1, mon[$1], $2 + 0) * 86400 + t - tz # last December
		return s
	}
	return -1
}
# tail splits "<head> <ip> port <n>" (or "<head> <ip>"): sets IP and HEAD.
function tail(s,   i) {
	if (match(s, / port [0-9]+$/)) s = substr(s, 1, RSTART - 1)
	for (i = length(s); i > 0 && substr(s, i, 1) != " "; i--) ;
	IP = substr(s, i + 1); HEAD = (i > 0) ? substr(s, 1, i - 1) : ""
	return IP ~ /^[0-9A-Fa-f.:]+$/ && length(IP) <= 45 && IP ~ /[.:]/
}
function note(kind, ip, user, n,   k) {
	k = pid SUBSEP ip
	if (!(k in first)) { first[k] = at; order[++nconn] = k; cip[k] = ip; cpid[k] = pid }
	if (ip != "-") pidip[pid] = ip
	last[k] = at
	if (kind == "F") fails[k] += n
	else if (kind == "P") pam[k] += n
	else flag[k] = 1
	if (user != "\001" && !((k, user) in seenu)) { seenu[k, user] = 1; users[k] = users[k] " " hash(user) }
}
BEGIN {
	for (i = 1; i < 256; i++) ord[sprintf("%c", i)] = i
	split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec", mn, " ")
	for (i = 1; i <= 12; i++) mon[mn[i]] = i
	now += 0; tz += 0
	d = int(now / 86400) + 719468; era = int(d / 146097); doe = d - era * 146097
	yoe = int((doe - int(doe / 1460) + int(doe / 36524) - int(doe / 146096)) / 365)
	doy = doe - (365 * yoe + int(yoe / 4) - int(yoe / 100)); mp = int((5 * doy + 2) / 153)
	year = yoe + era * 400 + (mp >= 10)
}
{
	tag = ""
	for (i = 2; i <= 6 && i <= NF; i++) if ($i ~ /^sshd(-session|-auth)?\[[0-9]+\]:$/) { tag = $i; break }
	if (tag == "") next
	pid = substr(tag, index(tag, "[") + 1); sub(/\].*/, "", pid)
	at = stamp(); if (at < 0) next
	msg = substr($0, index($0, " " tag " ") + length(tag) + 2)
	sub(/[ \t\r]+$/, "", msg); sub(/ \[preauth\]$/, "", msg)
	sub(/ ssh2: [A-Z0-9-]+ SHA256:[A-Za-z0-9+\/=]+$/, "", msg); sub(/ ssh2$/, "", msg)

	if (msg ~ /^Failed [^ ]+ for /) {
		if (msg ~ /^Failed none /) next
		rest = substr(msg, index(msg, " for ") + 5); sub(/^invalid user /, "", rest)
		if (!tail(rest) || HEAD !~ / from$/ && HEAD != "from") next
		note("F", IP, substr(HEAD, 1, length(HEAD) - 5), 1)
	} else if (msg ~ /^Accepted [^ ]+ for [^ ]+ from [^ ]+ port [0-9]+( |$)/) {
		# An account that exists, so its name has no spaces.
		split(msg, w, " "); if (tail(w[6])) print "A", at, IP
	} else if (msg ~ /^Invalid user /) {
		rest = substr(msg, 14)
		if (rest ~ /^from /) rest = " " rest # an empty username
		if (tail(rest) && HEAD ~ / from$/) note("I", IP, substr(HEAD, 1, length(HEAD) - 5), 0)
	} else if (msg ~ /^(error: )?maximum authentication attempts exceeded for /) {
		rest = substr(msg, index(msg, " for ") + 5); sub(/^invalid user /, "", rest)
		if (tail(rest) && HEAD ~ / from$/) note("M", IP, substr(HEAD, 1, length(HEAD) - 5), 0)
	} else if (msg ~ /^(Disconnecting|Connection closed by|Disconnected from) (authenticating|invalid) user /) {
		sub(/: Too many authentication failures$/, "", msg)
		rest = msg; sub(/^(Disconnecting|Connection closed by|Disconnected from) (authenticating|invalid) user /, "", rest)
		if (tail(rest)) note("C", IP, HEAD, 0)
	} else if (msg ~ /^pam_[a-z0-9_]+\(sshd:auth\): authentication failure;/ || msg ~ /^PAM [0-9]+ more authentication failures;/) {
		n = 1
		if (msg ~ /^PAM /) { split(msg, w, " "); n = w[2] + 0 }
		# rhost comes before user=, the only part a client chooses.
		i = index(msg, " rhost="); if (i == 0) next
		rest = substr(msg, i + 7); sub(/[ \t].*$/, "", rest)
		if (rest ~ /^[0-9A-Fa-f.:]+$/ && rest ~ /[.:]/ && length(rest) <= 45) note("P", rest, "\001", n)
		else note("P", "-", "\001", n) # a host name (UseDNS): counted in the total only
	}
}
END {
	# PAM names the client by host name with UseDNS, sshd by address.
	for (j = 1; j <= nconn; j++) {
		k = order[j]
		if (cip[k] != "-" || !(cpid[k] in pidip)) continue
		k2 = cpid[k] SUBSEP pidip[cpid[k]]
		pam[k2] += pam[k]; pam[k] = 0
		if (first[k] < first[k2]) first[k2] = first[k]
		if (last[k] > last[k2]) last[k2] = last[k]
	}
	for (j = 1; j <= nconn; j++) {
		k = order[j]
		n = fails[k] + 0; if (pam[k] + 0 > n) n = pam[k] + 0; if (n == 0 && flag[k]) n = 1
		if (n > 0) print "C", first[k], last[k], cip[k], n users[k]
	}
}'

# MERGE_AWK adds PARSE_AWK's records (stdin) to the counts and username
# hashes kept so far (DIR/counts and DIR/users), for today and yesterday
# (UTC) only, and writes DIR/counts.new and DIR/users.new:
#
#   # heimdall-logins v1 <source> <updated>
#   D <day> <failures> <addresses>
#   I <day> <ip> <failures> <usernames> <first> <last> <succeeded>
#
# first and last are seconds into the (UTC) day. succeeded is 1 when a
# login from the address succeeded after its first failure that day. At
# most 5,000 addresses a day are kept; past that, failures only add to the
# day's total.
# shellcheck disable=SC2016 # awk program, not shell
MERGE_AWK='
function civil(z,   era, doe, yoe, doy, mp, d, m, y) {
	z += 719468; era = int(z / 146097); doe = z - era * 146097
	yoe = int((doe - int(doe / 1460) + int(doe / 36524) - int(doe / 146096)) / 365)
	doy = doe - (365 * yoe + int(yoe / 4) - int(yoe / 100)); mp = int((5 * doy + 2) / 153)
	d = doy - int((153 * mp + 2) / 5) + 1; m = mp + (mp < 10 ? 3 : -9); y = yoe + era * 400 + (m <= 2)
	return sprintf("%04d-%02d-%02d", y, m, d)
}
function row(day, ip) {
	if ((day, ip) in fl) return 1
	if (nips[day] >= 5000) return 0
	nips[day]++; fl[day, ip] = 0; ok[day, ip] = 0; nu[day, ip] = 0; rows[++nrows] = day SUBSEP ip
	return 1
}
BEGIN {
	now += 0; today = int(now / 86400)
	keep[civil(today)] = today; keep[civil(today - 1)] = today - 1
}
FILENAME == counts && $1 == "D" && ($2 in keep) { total[$2] = $3 + 0; next }
FILENAME == counts && $1 == "I" && ($2 in keep) && NF == 8 {
	if (row($2, $3)) { fl[$2, $3] = $4 + 0; nu[$2, $3] = $5 + 0; fa[$2, $3] = $6 + 0; la[$2, $3] = $7 + 0; ok[$2, $3] = $8 + 0 }
	next
}
FILENAME == userfile && $1 == "U" && ($2 in keep) && NF == 4 { hu[$2, $3, $4] = 1; next }
FILENAME == counts || FILENAME == userfile { next }
$1 == "A" && NF == 3 { acc[++nacc] = $2 " " $3; next }
$1 == "C" && NF >= 5 {
	dn = int($2 / 86400); day = civil(dn)
	if (!(day in keep)) next
	total[day] += $5
	if ($4 == "-" || !row(day, $4)) next
	k = day SUBSEP $4; off1 = $2 - dn * 86400; off2 = $3 - dn * 86400; if (off2 > 86399) off2 = 86399
	if (fl[k] == 0 || off1 < fa[k]) fa[k] = off1
	if (off2 > la[k]) la[k] = off2
	fl[k] += $5
	for (i = 6; i <= NF; i++) if (!((day, $4, $i) in hu) && nu[k] < 1000) { hu[day, $4, $i] = 1; nu[k]++ }
}
END {
	for (i = 1; i <= nacc; i++) {
		split(acc[i], a, " "); dn = int(a[1] / 86400); day = civil(dn)
		if (((day, a[2]) in fl) && fl[day, a[2]] > 0 && a[1] - dn * 86400 >= fa[day, a[2]]) ok[day, a[2]] = 1
	}
	print "# heimdall-logins v1 " source " " int(now) > out
	for (day in keep) if (total[day] > 0 || nips[day] > 0) print "D", day, total[day] + 0, nips[day] + 0 > out
	for (i = 1; i <= nrows; i++) {
		split(rows[i], p, SUBSEP)
		if (fl[rows[i]] > 0) print "I", p[1], p[2], fl[rows[i]], nu[rows[i]], fa[rows[i]], la[rows[i]], ok[rows[i]] > out
	}
	for (k in hu) { split(k, p, SUBSEP); print "U", p[1], p[2], p[3] > uout }
}'

# count DIR NOW TZ SOURCE: add sshd log lines on stdin to DIR's counts.
count() {
	dir=$1 now=$2 tz=$3 source=$4
	[ -f "$dir/counts" ] || : >"$dir/counts"
	[ -f "$dir/users" ] || : >"$dir/users"
	awk -v now="$now" -v tz="$tz" "$PARSE_AWK" |
		awk -v now="$now" -v source="$source" -v counts="$dir/counts" -v userfile="$dir/users" \
			-v out="$dir/counts.new" -v uout="$dir/users.new" "$MERGE_AWK" "$dir/counts" "$dir/users" -
	mv -f "$dir/users.new" "$dir/users"
	mv -f "$dir/counts.new" "$dir/counts"
}

# ── Reading the logs from where the last run stopped ───────────────────────

# tz_seconds: this server's UTC offset in seconds (for traditional syslog).
tz_seconds() {
	date +%z | awk '{ s = substr($0, 2, 2) * 3600 + substr($0, 4, 2) * 60; print (substr($0, 1, 1) == "-") ? -s : s }'
}

journal_has_sshd() {
	[ -d /run/systemd/system ] && have journalctl || return 1
	[ -n "$(journalctl -q --no-pager -n 1 -t sshd -t sshd-session -t sshd-auth 2>/dev/null | head -n 1)" ]
}

# new_journal OUT: sshd's journal entries since the saved cursor (or since
# yesterday on the first run) into OUT; prints the new cursor line.
new_journal() {
	out=$1
	cur=$(sed -n 's/^journal //p' "$STATE/cursor" 2>/dev/null | head -n 1)
	if [ -n "$cur" ]; then set -- "--after-cursor=$cur"; else set -- --since=yesterday; fi
	journalctl -q --no-pager --utc -o short-iso --show-cursor -t sshd -t sshd-session -t sshd-auth "$@" >"$out.raw" 2>/dev/null || true
	next=$(sed -n 's/^-- cursor: //p' "$out.raw" | tail -n 1)
	grep -v '^-- ' "$out.raw" >"$out" || true
	rm -f "$out.raw"
	if [ -n "$next" ]; then echo "journal $next"; elif [ -n "$cur" ]; then echo "journal $cur"; fi
}

# new_file LOG OUT: what LOG gained since the saved offset into OUT (and
# the rest of LOG.1 if LOG was rotated meanwhile); prints the new cursor.
# Only whole lines are taken: a half-written last line waits for next time.
new_file() {
	log=$1 out=$2
	saved=$(sed -n "s#^file $log ##p" "$STATE/cursor" 2>/dev/null | head -n 1)
	ino=$(stat -c %i "$log") size=$(stat -c %s "$log")
	sino=${saved% *} soff=${saved#* }
	case $sino:$soff in *[!0-9:]* | :* | *:) sino='' soff=0 ;; esac
	: >"$out"
	if [ -n "$sino" ] && [ "$sino" = "$ino" ] && [ "$size" -ge "$soff" ]; then
		start=$soff
	else
		# Rotated (or new): finish the old file first, if it's LOG.1 now.
		if [ -n "$sino" ] && [ -f "$log.1" ] && [ "$(stat -c %i "$log.1")" = "$sino" ]; then
			tail -c +"$((soff + 1))" "$log.1" >>"$out"
		fi
		start=0
	fi
	tail -c +"$((start + 1))" "$log" | head -c "$((size - start))" >"$out.part"
	if [ -s "$out.part" ] && [ -n "$(tail -c 1 "$out.part")" ]; then
		whole=$(sed '$d' "$out.part" | wc -c | tr -d ' ')
		head -c "$whole" "$out.part" >>"$out"
		size=$((start + whole))
	else
		cat "$out.part" >>"$out"
	fi
	rm -f "$out.part"
	echo "file $log $ino $size"
}

run() {
	[ -d "$STATE" ] || die "$STATE is missing; turn the login watch on with install.sh --watch-logins"
	# One run at a time; a lock left by a run that died is taken after 10 minutes.
	if ! mkdir "$STATE/lock" 2>/dev/null; then
		[ -n "$(find "$STATE/lock" -maxdepth 0 -mmin +10 2>/dev/null)" ] || exit 0
		rm -rf "$STATE/lock"
		mkdir "$STATE/lock" || exit 0
	fi
	trap 'rm -rf "$STATE/lock" "$STATE/lines"' EXIT
	now=$(date +%s)
	source=none cursor=
	if [ "${HEIMDALL_LOGIN_JOURNAL:-1}" != 0 ] && journal_has_sshd; then
		source=journal
		cursor=$(new_journal "$STATE/lines")
	else
		for log in ${HEIMDALL_LOGIN_FILES:-/var/log/auth.log /var/log/secure /var/log/messages}; do
			[ -f "$log" ] || continue
			source=${log##*/}
			cursor=$(new_file "$log" "$STATE/lines")
			break
		done
	fi
	[ -f "$STATE/lines" ] || : >"$STATE/lines"
	count "$STATE" "$now" "$(tz_seconds)" "$source" <"$STATE/lines"
	[ -z "$cursor" ] || printf '%s\n' "$cursor" >"$STATE/cursor"
	# The collector (heimdall) reads the counts; nobody else needs to.
	chmod 0640 "$STATE/counts"
	if g=$(id -g heimdall 2>/dev/null); then chgrp "$g" "$STATE/counts" 2>/dev/null || true; fi
}

# ── Install and remove ──────────────────────────────────────────────────────

install_watch() {
	src=$1
	[ -r "$src" ] || die "missing $src"
	install -d -m 0755 -o root -g 0 /usr/local/lib/heimdall
	cp "$src" "$BIN.new"
	chown root:0 "$BIN.new"
	chmod 0755 "$BIN.new"
	mv -f "$BIN.new" "$BIN"
	install -d -m 0755 -o root -g 0 "$STATE"
	if command -v restorecon >/dev/null 2>&1; then restorecon -R "$BIN" "$STATE" 2>/dev/null || true; fi
	if [ -d /run/systemd/system ] && have systemctl; then
		# Runs as root before each push, pulled in by the collector's
		# service; it can only read, and write its own directory.
		cat >"$UNIT" <<EOF
# Heimdall login watch: count failed SSH logins (counts only, never
# usernames) before each push. Written by install.sh --watch-logins.
[Unit]
Description=Heimdall login watch (count failed SSH logins)
Documentation=https://github.com/chrisreedio/heimdall/blob/main/docs/failed-logins.md

[Service]
Type=oneshot
ExecStart=$BIN run
TimeoutStartSec=2min
UMask=0077
ProtectSystem=strict
ReadWritePaths=$STATE
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
PrivateNetwork=yes
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_CHOWN
RestrictSUIDSGID=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictNamespaces=yes
RestrictRealtime=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
RestrictAddressFamilies=AF_UNIX
EOF
		chmod 0644 "$UNIT"
		install -d -m 0755 "$DROPIN_DIR"
		cat >"$DROPIN" <<'EOF'
# Heimdall login watch: count failed SSH logins before each push. Written
# by install.sh --watch-logins; a failure never stops the push.
[Unit]
Wants=heimdall-login-watch.service
After=heimdall-login-watch.service
EOF
		chmod 0644 "$DROPIN"
		systemctl daemon-reload
	fi
	# Count what's there now, so the first push has something.
	"$BIN" run || say "WARNING: the first count failed; it's retried before each push"
	say "Login watch on (failed SSH logins per address; counts only, never usernames)"
}

remove_watch() {
	if [ -e "$UNIT" ] || [ -e "$DROPIN" ]; then
		rm -f "$UNIT" "$DROPIN"
		rmdir "$DROPIN_DIR" 2>/dev/null || true
		if [ -d /run/systemd/system ] && have systemctl; then systemctl daemon-reload; fi
	fi
	rm -f "$BIN"
	rmdir /usr/local/lib/heimdall 2>/dev/null || true
	rm -rf "$STATE"
	say "Login watch off"
}

case ${1:-} in
install)
	[ "$(id -u)" -eq 0 ] || die "run as root"
	install_watch "${2:-}"
	;;
remove)
	[ "$(id -u)" -eq 0 ] || die "run as root"
	remove_watch
	;;
run)
	[ "$(id -u)" -eq 0 ] || [ -n "${HEIMDALL_LOGIN_STATE:-}" ] || die "run as root"
	run
	;;
count)
	[ $# -ge 4 ] || die "usage: login-watch count DIR NOW TZ [SOURCE]"
	count "$2" "$3" "$4" "${5:-test}"
	;;
*) die "usage: login-watch.sh install SELF | remove | run" ;;
esac
