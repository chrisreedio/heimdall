#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# collector/test/set-hub.sh: tests for `heimdall-collect set-hub`, run as
# root in a throwaway container (it creates the heimdall user and writes
# /etc/heimdall), with a fake curl standing in for the hub:
#
#   docker run --rm -v "$PWD/collector:/opt/heimdall:ro" alpine:3.20 sh /opt/heimdall/test/set-hub.sh
#
# The test report really runs as heimdall through su, as on a server.
set -eu
[ "$(id -u)" -eq 0 ] || { echo "set-hub.sh: run it as root in a container" >&2; exit 1; }
[ -f /.dockerenv ] || [ -n "${HEIMDALL_TEST_IN_CONTAINER:-}" ] || { echo "set-hub.sh: run it in a container; it writes /etc/heimdall" >&2; exit 1; }
collect=$(cd "$(dirname "$0")/.." && pwd)/collect.sh
fail() { printf 'FAIL (set-hub): %s\n' "$*" >&2; exit 1; }

id heimdall >/dev/null 2>&1 || useradd -r heimdall 2>/dev/null || adduser -S -D -H heimdall
conf=/etc/heimdall
mkdir -p "$conf"
chown heimdall "$conf"
chmod 0700 "$conf"
printf 'hmd_ingest_test\n' >"$conf/token"
chown heimdall "$conf/token"
chmod 0400 "$conf/token"
env_file=$conf/collect.env
cat >"$env_file" <<EOF
HEIMDALL_URL=https://ingest.example.com
HEIMDALL_TOKEN_FILE=$conf/token
HEIMDALL_SITES='/srv/a /srv/b'
HEIMDALL_DISCOVER_SITES=0
EOF
chmod 0644 "$env_file"

# The fake hub: records each request's URL and token, answers $f/status.
f=/tmp/fake-hub
mkdir -p "$f"
chmod 0777 "$f"
cat >"$f/curl" <<'EOF'
#!/bin/sh
f=/tmp/fake-hub
auth=$(grep '^header = "Authorization: ' | sed 's/.*Bearer \([^"]*\)".*/\1/')
while [ $# -gt 0 ]; do
	case $1 in
	--output) out=$2; shift ;;
	--dump-header) hdr=$2; shift ;;
	*) url=$1 ;;
	esac
	shift
done
printf '%s %s %s\n' "$(id -un)" "$url" "$auth" >>"$f/log"
status=$(cat "$f/status")
case $status in
down) echo 'curl: (6) Could not resolve host' >&2; printf 000; exit 6 ;;
esac
printf 'HTTP/1.1 %s X\r\n\r\n' "$status" >"$hdr"
printf 'nope\n' >"$out"
printf '%s' "$status"
EOF
chmod 0755 "$f/curl"
export HEIMDALL_CURL="$f/curl"

sethub() { : >"$f/log"; chmod 0666 "$f/log"; sh "$collect" set-hub "$@" >"$f/out" 2>"$f/err"; }
cp -p "$env_file" "$f/before"

# A hub that refuses the token: the file is untouched, and it says why.
for case in 401:"doesn't know this server's token" 403:'a firewall or proxy' 500:'hub returned HTTP 500: nope' down:'could not reach https://new-ingest.example.com (curl exit 6)'; do
	echo "${case%%:*}" >"$f/status"
	if sethub https://new-ingest.example.com; then fail "set-hub succeeded on ${case%%:*}"; fi
	cmp -s "$f/before" "$env_file" || fail "a failed test (${case%%:*}) changed collect.env"
	grep -qF "${case#*:}" "$f/err" || fail "${case%%:*}: $(cat "$f/err")"
	grep -qF 'not changed; still reporting to https://ingest.example.com' "$f/err" || fail "${case%%:*}: $(cat "$f/err")"
done
[ -z "$(find "$conf" -name '.collect.env.*')" ] || fail "a temp file was left behind"

# Not https, junk, or not root: refused before anything is sent.
for bad in http://new-ingest.example.com ftp://x 'https://a.example.com/ x' "https://a.example.com'" 'https://user@a.example.com' 'https://a.example.com/?q=1' "$(printf 'https://a.example.com\nhttps://b.example.com')" ''; do
	if sethub "$bad"; then fail "set-hub accepted '$bad'"; fi
	[ ! -s "$f/log" ] || fail "'$bad' sent a request"
	cmp -s "$f/before" "$env_file" || fail "'$bad' changed collect.env"
done
grep -q 'needs an https:// URL' "$f/err" || fail "empty URL: $(cat "$f/err")"
if su -s /bin/sh heimdall -c "sh '$collect' set-hub https://new-ingest.example.com" 2>"$f/err"; then fail "set-hub ran as heimdall"; fi
grep -q 'run it as root: sudo heimdall-collect set-hub https://new-ingest.example.com' "$f/err" || fail "non-root: $(cat "$f/err")"
if sh "$collect" set-hub; then fail "set-hub with no URL"; fi 2>/dev/null

# The same address (give or take a trailing slash): nothing sent or changed.
sethub https://ingest.example.com/ || fail "same URL failed: $(cat "$f/err")"
[ ! -s "$f/log" ] || fail "same URL sent a request"
cmp -s "$f/before" "$env_file" || fail "same URL changed collect.env"
grep -qx 'heimdall-collect: already reporting to https://ingest.example.com; nothing to change' "$f/err" || fail "same URL: $(cat "$f/err")"

# Success: one report, as heimdall, with the server's token, to the new
# address; then only HEIMDALL_URL changes, and the mode and owner stay.
echo 200 >"$f/status"
sethub https://new-ingest.example.com:8443/ || fail "set-hub failed: $(cat "$f/err")"
[ "$(cat "$f/log")" = 'heimdall https://new-ingest.example.com:8443/api/v1/ingest hmd_ingest_test' ] || fail "test report: $(cat "$f/log")"
cat >"$f/want" <<EOF
HEIMDALL_URL=https://new-ingest.example.com:8443
HEIMDALL_TOKEN_FILE=$conf/token
HEIMDALL_SITES='/srv/a /srv/b'
HEIMDALL_DISCOVER_SITES=0
EOF
diff "$f/want" "$env_file" >&2 || fail "collect.env after set-hub"
[ "$(stat -c '%a %u' "$env_file")" = "644 0" ] || fail "mode/owner: $(stat -c '%a %u' "$env_file")"
grep -qx 'heimdall-collect: hub changed: https://ingest.example.com -> https://new-ingest.example.com:8443 (in /etc/heimdall/collect.env)' "$f/err" || fail "success: $(cat "$f/err")"
[ ! -s "$f/out" ] || fail "stdout: $(cat "$f/out")"
[ -z "$(find "$conf" -name '.collect.env.*')" ] || fail "a temp file was left behind"
# What `upgrade` reads back (it re-runs install.sh with --hub this).
[ "$(sed -n 's/^HEIMDALL_URL=//p' "$env_file" | tail -n 1)" = https://new-ingest.example.com:8443 ] || fail "upgrade would read another hub"

echo "--- example output"
cat "$f/err"
printf 'ok   set-hub (%s)\n' "$(sed -n 's/^ID=//p' /etc/os-release)"
