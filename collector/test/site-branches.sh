#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# collector/test/site-branches.sh [SHELL]: unit tests for collect.sh's
# branch detection (--site-branches): plain and detached checkouts, Forge
# zero-downtime layouts with and without a .git beside releases/, gitdir
# pointers, symlinks out of the site's tree, malformed HEAD files, no
# sites and missing files. No root, no git. Run by `make test-collector`,
# under dash, bash and busybox ash where they're installed.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
collect=$here/collect.sh
t=$(mktemp -d)
trap 'rm -rf "$t"' EXIT
t=$(cd -P "$t" && pwd -P)
fail() { printf 'FAIL (%s): %s\n' "$sh" "$*" >&2; exit 1; }

sha=0123456789abcdef0123456789abcdef01234567
mkhead() { mkdir -p "$1/.git" && printf '%s\n' "$2" >"$1/.git/HEAD"; }

# A plain checkout, and one on a branch with a slash.
mkhead "$t/plain" 'ref: refs/heads/main'
mkhead "$t/beta" 'ref: refs/heads/env/beta'
# Detached HEAD: a bare commit, CRLF and all.
mkdir -p "$t/detached/.git" && printf '%s\r\n' "$sha" >"$t/detached/.git/HEAD"
# Zero-downtime: current -> releases/<n>, which has no .git; the
# repository sits beside releases/.
mkdir -p "$t/zdt/releases/20261020120000"
ln -s "$t/zdt/releases/20261020120000" "$t/zdt/current"
mkhead "$t/zdt" 'ref: refs/heads/dev'
# Zero-downtime with no .git anywhere: unknown.
mkdir -p "$t/bare/releases/1"
ln -s releases/1 "$t/bare/current"
# The release kept its .git: that one wins over the base's.
mkdir -p "$t/kept/releases/7"
ln -s "$t/kept/releases/7" "$t/kept/current"
mkhead "$t/kept/releases/7" 'ref: refs/heads/release'
mkhead "$t/kept" 'ref: refs/heads/main'
# A release whose .git is a worktree pointer into the base's repository.
mkdir -p "$t/wt/releases/2" "$t/wt/.git/worktrees/2"
ln -s "$t/wt/releases/2" "$t/wt/current"
printf 'gitdir: ../../.git/worktrees/2\n' >"$t/wt/releases/2/.git"
printf 'ref: refs/heads/staging\n' >"$t/wt/.git/worktrees/2/HEAD"
# Escapes, none followed: current pointing outside the site, a .git
# symlink and a gitdir pointer leading out, and a symlinked HEAD.
mkhead "$t/outside" 'ref: refs/heads/secret'
mkdir -p "$t/esc1"
ln -s "$t/outside" "$t/esc1/current"
mkdir -p "$t/esc2"
ln -s "$t/outside/.git" "$t/esc2/.git"
mkdir -p "$t/esc3"
printf 'gitdir: ../outside/.git\n' >"$t/esc3/.git"
mkdir -p "$t/esc4/.git"
ln -s "$t/outside/.git/HEAD" "$t/esc4/.git/HEAD"
# Malformed: junk, a ref outside refs/heads, a name git wouldn't allow,
# a name with a shell metacharacter, one too long, a short hash, empty,
# and a .git with no HEAD.
mkhead "$t/junk" 'hello world'
mkhead "$t/remote" 'ref: refs/remotes/origin/main'
mkhead "$t/dots" 'ref: refs/heads/../../etc/passwd'
mkhead "$t/semi" 'ref: refs/heads/feat;reboot'
mkhead "$t/long" "ref: refs/heads/$(printf '%0201d' 0)"
mkhead "$t/short" '0123abc'
mkdir -p "$t/empty/.git" && : >"$t/empty/.git/HEAD"
mkdir -p "$t/nohead/.git"

all="$t/plain $t/beta $t/detached $t/zdt/current $t/bare/current $t/kept/current $t/wt/current $t/esc1/current $t/esc2 $t/esc3 $t/esc4 $t/junk $t/remote $t/dots $t/semi $t/long $t/short $t/empty $t/nohead $t/missing $t/zdt/releases/20261020120000"
want="$t/plain branch:main
$t/beta branch:env/beta
$t/detached commit:$sha
$t/zdt/current branch:dev
$t/kept/current branch:release
$t/wt/current branch:staging
$t/zdt/releases/20261020120000 branch:dev"

run() {
	sh=$1
	# shellcheck disable=SC2086 # $sh may be "busybox sh"
	branches() {
		env HEIMDALL_ENV_FILE="$t/missing.env" HEIMDALL_DISCOVER_SITES=0 HEIMDALL_SITES="$1" ${2:+HEIMDALL_DETECT_REPOS=$2} \
			$sh "$collect" --site-branches 2>"$t/err"
	}
	got=$(branches "$all") || fail "--site-branches failed: $(cat "$t/err")"
	case $got in "v1 "*) ;; *) fail "no v1 prefix: $got" ;; esac
	printf '%s\n' "${got#v1 }" | tr ',' '\n' | sort >"$t/got"
	printf '%s\n' "$want" | sort >"$t/want"
	cmp -s "$t/got" "$t/want" || fail "branches differ:
$(diff "$t/want" "$t/got")"
	case $got in *secret*) fail "followed a path out of the site: $got" ;; esac

	# No sites, and detection turned off: just "v1", never an error.
	[ "$(branches '')" = v1 ] || fail "no sites: $(branches '')"
	[ "$(branches "$t/plain" 0)" = v1 ] || fail "HEIMDALL_DETECT_REPOS=0 still sent a branch"
	# Only missing sites: still a clean run.
	[ "$(branches "$t/missing $t/nohead")" = v1 ] || fail "missing files: $(branches "$t/missing $t/nohead")"
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
