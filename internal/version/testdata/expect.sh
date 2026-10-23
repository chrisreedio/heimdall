#!/bin/sh
# Regenerate expected-<scheme>.txt by asking the real package managers to
# compare every pair in pairs-<scheme>.txt. Needs Docker. Pairs a tool
# rejects as invalid are left out.
#
#   internal/version/testdata/expect.sh   (or: make test-versions)
set -eu
cd "$(dirname "$0")"

docker run --rm -i debian:12 sh -c '
	while read -r a b; do
		dpkg --compare-versions "$a" lt "$b" 2>/dev/null && rc=0 || rc=$?
		[ "$rc" -le 1 ] || continue
		if [ "$rc" -eq 0 ]; then r=-1
		elif dpkg --compare-versions "$a" eq "$b" 2>/dev/null; then r=0
		else r=1; fi
		echo "$a $b $r"
	done' <pairs-dpkg.txt >expected-dpkg.txt

docker run --rm -i rockylinux:9 python3 -c '
import sys, rpm
for line in sys.stdin:
    a, b = line.split()
    va, vb = rpm.ver(a), rpm.ver(b)
    print(a, b, -1 if va < vb else (0 if va == vb else 1))' <pairs-rpm.txt >expected-rpm.txt

docker run --rm -i alpine:3.20 sh -c '
	while read -r a b; do
		case $(apk version -t "$a" "$b") in
		"<") echo "$a $b -1" ;;
		"=") echo "$a $b 0" ;;
		">") echo "$a $b 1" ;;
		esac
	done' <pairs-apk.txt >expected-apk.txt

wc -l expected-*.txt
