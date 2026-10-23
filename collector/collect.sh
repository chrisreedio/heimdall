#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# heimdall-collect: report this host's OS and package inventory to Heimdall.
#
#   heimdall-collect --print     write a snapshot (JSON) to stdout
#   heimdall-collect --push      send a snapshot to the hub
#
# Read-only and unprivileged: it refuses to run as root, never changes the
# system, makes one HTTPS request in --push mode, and ignores everything in
# the hub's response except the status code.
#
# Environment (push mode):
#   HEIMDALL_URL         hub base URL, e.g. https://heimdall.example.com:8443
#   HEIMDALL_TOKEN_FILE  ingest token file (default /etc/heimdall/token)
#   HEIMDALL_CA_FILE     optional CA bundle to pin the hub's certificate
#
# Environment (both modes):
#   HEIMDALL_SITES           extra app roots to inventory, space-separated
#   HEIMDALL_DISCOVER_SITES  set to 0 to skip reading nginx/Apache vhosts
#
# Format: heimdall.snapshot/v2 (docs/snapshot-format.md). POSIX sh; tested
# with dash, busybox ash and bash.

set -eu
umask 077
export LC_ALL=C
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

VERSION=0.4.5
FORMAT=heimdall.snapshot/v3

die() { printf 'heimdall-collect: %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

UNAVAILABLE=
unavailable() { UNAVAILABLE="$UNAVAILABLE $1"; }

# Make a value safe inside a JSON string. Control characters, backslashes
# and quotes are dropped rather than escaped: the hub rejects them in every
# field anyway, and dropping keeps this portable across awk/sed variants.
clean() { printf '%s' "$1" | tr -d '\000-\037\177\\"'; }

# Same for tab-separated streams: keep tabs and newlines as delimiters.
clean_tsv() { tr -d '\000-\010\013-\037\177\\"'; }

# Emit TSV rows (fields in the given order) as a JSON array of objects.
# Usage: ... | tsv_to_json name version arch
tsv_to_json() {
	clean_tsv | awk -v keys="$*" '
		BEGIN { FS = "\t"; n = split(keys, k, " "); rows = 0 }
		NF == 0 { next }
		{
			printf "%s\n    {", (rows++ ? "," : "")
			for (i = 1; i <= n; i++) {
				v = $i
				if (k[i] == "security") {
					printf "%s\"%s\": %s", (i > 1 ? ", " : ""), k[i], (v == "" ? "null" : v)
				} else {
					printf "%s\"%s\": \"%s\"", (i > 1 ? ", " : ""), k[i], v
				}
			}
			printf "}"
		}
		END { if (rows) printf "\n  " }'
}

# ── OS ──────────────────────────────────────────────────────────────────────

OS_RELEASE=/etc/os-release
[ -r "$OS_RELEASE" ] || OS_RELEASE=/usr/lib/os-release

# Parse, never source: os-release is data, not code.
os_value() {
	[ -r "$OS_RELEASE" ] || return 0
	sed -n "s/^$1=//p" "$OS_RELEASE" | head -n 1 | tr -d "\"'"
}

# ── Packages ────────────────────────────────────────────────────────────────

detect_package_manager() {
	if [ -r /lib/apk/db/installed ]; then
		echo apk
	elif have dpkg-query; then
		echo dpkg
	elif have rpm; then
		echo rpm
	elif have pacman; then
		echo pacman
	else
		echo none
	fi
}

# Output: name, version, arch, source_name, source_version (TSV)

# Arch Linux: inventory and pending updates from the local sync database
# (OSV has no Arch ecosystem, so findings aren't computed for it).
packages_pacman() {
	pacman -Q 2>/dev/null | awk 'BEGIN { OFS = "\t" } NF == 2 { print $1, $2, "", "", "" }'
}

updates_pacman() {
	out=$(pacman -Qu 2>/dev/null) || [ -z "$out" ] || return 1
	printf '%s\n' "$out" | awk 'BEGIN { OFS = "\t" } $3 == "->" { print $1, "", $4, "" }'
}

reboot_pacman() { return 1; }

# ── Containers (v3, opt-in) ─────────────────────────────────────────────────
# Reading the Docker socket is root-equivalent, so it's off unless
# HEIMDALL_DOCKER=1 (and the collector user can reach the socket).
containers_json() {
	[ "${HEIMDALL_DOCKER:-0}" = 1 ] && have docker || return 1
	out=$(docker ps -a --no-trunc --format '{{.Names}}\t{{.Image}}\t{{.State}}' 2>/dev/null) || return 1
	printf '%s\n' "$out" | clean_tsv | awk -F '\t' '
		NF >= 2 && $1 ~ /^[A-Za-z0-9][A-Za-z0-9_.-]*$/ {
			img = $2; tag = ""; digest = ""
			if (index(img, "@sha256:")) { digest = substr(img, index(img, "@") + 1); img = substr(img, 1, index(img, "@") - 1) }
			n = split(img, parts, "/"); last = parts[n]
			if (index(last, ":")) { tag = substr(last, index(last, ":") + 1); img = substr(img, 1, length(img) - length(tag) - 1) }
			if (img !~ /^[a-z0-9][a-z0-9._\/:-]*$/) next
			if (tag !~ /^([A-Za-z0-9_][A-Za-z0-9_.-]*)?$/) tag = ""
			if (digest !~ /^(sha256:[0-9a-f]{64})?$/) digest = ""
			state = tolower($3); if (state !~ /^[a-z]*$/) state = ""
			printf "%s\n    {\"name\": \"%s\", \"image\": \"%s\", \"tag\": \"%s\", \"digest\": \"%s\", \"state\": \"%s\"}", (n2++ ? "," : ""), $1, img, tag, digest, state
		}
		END { if (n2) printf "\n  " }'
}

# ── Application lockfiles (v3, allowlisted) ─────────────────────────────────
# HEIMDALL_LOCKFILES lists absolute paths: package-lock.json (npm, lockfile
# v2/v3) and requirements.txt (PyPI, pinned name==version lines).
lockfile_packages() {
	case $1 in
	*/package-lock.json)
		# Quotes are structure here, so only control characters are dropped;
		# every extracted name and version is then checked against a strict
		# pattern before it's printed.
		tr -d '\000-\010\013-\037\177' <"$1" | awk '
			/"node_modules\/[^"]+": \{/ {
				key = $0; sub(/^[^"]*"/, "", key); sub(/".*$/, "", key)
				n = split(key, p, "node_modules/"); name = p[n]
			}
			/^ *"version": "/ && name != "" {
				v = $0; sub(/^ *"version": "/, "", v); sub(/".*$/, "", v)
				if (name ~ /^(@[a-z0-9._~-]+\/)?[a-z0-9._~-]+$/ && v ~ /^[A-Za-z0-9][A-Za-z0-9._+!-]*$/) print name "\t" v
				name = ""
			}' ;;
	*/requirements*.txt)
		clean_tsv <"$1" | awk '
			{ sub(/#.*/, ""); gsub(/[ \t]/, "") }
			/^[A-Za-z0-9][A-Za-z0-9._-]*==[A-Za-z0-9][A-Za-z0-9._+!-]*$/ { split($0, p, "=="); print p[1] "\t" p[2] }' ;;
	esac
}

lockfiles_json() {
	first=1
	for f in ${HEIMDALL_LOCKFILES:-}; do
		case $f in /*) ;; *) continue ;; esac
		case $f in */../* | */./*) continue ;; esac
		case $f in */package-lock.json) eco=npm ;; */requirements*.txt) eco=PyPI ;; *) continue ;; esac
		[ -r "$f" ] || continue
		pkgs=$(lockfile_packages "$f" | awk -F '\t' '!seen[$0]++ && NF == 2 && n++ < 5000 {
			printf "%s{\"name\": \"%s\", \"version\": \"%s\"}", (n > 1 ? ", " : ""), $1, $2 }')
		[ "$first" = 1 ] || printf ','
		first=0
		printf '\n    {"path": "%s", "ecosystem": "%s", "packages": [%s]}' "$(clean "$f")" "$eco" "$pkgs"
	done
	[ "$first" = 1 ] || printf '\n  '
}
packages_dpkg() {
	dpkg-query -W -f '${db:Status-Abbrev}\t${Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\n' 2>/dev/null |
		awk -F '\t' 'BEGIN { OFS = "\t" } substr($1, 2, 1) == "i" { print $2, $3, $4, $5, $6 }'
}

packages_rpm() {
	rpm -qa --qf '%{NAME}\t%{EPOCH}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{SOURCERPM}\n' 2>/dev/null |
		awk -F '\t' 'BEGIN { OFS = "\t" }
			$1 == "gpg-pubkey" { next }
			{
				ver = $3 "-" $4
				if ($2 != "(none)" && $2 != "0") ver = $2 ":" ver
				arch = ($5 == "(none)") ? "" : $5
				# foo-1.2-3.el9.src.rpm -> source name foo, version 1.2-3.el9
				src = $6; sname = ""; sver = ""
				if (src != "(none)" && sub(/\.src\.rpm$/, "", src)) {
					n = split(src, p, "-")
					if (n >= 3) {
						sver = p[n - 1] "-" p[n]
						sname = p[1]
						for (i = 2; i <= n - 2; i++) sname = sname "-" p[i]
					}
				}
				print $1, ver, arch, sname, sver
			}'
}

# Read apk's database directly: P=name, V=version, A=arch, o=origin.
packages_apk() {
	awk 'BEGIN { OFS = "\t" }
		/^P:/ { name = substr($0, 3) }
		/^V:/ { ver = substr($0, 3) }
		/^A:/ { arch = substr($0, 3) }
		/^o:/ { origin = substr($0, 3) }
		/^$/ { if (name != "") print name, ver, arch, origin, ""; name = ver = arch = origin = "" }
		END { if (name != "") print name, ver, arch, origin, "" }' /lib/apk/db/installed
}

# ── Pending updates ─────────────────────────────────────────────────────────
# Uses the package manager's existing metadata cache (kept fresh by
# apt-daily, dnf-makecache or a cron job); it never refreshes it.
# Output: name, arch, version, security (true/false/empty) as TSV.

updates_dpkg() {
	have apt-get || return 1
	out=$(apt-get -s -o Debug::NoLocking=1 dist-upgrade 2>/dev/null) || return 1
	printf '%s\n' "$out" | awk 'BEGIN { OFS = "\t" }
		/^Inst / {
			# Inst NAME [OLD] (NEW ORIGIN[, ORIGIN...] [ARCH])
			rest = substr($0, index($0, "(") + 1)
			split(rest, f, " ")
			arch = $NF; gsub(/\(|\)|\[|\]/, "", arch)
			sec = (rest ~ /-security/ || rest ~ /Debian-Security/) ? "true" : "false"
			print $2, arch, f[1], sec
		}'
}

updates_rpm() {
	have dnf || return 1
	rc=0
	list=$(dnf -q -C check-update 2>/dev/null) || rc=$?
	# check-update exits 100 when updates exist, 0 when none.
	[ "$rc" -eq 0 ] || [ "$rc" -eq 100 ] || return 1
	security=$(dnf -q -C updateinfo list --security 2>/dev/null | awk 'NF >= 3 { print $3 }') || security=
	printf '%s\n' "$list" | SECURITY=$security awk 'BEGIN {
			OFS = "\t"; n = split(ENVIRON["SECURITY"], s, "\n"); for (i = 1; i <= n; i++) sec[s[i]] = 1
		}
		/^Obsoleting/ { exit }
		# Long names wrap: "name.arch" alone, then "version repo".
		NF == 1 && held == "" { held = $1; next }
		{
			if (held != "") { $0 = held " " $0; held = "" }
			if (NF < 3) next
			dot = 0
			for (i = length($1); i > 0; i--) if (substr($1, i, 1) == ".") { dot = i; break }
			if (!dot) next
			name = substr($1, 1, dot - 1); arch = substr($1, dot + 1)
			print name, arch, $2, ((name "-" $2 "." arch) in sec) ? "true" : "false"
		}'
}

updates_apk() {
	have apk || return 1
	out=$(apk version -l '<' 2>/dev/null) || return 1
	# busybox-1.36.1-r29  < 1.36.1-r30   (Alpine can't tell security updates)
	printf '%s\n' "$out" | awk 'BEGIN { OFS = "\t" }
		$2 == "<" { name = $1; sub(/-[^-]+-r[0-9]+$/, "", name); print name, "", $3, "" }'
}

# ── Reboot required ─────────────────────────────────────────────────────────
# Prints true/false, or returns 1 if it can't tell.

reboot_dpkg() {
	if [ -e /var/run/reboot-required ]; then
		echo true
		return 0
	fi
	# Debian kernel packages embed the release: linux-image-6.1.0-26-amd64.
	newest=$(dpkg-query -W -f '${db:Status-Abbrev} ${Package}\n' 'linux-image-[0-9]*' 2>/dev/null |
		awk 'substr($1, 2, 1) == "i" && $2 !~ /-(unsigned|dbg)$/ { sub(/^linux-image-/, "", $2); print $2 }' |
		sort -V | tail -n 1) || true
	if [ -n "$newest" ]; then
		if [ "$newest" = "$(uname -r)" ]; then echo false; else echo true; fi
	elif [ -x /usr/share/update-notifier/notify-reboot-required ]; then
		echo false # Ubuntu's notifier would have created the flag file
	else
		return 1 # no kernel package and no notifier, e.g. a container
	fi
}

reboot_rpm() {
	if have needs-restarting; then
		if needs-restarting -r >/dev/null 2>&1; then echo false; else echo true; fi
		return 0
	fi
	# Fall back to comparing the running kernel with the newest installed one.
	newest=$(rpm -q --last kernel-core kernel 2>/dev/null | awk '/^kernel/ { print $1; exit }') || true
	[ -n "$newest" ] || return 1
	newest=${newest#kernel-core-}
	newest=${newest#kernel-}
	if [ "$newest" = "$(uname -r)" ]; then echo false; else echo true; fi
}

reboot_apk() {
	running=$(uname -r)
	for flavor in lts virt edge rpi; do
		ver=$(awk -v p="linux-$flavor" '/^P:/ { hit = (substr($0, 3) == p) } hit && /^V:/ { print substr($0, 3); exit }' /lib/apk/db/installed)
		[ -n "$ver" ] || continue
		# linux-lts 6.6.52-r0 runs as 6.6.52-0-lts
		expected="${ver%-r*}-${ver##*-r}-$flavor"
		if [ "$expected" = "$running" ]; then echo false; else echo true; fi
		return 0
	done
	return 1 # no kernel package, e.g. a container
}

# ── Sites (format v2) ───────────────────────────────────────────────────────
# Web apps the host serves: enabled nginx/Apache vhosts plus any roots in
# HEIMDALL_SITES. Reads only vhost files and each app's composer.json and
# composer.lock. Never reads .env, never runs php, composer or artisan.

NGINX_VHOSTS='/etc/nginx/sites-enabled/* /etc/nginx/conf.d/*.conf /etc/nginx/http.d/*.conf'
APACHE_VHOSTS='/etc/apache2/sites-enabled/* /etc/httpd/conf.d/*.conf'

# awk helpers shared by the parsers. They mirror the hub's validation, so a
# value the hub would reject is dropped here instead of failing the snapshot.
# shellcheck disable=SC2016 # awk program, not shell
AWK_SITE_LIB='
function validpath(p,   n, parts, i) {
	if (length(p) > 512 || p !~ /^\/[A-Za-z0-9._@+-]+(\/[A-Za-z0-9._@+-]+)*$/) return 0
	n = split(p, parts, "/")
	for (i = 2; i <= n; i++) if (parts[i] == "." || parts[i] == "..") return 0
	return 1
}
function validname(s,   n, l, i) {
	if (s == "_" || s == "localhost") return 1
	if (length(s) > 253) return 0
	if (substr(s, 1, 2) == "*.") s = substr(s, 3)
	n = split(s, l, ".")
	if (n < 1) return 0
	for (i = 1; i <= n; i++)
		if (length(l[i]) < 1 || length(l[i]) > 63 || l[i] !~ /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/) return 0
	return 1
}
# php8.3-fpm.sock -> 8.3; php-fpm83 / php83-fpm (Alpine) -> 8.3
function phpver(s,   v) {
	v = ""
	if (match(s, /php[0-9]\.[0-9]+/)) v = substr(s, RSTART + 3, RLENGTH - 3)
	else if (match(s, /php-?fpm-?[0-9][0-9]+/) || match(s, /php[0-9][0-9]+/)) {
		v = substr(s, RSTART, RLENGTH); gsub(/[^0-9]/, "", v)
		v = substr(v, 1, 1) "." substr(v, 2)
	}
	return (v ~ /^[0-9]\.[0-9][0-9]?$/) ? v : ""
}
function addname(v) {
	v = tolower(v); gsub(/"/, "", v); sub(/:[0-9]+$/, "", v); sub(/\.$/, "", v)
	if (validname(v)) names = names " " v
}
'

# Prints "nginx|docroot|php|names" per server block.
nginx_vhosts() {
	for f in $NGINX_VHOSTS; do
		if [ ! -f "$f" ] || [ ! -r "$f" ]; then continue; fi
		sed -e 's/#.*$//' -e 's/[{};]/ & /g' "$f"
		echo ' __EOF__ '
	done | awk "$AWK_SITE_LIB"'
		{ for (i = 1; i <= NF; i++) tok[++n] = $i }
		END {
			for (i = 1; i <= n; i++) {
				t = tok[i]
				if (t == "__EOF__") { if (insrv) emit(); depth = 0; insrv = 0; nst = 0; continue }
				if (t == "{") {
					if (!insrv && nst == 1 && st[1] == "server") {
						insrv = 1; sdepth = depth + 1; names = ""; root = ""; php = ""
					}
					depth++; nst = 0; continue
				}
				if (t == "}") {
					depth--; nst = 0
					if (insrv && depth < sdepth) { emit(); insrv = 0 }
					continue
				}
				if (t == ";") { if (insrv) stmt(); nst = 0; continue }
				st[++nst] = t
			}
		}
		function stmt(   k, v) {
			if (st[1] == "server_name") {
				for (k = 2; k <= nst; k++) if (st[k] !~ /^~/) addname(st[k])
			} else if (st[1] == "root" && (root == "" || depth == sdepth)) {
				# The server-level root wins over one inside a location block.
				v = st[2]; gsub(/["\047]/, "", v); sub(/\/+$/, "", v)
				if (validpath(v)) root = v
			} else if (st[1] == "fastcgi_pass" && php == "") {
				php = phpver(st[2])
			}
		}
		function emit() { if (root != "") printf "nginx|%s|%s|%s\n", root, php, names }'
}

# Prints "apache|docroot|php|names" per VirtualHost.
apache_vhosts() {
	for f in $APACHE_VHOSTS; do
		if [ ! -f "$f" ] || [ ! -r "$f" ]; then continue; fi
		cat "$f"
		echo '__EOF__'
	done | awk "$AWK_SITE_LIB"'
		{ sub(/#.*/, ""); d = tolower($1) }
		d == "__eof__" { if (invh) emit(); invh = 0; next }
		d ~ /^<virtualhost/ { invh = 1; names = ""; root = ""; php = ""; next }
		d == "</virtualhost>" { if (invh) emit(); invh = 0; next }
		!invh { next }
		d == "servername" || d == "serveralias" { for (k = 2; k <= NF; k++) addname($k) }
		d == "documentroot" && root == "" {
			v = $2; gsub(/"/, "", v); sub(/\/+$/, "", v)
			if (validpath(v)) root = v
		}
		(d == "sethandler" || d == "proxypassmatch") && php == "" && /php/ { php = phpver($0) }
		function emit() { if (root != "") printf "apache|%s|%s|%s\n", root, php, names }'
}

# Every candidate as "web_server|document_root|php|names", validated.
site_candidates() {
	if [ "${HEIMDALL_DISCOVER_SITES:-1}" != 0 ]; then
		nginx_vhosts
		apache_vhosts
	fi
	set -f # HEIMDALL_SITES is a list of paths, not globs
	# shellcheck disable=SC2086 # word splitting is intended
	printf '%s\n' ${HEIMDALL_SITES:-} | awk "$AWK_SITE_LIB"'
		{ p = $0; sub(/\/+$/, "", p); if (validpath(p)) printf "|%s||\n", p }'
	set +f
}

# A Laravel docroot is <app>/public; the app root holds composer.json.
resolve_root() {
	case $1 in
	*/public)
		if [ -e "${1%/public}/composer.json" ]; then
			echo "${1%/public}"
			return
		fi
		;;
	esac
	echo "$1"
}

# "name<TAB>version" for every package in a pretty-printed composer.lock
# (packages and packages-dev). Authors' "name" fields don't look like
# vendor/package and are skipped.
composer_packages() {
	awk 'BEGIN { OFS = "\t" }
		/^[ \t]*"name"[ \t]*:/ {
			v = $0; sub(/^[^:]*:[ \t]*"/, "", v); sub(/".*$/, "", v)
			if (v ~ /^[a-z0-9]([_.-]?[a-z0-9]+)*\/[a-z0-9](([_.]|-|--)?[a-z0-9]+)*$/) pending = v
			next
		}
		/^[ \t]*"version"[ \t]*:/ && pending != "" {
			v = $0; sub(/^[^:]*:[ \t]*"/, "", v); sub(/".*$/, "", v)
			if (v ~ /^v[0-9]/) v = substr(v, 2)
			if (length(v) <= 100 && v ~ /^[A-Za-z0-9][A-Za-z0-9._+-]*$/ && !seen[pending]++ && n < 3000) {
				print pending, v; n++
			}
			pending = ""
		}' "$1"
}

# composer.json require.php, e.g. "^8.2".
composer_php_requirement() {
	awk '/"require"[ \t]*:[ \t]*\{[ \t]*\}/ { exit }
		/"require"[ \t]*:[ \t]*\{/ { inreq = 1; next }
		inreq && /^[ \t]*\}/ { exit }
		inreq && /^[ \t]*"php"[ \t]*:/ {
			v = $0; sub(/^[^:]*:[ \t]*"/, "", v); sub(/".*$/, "", v)
			if (length(v) <= 100 && v ~ /^[0-9A-Za-z .,|<>=^~*@-]*$/) print v
			exit
		}' "$1"
}

# One site as JSON. Composer data is only read when the app directory and
# its composer files are readable by this (unprivileged) user.
site_json() {
	root=$1 ws=$2 docroot=$3 php=$4 names=$5
	readable=false
	if [ -d "$root" ] && [ -x "$root" ]; then
		readable=true
		for f in "$root/composer.json" "$root/composer.lock"; do
			if [ -e "$f" ] && [ ! -r "$f" ]; then readable=false; fi
		done
	fi
	framework='' fwver='' phpreq='' deployed=null pkgs=''
	if [ "$readable" = true ]; then
		[ ! -f "$root/composer.json" ] || phpreq=$(composer_php_requirement "$root/composer.json")
		if [ -f "$root/composer.lock" ]; then
			tsv=$(composer_packages "$root/composer.lock")
			pkgs=$(printf '%s\n' "$tsv" | tsv_to_json name version)
			fwver=$(printf '%s\n' "$tsv" | awk -F '\t' '$1 == "laravel/framework" { print $2; exit }')
			[ -z "$fwver" ] || framework=laravel
			if ts=$(stat -c %Y "$root/composer.lock" 2>/dev/null) &&
				d=$(date -u -d "@$ts" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null); then
				deployed="\"$d\""
			fi
		fi
	fi
	# shellcheck disable=SC2086 # word splitting is intended
	server_names=$(printf '%s\n' $names | awk 'NF { printf "%s\"%s\"", (n++ ? ", " : ""), $0 }')
	printf '{"root": "%s", "document_root": "%s", "server_names": [%s], "web_server": "%s", "php_fpm_version": "%s", "readable": %s, "framework": "%s", "framework_version": "%s", "php_requirement": "%s", "deployed_at": %s, "composer_packages": [%s]}' \
		"$(clean "$root")" "$(clean "$docroot")" "$server_names" "$ws" "$php" "$readable" \
		"$framework" "$(clean "$fwver")" "$(clean "$phpreq")" "$deployed" "$pkgs"
}

# All sites as the body of a JSON array, de-duplicated by app root (server
# names are merged; the first web server and PHP version found win).
sites_json() {
	site_candidates | while IFS='|' read -r ws docroot php names; do
		[ -n "$docroot" ] || continue
		printf '%s|%s|%s|%s|%s\n' "$(resolve_root "$docroot")" "$ws" "$docroot" "$php" "$names"
	done | awk -F '|' "$AWK_SITE_LIB"'
		!validpath($1) { next }
		!($1 in ws) {
			if (count >= 200) next
			order[++count] = $1; ws[$1] = $2; doc[$1] = $3
		}
		{
			if (php[$1] == "") php[$1] = $4
			n = split($5, nm, " ")
			for (i = 1; i <= n; i++)
				if (!seen[$1 SUBSEP nm[i]]++ && nnames[$1]++ < 50) all[$1] = all[$1] " " nm[i]
		}
		END { for (i = 1; i <= count; i++) { r = order[i]; printf "%s|%s|%s|%s|%s\n", r, ws[r], doc[r], php[r], all[r] } }' |
		{
			n=0
			while IFS='|' read -r root ws docroot php names; do
				[ "$n" -eq 0 ] || printf ','
				printf '\n    '
				site_json "$root" "$ws" "$docroot" "$php" "$names"
				n=$((n + 1))
			done
			[ "$n" -eq 0 ] || printf '\n  '
		}
}

# ── Snapshot ────────────────────────────────────────────────────────────────

self_sha256() {
	# When piped into `sh -s`, $0 is the shell itself and there is no file.
	case $0 in sh | -sh | */sh | dash | */dash | bash | */bash | ash | */ash) return 1 ;; esac
	[ -f "$0" ] && [ -r "$0" ] && have sha256sum || return 1
	sha256sum <"$0" | awk '{ print $1 }'
}

snapshot() {
	pm=$(detect_package_manager)

	sha=$(self_sha256) || { sha=; unavailable collector_sha256; }

	uptime=0
	if [ -r /proc/uptime ]; then
		uptime=$(awk '{ printf "%d", $1 }' /proc/uptime)
	else
		unavailable uptime
	fi

	reboot=null
	case $pm in
	dpkg | rpm | apk | pacman) reboot=$("reboot_$pm") || reboot=null ;;
	esac
	[ "$reboot" != null ] || unavailable reboot_required

	packages=
	case $pm in
	dpkg | rpm | apk | pacman) packages=$("packages_$pm" | tsv_to_json name version arch source_name source_version) ;;
	esac
	[ -n "$packages" ] || unavailable packages

	updates=
	case $pm in
	dpkg | rpm | apk | pacman)
		if tsv=$("updates_$pm"); then
			updates=$(printf '%s\n' "$tsv" | tsv_to_json name arch version security)
		else
			unavailable updates
		fi
		;;
	*) unavailable updates ;;
	esac
	# Packages unavailable implies updates are meaningless too.
	if [ -z "$packages" ] && [ -n "$updates" ]; then updates=; unavailable updates; fi

	sites=$(sites_json)
	containers=$(containers_json) || { containers=; unavailable containers; }
	lockfiles=$(lockfiles_json)

	# shellcheck disable=SC2086 # word splitting is intended
	unavail=$(printf '%s\n' $UNAVAILABLE | awk 'NF && !seen[$0]++ { printf "%s\"%s\"", (n++ ? ", " : ""), $0 }')
	[ "$pm" != none ] || pm=

	cat <<EOF
{
  "format": "$FORMAT",
  "collector": { "version": "$VERSION", "sha256": "$sha" },
  "collected_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "os": {
    "id": "$(clean "$(os_value ID)")",
    "id_like": "$(clean "$(os_value ID_LIKE)")",
    "version_id": "$(clean "$(os_value VERSION_ID)")",
    "version_codename": "$(clean "$(os_value VERSION_CODENAME)")",
    "pretty_name": "$(clean "$(os_value PRETTY_NAME)")"
  },
  "kernel": { "release": "$(clean "$(uname -r)")", "arch": "$(clean "$(uname -m)")" },
  "uptime_seconds": $uptime,
  "reboot_required": $reboot,
  "package_manager": "$pm",
  "packages": [$packages],
  "updates": [$updates],
  "unavailable": [$unavail],
  "sites": [$sites],
  "containers": [$containers],
  "lockfiles": [$lockfiles]
}
EOF
}

# ── Push ────────────────────────────────────────────────────────────────────

push() {
	url=${HEIMDALL_URL:-}
	token_file=${HEIMDALL_TOKEN_FILE:-/etc/heimdall/token}
	[ -n "$url" ] || die "HEIMDALL_URL is not set"
	case $url in
	https://*) ;;
	http://127.0.0.1[:/]* | http://localhost[:/]* | http://\[::1\][:/]*) ;; # local proxy or tests
	*) die "HEIMDALL_URL must use https://" ;;
	esac
	have curl || die "curl is required for --push"
	[ -r "$token_file" ] || die "cannot read token file $token_file"
	if [ -n "$(find "$token_file" -prune \( -perm -040 -o -perm -004 \) 2>/dev/null)" ]; then
		die "$token_file is readable by other users; run: chmod 400 $token_file"
	fi
	token=$(tr -d ' \t\r\n' <"$token_file")
	case $token in
	'' | *[!A-Za-z0-9_-]*) die "token file $token_file does not contain a valid token" ;;
	esac

	tmp=$(mktemp -d)
	trap 'rm -rf "$tmp"' EXIT
	snapshot >"$tmp/snapshot.json"
	body=$tmp/snapshot.json
	encoding=
	if have gzip; then
		gzip -c "$body" >"$tmp/snapshot.json.gz"
		body=$tmp/snapshot.json.gz
		encoding='header = "Content-Encoding: gzip"'
	fi
	cacert=
	if [ -n "${HEIMDALL_CA_FILE:-}" ]; then
		[ -r "$HEIMDALL_CA_FILE" ] || die "cannot read $HEIMDALL_CA_FILE"
		cacert="cacert = \"$HEIMDALL_CA_FILE\""
	fi

	# The token goes to curl on stdin via --config (printf is a shell
	# builtin), so it never appears in any process's arguments.
	status=$(printf '%s\n' \
		"header = \"Authorization: Bearer $token\"" \
		'header = "Content-Type: application/json"' \
		"$encoding" "$cacert" |
		curl --config - --silent --show-error \
			--proto '=https,http' --tlsv1.2 \
			--connect-timeout 10 --max-time 120 \
			--retry 2 --retry-delay 10 \
			--data-binary "@$body" \
			--output /dev/null --write-out '%{http_code}' \
			"${url%/}/api/v1/ingest") || die "could not reach $url"

	case $status in
	2??) ;;
	401 | 403) die "hub rejected the token (HTTP $status); check $token_file" ;;
	409) die "hub rejected a duplicate snapshot (HTTP 409)" ;;
	413) die "snapshot too large for the hub (HTTP 413)" ;;
	422) die "hub rejected the snapshot as invalid (HTTP 422); run --print and check it with 'heimdall import --check'" ;;
	429) die "rate limited by the hub (HTTP 429); try again later" ;;
	*) die "hub returned HTTP $status" ;;
	esac
}

# ── Main ────────────────────────────────────────────────────────────────────

usage() {
	cat >&2 <<'EOF'
usage: heimdall-collect --print | --push | --version

  --print    write a snapshot to stdout (for review or 'heimdall import')
  --push     send a snapshot to $HEIMDALL_URL using $HEIMDALL_TOKEN_FILE
  --version  print the collector version
EOF
	exit 2
}

[ $# -eq 1 ] || usage
case $1 in
--version) echo "$VERSION"; exit 0 ;;
--print | --push) ;;
*) usage ;;
esac

if [ "$(id -u)" -eq 0 ] && [ "${HEIMDALL_ALLOW_ROOT:-}" != 1 ]; then
	die "refusing to run as root; run as the unprivileged 'heimdall' user"
fi

case $1 in
--print) snapshot ;;
--push) push ;;
esac
