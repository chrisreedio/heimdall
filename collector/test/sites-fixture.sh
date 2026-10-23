#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Creates fake web server vhosts and PHP apps (files only; nothing is
# installed or run) so the collector's site discovery can be tested.
# Run as root inside a throwaway container, before the collector.
#
# Expected results are asserted by TestCollectorSites in
# internal/snapshot/collector_test.go.
set -eu

mkdir -p /etc/nginx/sites-enabled /etc/nginx/conf.d /etc/nginx/http.d /etc/apache2/sites-enabled

# A Laravel lock file: packages + packages-dev, with authors arrays whose
# "name" entries must not be mistaken for packages.
laravel_lock() { # $1 = laravel/framework version
	cat <<EOF
{
    "_readme": [
        "This file locks the dependencies of your project to a known state"
    ],
    "content-hash": "0123456789abcdef0123456789abcdef",
    "packages": [
        {
            "name": "guzzlehttp/guzzle",
            "version": "7.9.2",
            "source": {
                "type": "git",
                "url": "https://github.com/guzzle/guzzle.git",
                "reference": "d281ed313b989f213357e3be1a179f02196ac99b"
            },
            "require": {
                "php": "^7.2.5 || ^8.0"
            },
            "authors": [
                {
                    "name": "Graham Campbell",
                    "email": "hello@gjcampbell.co.uk"
                },
                {
                    "name": "Michael Dowling",
                    "homepage": "https://github.com/mtdowling"
                }
            ],
            "time": "2024-07-24T11:22:20+00:00"
        },
        {
            "name": "laravel/framework",
            "version": "$1",
            "authors": [
                {
                    "name": "Taylor Otwell",
                    "email": "taylor@laravel.com"
                }
            ]
        },
        {
            "name": "symfony/http-foundation",
            "version": "v7.1.6"
        }
    ],
    "packages-dev": [
        {
            "name": "phpunit/phpunit",
            "version": "11.4.3",
            "authors": [
                {
                    "name": "Sebastian Bergmann",
                    "role": "lead"
                }
            ]
        }
    ],
    "aliases": [],
    "minimum-stability": "stable",
    "platform": {
        "php": "^8.2"
    }
}
EOF
}

laravel_app() { # $1 = app root, $2 = laravel version, $3 = require.php
	mkdir -p "$1/public"
	cat >"$1/composer.json" <<EOF
{
    "name": "laravel/laravel",
    "type": "project",
    "require": {
        "php": "$3",
        "laravel/framework": "^11.0"
    },
    "require-dev": {
        "phpunit/phpunit": "^11.0"
    }
}
EOF
	laravel_lock "$2" >"$1/composer.lock"
	echo '<?php // public/index.php' >"$1/public/index.php"
	echo 'APP_KEY=base64:must-never-be-read' >"$1/.env"
	chmod 600 "$1/.env"
}

# 1. Forge-style site: TLS block with PHP 8.3, plus a redirect block (no root).
laravel_app /home/forge/example.com 'v11.31.0' '^8.2'
cat >/etc/nginx/sites-enabled/example.com <<'EOF'
# FORGE CONFIG (DO NOT REMOVE!)
include forge-conf/example.com/before/*;

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name example.com www.example.com;
    server_tokens off;
    root /home/forge/example.com/public;   # app lives one level up

    index index.html index.htm index.php;
    charset utf-8;

    include forge-conf/example.com/server/*;

    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }

    location ~ \.php$ {
        fastcgi_split_path_info ^(.+\.php)(/.+)$;
        fastcgi_pass unix:/var/run/php/php8.3-fpm.sock;
        fastcgi_index index.php;
        include fastcgi_params;
    }
}

server {
    listen 80;
    server_name example.com www.example.com;
    return 301 https://$host$request_uri;
}
EOF
# Same app under another name: must merge into the same site.
cat >/etc/nginx/sites-enabled/example.org <<'EOF'
server { server_name example.org; root /home/forge/example.com/public; }
EOF

# 2. Several blocks in one file: an upstream (not a site), a regex name
#    (skipped), an API on PHP 8.2 and a catch-all static default.
laravel_app /var/www/api 'v10.48.22' '^8.1'
mkdir -p /var/www/html
cat >/etc/nginx/sites-enabled/multi <<'EOF'
upstream php_pool {
    server 127.0.0.1:9000;
}
server {
    server_name api.example.com ~^(?<tenant>.+)\.api\.example\.com$;
    root "/var/www/api/public";
    location ~ \.php$ { fastcgi_pass unix:/run/php/php8.2-fpm.sock; }
}
server {
    listen 80 default_server;
    server_name _;
    root /var/www/html;
}
EOF

# 3. An app the collector user can't enter at all.
laravel_app /home/locked/app 'v11.0.0' '^8.2'
chmod 700 /home/locked
cat >/etc/nginx/conf.d/locked.conf <<'EOF'
server { server_name locked.example.com; root /home/locked/app/public; fastcgi_pass 127.0.0.1:9000; }
EOF

# 4. Apache vhost with PHP-FPM via proxy:unix and an unreadable lock file.
laravel_app /var/www/legacy 'v8.83.27' '^7.4|^8.0'
chmod 000 /var/www/legacy/composer.lock
cat >/etc/apache2/sites-enabled/legacy.conf <<'EOF'
<VirtualHost *:80>
    ServerName legacy.example.com
    ServerAlias old.example.com:80
    DocumentRoot "/var/www/legacy/public"
    <FilesMatch \.php$>
        SetHandler "proxy:unix:/run/php/php8.1-fpm.sock|fcgi://localhost"
    </FilesMatch>
</VirtualHost>
EOF

# 5. Alpine naming: php-fpm83 socket under http.d.
laravel_app /var/www/alp 'v11.31.0' '^8.3'
cat >/etc/nginx/http.d/alp.conf <<'EOF'
server {
	server_name alp.example.com;
	root /var/www/alp/public;
	location ~ \.php$ { fastcgi_pass unix:/run/php-fpm83/php-fpm.sock; }
}
EOF

# 6. A queue worker with no vhost, listed in HEIMDALL_SITES.
laravel_app /srv/worker 'v11.31.0' '^8.2'

chmod 755 /home/forge

# Collector settings, read by run-containers.sh. The "../" entry must be
# dropped; the missing path is reported as an unreadable site.
# 7. Allowlisted application lockfiles (npm v3 lockfile and pinned pip).
mkdir -p /srv/js /srv/py
cat >/srv/js/package-lock.json <<'JSON'
{
  "name": "frontend",
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "frontend", "version": "1.0.0" },
    "node_modules/lodash": {
      "version": "4.17.20",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz"
    },
    "node_modules/@babel/core": {
      "version": "7.24.0"
    },
    "node_modules/@babel/core/node_modules/semver": {
      "version": "6.3.1"
    }
  }
}
JSON
printf 'Django==4.2.11\nrequests == 2.31.0  # pinned\n-e git+https://example.com/x.git\nflask>=2\n' >/srv/py/requirements.txt
chmod -R a+rX /srv/js /srv/py

cat >/tmp/collect.env <<'ENV'
HEIMDALL_SITES='/srv/worker /srv/../etc /var/www/missing'
HEIMDALL_LOCKFILES='/srv/js/package-lock.json /srv/py/requirements.txt /srv/../etc/passwd relative/package-lock.json'
ENV
chmod 644 /tmp/collect.env
