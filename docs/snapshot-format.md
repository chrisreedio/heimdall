# Snapshot format (v1 and v2)

> The JSON document `collect.sh` produces and the hub accepts.
> Source of truth: [`internal/snapshot/snapshot.go`](../internal/snapshot/snapshot.go) and [`sites.go`](../internal/snapshot/sites.go).

| Format | Emitted by | Adds |
|---|---|---|
| `heimdall.snapshot/v1` | collector 0.1.x | OS, kernel, packages, pending updates |
| `heimdall.snapshot/v2` | collector 0.2+ | everything in v1, plus [`sites`](#sites-v2): web apps, PHP-FPM versions, Laravel and Composer packages |

The hub accepts both, so collectors can be upgraded one server at a time.

## At a glance

- **One JSON object per check-in.** It's sent as the body of `POST /api/v1/ingest`, or saved to a file for `heimdall import`.
- **The collector reports raw facts.** The hub works out everything else, such as which vulnerability feed applies, so fixing that logic never means updating your servers.
- **Strict.** Unknown fields, trailing data, odd characters or a list that's too long get the whole snapshot rejected. Nothing is silently "cleaned up".
- **The hub never trusts it.** A compromised host can send anything, so every field is validated as if it were hostile.

## Example

```json
{
  "format": "heimdall.snapshot/v1",
  "collector": { "version": "0.1.0", "sha256": "9f2c…5f60" },
  "collected_at": "2026-10-22T04:17:03Z",
  "os": {
    "id": "debian", "id_like": "", "version_id": "12",
    "version_codename": "bookworm", "pretty_name": "Debian GNU/Linux 12 (bookworm)"
  },
  "kernel": { "release": "6.1.0-26-amd64", "arch": "x86_64" },
  "uptime_seconds": 1209600,
  "reboot_required": true,
  "package_manager": "dpkg",
  "packages": [
    { "name": "libssl3", "version": "3.0.14-1~deb12u2", "arch": "amd64",
      "source_name": "openssl", "source_version": "3.0.14-1~deb12u2" }
  ],
  "updates": [
    { "name": "openssh-server", "arch": "amd64", "version": "1:9.2p1-2+deb12u5", "security": true }
  ],
  "unavailable": []
}
```

Full examples: [`debian12.json`](../internal/snapshot/testdata/debian12.json) and [`alpine320.json`](../internal/snapshot/testdata/alpine320.json).

## Fields

| Field | What it is | Rules |
|---|---|---|
| `format` | Always `heimdall.snapshot/v1` | Exact match |
| `collector.version` | Collector release | Semver, e.g. `0.1.0` |
| `collector.sha256` | Checksum of the collector script itself | 64 lowercase hex characters, checked against trusted releases (M8). Empty only when declared unavailable, e.g. when piped into `ssh host sh -s`. |
| `collected_at` | When the host ran the collector | RFC 3339 timestamp. Compared with the time received to spot clock skew and replays. |
| `os.*` | Raw values from `/etc/os-release` | `id` is required (lowercase `a-z 0-9 . _ -`). `pretty_name` is at most 128 characters with no control characters. |
| `kernel.release` | `uname -r` | Required |
| `kernel.arch` | `uname -m` | Required |
| `uptime_seconds` | Seconds since boot | 0 to 20 years |
| `reboot_required` | Whether a reboot is pending | `true`, `false`, or `null` if unknown |
| `package_manager` | Which package manager was used | `dpkg`, `rpm` or `apk` |
| `packages[]` | Every installed package | At most 20,000. No duplicate name, arch and version. |
| `packages[].source_*` | The source package, if the manager tracks one | Optional. Used for advisory matching, since Debian advisories are per source package. |
| `updates[]` | Pending upgrades | `security` is `true`, `false` or `null` if the manager can't tell (e.g. Alpine) |
| `unavailable[]` | Checks the collector couldn't run | Any of `packages`, `updates`, `reboot_required`, `uptime`, `collector_sha256`, and `sites` (v2 only) |
| `sites[]` | v2 only: web apps on the host | See [Sites (v2)](#sites-v2). Must be absent in v1, present in v2 (`[]` for none). |

**Allowed characters** for package names and versions are letters, digits and `. _ + ~ : ^ -`. That covers dpkg epochs (`1:9.2p1`), tildes (`~deb12u2`) and rpm carets. Spaces, quotes, `<`, `;` and so on are rejected.

## Sites (v2)

```json
"sites": [
  {
    "root": "/home/forge/example.com",
    "document_root": "/home/forge/example.com/public",
    "server_names": ["example.com", "www.example.com"],
    "web_server": "nginx",
    "php_fpm_version": "8.3",
    "readable": true,
    "framework": "laravel",
    "framework_version": "11.31.0",
    "php_requirement": "^8.2",
    "deployed_at": "2026-10-20T15:04:05Z",
    "composer_packages": [
      { "name": "laravel/framework", "version": "11.31.0" },
      { "name": "guzzlehttp/guzzle", "version": "7.9.2" }
    ]
  }
]
```

| Field | What it is | Rules |
|---|---|---|
| `root` | The app root: the folder holding `composer.json` | Absolute path using `A-Z a-z 0-9 . _ @ + -`, no `.`/`..` segments, at most 512 characters. Unique per snapshot. |
| `document_root` | What the web server serves (often `<root>/public`) | Same path rules |
| `server_names[]` | Hostnames from `server_name` / `ServerName` / `ServerAlias` | Lowercase DNS names, optionally `*.`-prefixed, plus `_` and `localhost`. At most 50. |
| `web_server` | Where the site was found | `nginx`, `apache`, or `""` when listed in `HEIMDALL_SITES` |
| `php_fpm_version` | The PHP-FPM pool the vhost passes PHP to | `"8.3"`-style, or `""` if it can't be told (e.g. a TCP pool) |
| `readable` | Whether the collector could read the app's composer files | `false` means there must be no framework, version, requirement, deploy time or packages |
| `framework` / `framework_version` | `laravel` when `composer.lock` has `laravel/framework` | Version without the leading `v` |
| `php_requirement` | `require.php` from `composer.json` | At most 100 characters of `0-9 A-Z a-z . , \| < > = ^ ~ * @ -` and spaces |
| `deployed_at` | `composer.lock` modification time | RFC 3339, or `null` |
| `composer_packages[]` | Every package in `composer.lock` (`packages` and `packages-dev`) | Composer `vendor/package` names, versions like `7.9.2` or `dev-main`. No duplicates. At most 3,000. |

At most 200 sites per snapshot. As with every other field, one bad value rejects the whole snapshot. The collector applies the same rules before sending, so values that wouldn't pass are dropped on the host instead.

## The `unavailable` rule

A check the collector can't run is **declared**, never silently missing:

- Listed as unavailable → its field must be empty, `0` or `null`.
- Not listed → its field must have real data. For example, an empty `packages` list must be declared.

This keeps "the collector couldn't check" separate from "nothing to report". A collector that suddenly stops reporting something is itself worth noticing.

## What happens on the hub (ingest, being built in M1)

1. The body is capped (`ingest.max_body`, 5 MB by default), including after gzip decompression.
2. The document is decoded strictly and validated. If anything fails, the whole snapshot is rejected, and the response names up to 20 bad fields.
3. The SHA-256 of the exact bytes received is checked against earlier snapshots. A duplicate is a **replay** (M1). A quick network retry gets an idempotent success instead.
4. The snapshot and its packages are stored **append-only**.

## Changing the format

- **Adding an optional field** still needs a new format version, because the hub rejects unknown fields. Strictness is the point.
- **New version:** `heimdall.snapshot/v2` added `sites`. The hub accepts v1 and v2, so collectors can be upgraded gradually. A future v3 would follow the same pattern.

## Version 3 additions

`heimdall.snapshot/v3` is v2 plus two lists. Both are required in v3 (use `[]` for none), forbidden in v1 and v2, and can be declared in `unavailable`:

| Field | Contents |
|---|---|
| `containers[]` | `name`, `image`, `tag`, `digest` (`sha256:…` or empty), `state`. At most 500. |
| `lockfiles[]` | `path` (absolute), `ecosystem` (`npm` or `PyPI`), `packages[]` with `name` and `version`. At most 50 files and 5,000 packages each. |

`package_manager` also accepts `pacman` and `windows`. Windows program names may contain spaces and common punctuation, but never quotes, angle brackets or control characters.
