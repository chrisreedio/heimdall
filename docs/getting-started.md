# Getting started

> **What works today:** setting up the hub, registering hosts, servers reporting in with the [collector](collector.md), and vulnerability findings with OS and runtime end-of-life status (`heimdall report`).
> Plus the **web UI**: dashboard, host pages and fleet search.

## 1. One-time setup

You need **Go 1.27+**. On this machine it's installed in `~/.local/go`, so add it to your shell:

```sh
echo 'export PATH=$HOME/.local/go/bin:$PATH' >> ~/.zshrc && source ~/.zshrc
```

Build the binary:

```sh
make build        # → bin/heimdall (a single static file you can copy anywhere)
```

## 2. First run

```sh
./bin/heimdall init                                   # creates heimdall.toml + heimdall.db
./bin/heimdall org  create acme --name "Acme Corp"
./bin/heimdall env  create prod
./bin/heimdall host add web-01 > web-01.token
```

`host add` prints the host's **ingest token**, and only the token, to stdout, so `> file` captures it cleanly. Move that file to the server as `/etc/heimdall/token` (in M1), then delete your local copy.

## 3. Commands

| Command | What it does |
|---|---|
| `heimdall init [--database path]` | Create config and database. Refuses to overwrite either one. |
| `heimdall migrate` | Upgrade the database schema after installing a new version |
| `heimdall org create <slug> [--name "…"]` | Add an organization |
| `heimdall org list` | List orgs with their host counts |
| `heimdall env create <slug>` | Add an environment (e.g. `prod`, `staging`) |
| `heimdall env list` | List environments |
| `heimdall host add [--env <env>] [--tag t] <hostname>` | Register a host and print its token |
| `heimdall host list` | List hosts with their tags and last check-in |
| `heimdall host show <hostname>` | Latest snapshot summary and open anomalies |
| `heimdall host token --rotate <hostname>` | Revoke a host's token and print a new one |
| `heimdall host rm --yes <hostname>` | Delete a host **and all its history** |
| `heimdall enroll create [--env <env>] [--tag t] [--expires 24h] [--uses N] [--no-approval]` | Print an expiring enrollment key that adds many servers, each with its own token (see [Many servers](collector.md#many-servers-enrollment-keys)) |
| `heimdall enroll list` / `enroll revoke <id>` | List enrollment keys with their uses and status; stop one early |
| `heimdall enroll pending` / `enroll approve <hostname>...` | Servers enrolled with a key that requires approval, and letting them report (reject with `host rm`) |
| `heimdall serve` | Run the ingest listener that collectors push to |
| `heimdall import [--check] <file.json>` | Store a snapshot collected by hand, or just validate it |
| `heimdall collector trust --version <v> <sha256>` / `collector list` | Mark collector releases as known-good, and see which hosts run what |
| `heimdall feeds sync` / `feeds status` | Refresh OSV, CISA KEV and end-of-life data now, and show when each feed last synced |
| `heimdall report [--format json] [--limit N]` | What to patch first: findings per host (known-exploited, then fixable, then by severity) plus OS and runtime end-of-life |
| `heimdall version` | Print the version |

**One org, one install.** Heimdall expects one install per organization, so `--org` is optional when there's only one org, and `--env` is optional when the org has only one environment. With several, Heimdall asks you to pick, and never guesses.

Flags can go before or after the name: `host add web-01 --env prod` works too.

To use a config file other than `./heimdall.toml`, put `-c` **before** the command (`heimdall -c /etc/heimdall/heimdall.toml host list`) or set `HEIMDALL_CONFIG`.

---

## 4. Signing in to the web UI

```sh
heimdall user create --admin you@example.com   # password twice, then scan the QR code shown in the terminal
heimdall serve                                 # UI on 127.0.0.1:8080, ingest on its own port
```

- **On the hub itself, or over an SSH tunnel:** `ssh -L 8080:127.0.0.1:8080 hub`, then open http://127.0.0.1:8080.
- **Over your tailnet:** run `tailscale serve --bg 8080` on the hub and set `ui.base_url` to the `https://…ts.net` address it prints. Caddy works the same way.
- **Plain http is refused off loopback**, because session cookies must never cross the network unencrypted.
- **Sign-in needs** email, password and the current 6-digit code. Each code works only once.
- **Accounts:** `user list`, `user disable|enable`, `user passwd` and `user reset-totp`. All four end the user's active sessions.

## Things you need to know

### 🔑 Tokens
- **A token is shown once.** Heimdall stores only its hash and can't show it again.
- **Lost a token, or think it leaked?** Run `heimdall host token --rotate <hostname>`. The old token stops working immediately.
- **Treat tokens like passwords.** A token can only *send* reports for its one host, but don't paste it into chat or commit it.

### 📛 Names
- **Org and env slugs** are lowercase letters, digits and `-`, e.g. `acme`, `client-two`.
- **Hostnames are lowercased** automatically, so `Web-01` becomes `web-01`.
- **Tags** are lowercase and can include `:`, e.g. `--tag web --tag role:lb`, or `--tag web,role:lb`.
- **Create an environment** with `env create` before adding hosts to it. Heimdall won't invent one from a typo.

### 🔒 Safety rails you'll hit
| You'll see | Why | Fix |
|---|---|---|
| `database … has permissions 0644` | The database lists every server's weak spots, so only its owner may read it | `chmod 600 heimdall.db` |
| `unknown keys: ui.lisen` | Typos in the config are errors, not silent defaults | Fix the key name |
| `listening on ":8443" without TLS` | Ingest can't be exposed publicly without encryption | Bind to `127.0.0.1` behind Caddy, or set `tls_cert`/`tls_key` |
| `schema is at version N, need M` | You upgraded Heimdall | `heimdall migrate` |
| `re-run with --yes` | `host rm` permanently deletes history | Add `--yes` if you mean it |
| `already exists; refusing to overwrite` | `init` never clobbers an existing setup | Use `-c` to point at a different location |

### 📁 Files
- `heimdall.toml` holds settings only and never secrets. A relative `database` path is resolved next to this file.
- `heimdall.db` is **everything**: inventory, tokens (hashed) and the audit log. Back it up with:
  ```sh
  sqlite3 heimdall.db ".backup heimdall-$(date +%F).db"
  ```
  An encrypted `heimdall backup` command is coming in M10. Until then, keep backups somewhere private.
- Both files are git-ignored. **Never commit them.**

### 📜 Audit log
Every org, env, host and token change is recorded with who made it. Until `heimdall audit` exists, read it with:
```sh
sqlite3 -header -column heimdall.db "SELECT at, actor, action, target, detail FROM audit_log ORDER BY id DESC LIMIT 20"
```
The log can't be edited or deleted, even by a bug in Heimdall.

### 🚦 Exit codes
`0` means success, `1` means an error (the message is on stderr) and `2` means wrong usage (the help text is printed).

---

## For development

```sh
make test         # run tests
make check        # everything CI runs: gofmt, vet, staticcheck, govulncheck, tests
make vendor       # after changing dependencies (review the vendor/ diff)
```

The Go module path is `github.com/realmwatch/heimdall`. Change it in `go.mod` and the imports if your repo lives elsewhere.
