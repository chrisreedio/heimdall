# Where to host Heimdall

> Heimdall is small: one static binary, one SQLite file and almost no CPU. **1 vCPU and 1–2 GB of RAM is plenty** for a few hundred hosts. Disk grows with snapshot history (see `hosts.keep_snapshots_for`), and 20 GB goes a long way.

The hub needs exactly two things:
- **A private way in for you:** the UI and MCP over your tailnet. They're never public.
- **One HTTPS endpoint your servers can reach:** ingest. It's public only if some servers aren't on the tailnet.

## Which option?

| Option | Good when | Watch out for |
|---|---|---|
| **Small VPS** (Hetzner, DigitalOcean, Vultr, Linode) | You want the simplest always-on setup, and some servers aren't on your tailnet | You patch the VPS yourself (Heimdall will tell you when) |
| **Local box** (mini PC, NAS VM, Raspberry Pi 4/5) + Tailscale | Every server is on your tailnet, or you use Tailscale Funnel for ingest | Power and internet outages show up as "silent hosts", so back up off-box |
| **AWS** (Lightsail or a small EC2) | An org's policy says "it lives in our AWS", or you already manage AWS well | More moving parts than the job needs. Keep it to one small instance. Lightsail is the simple, flat-priced option; EC2 when the org needs its VPC, IAM roles or security tooling. |
| **Azure** (a small VM) | The org runs on Microsoft and you use Entra SSO anyway | Same as AWS |

**Recommendation:** a small VPS or Lightsail instance per organization, with Tailscale on it. Use AWS or Azure when an org asks for it.

Don't use serverless, containers-as-a-service or managed databases. Heimdall is a single process writing to a local SQLite file, so it wants one ordinary VM with a persistent disk.

---

## Common setup (any Linux VM)

1. **Ubuntu 24.04 or Debian 12**, fully updated, with unattended-upgrades on.
2. **Tailscale**, so you reach the box (and the UI, and MCP) without opening SSH to the internet:
   ```sh
   curl -fsSL https://tailscale.com/install.sh | sh && sudo tailscale up --ssh
   ```
3. **Heimdall**, following [deployment.md](deployment.md). UI and MCP via `tailscale serve`, ingest via Caddy (or `tailscale serve` too, if every server is on the tailnet).
4. **Firewall:** inbound **443 only** (Caddy's public ingest), and nothing at all if ingest is tailnet-only. The cloud firewall and `ufw` should agree.
5. **Backups:** schedule `heimdall backup --age-recipient …` and copy the `.age` files off the box (object storage or another machine).
6. **Watch the watcher:** install the collector on the hub too (see "Collecting on the hub's own box" in [collector.md](collector.md)).

### Behind Cloudflare's proxy

To keep Cloudflare (WAF, DDoS protection) in front of public ingest, Caddy can't get a Let's Encrypt certificate itself: the challenge reaches Cloudflare, not the box. Use a **Cloudflare Origin certificate** instead:
1. In Cloudflare: **SSL/TLS → Origin Server → Create certificate** for your ingest host (the 15-year default is fine). Keep the page open.
2. On the hub: `sudo heimdall ingest cert`. Paste the certificate, then the private key (hidden). It checks that they match and cover the ingest host, installs them for Caddy and reloads it. `install-hub.sh` keeps the certificate on later runs.
3. In Cloudflare: set **SSL/TLS** to **Full (strict)**.
4. Collectors are plain `curl`. If **Bot Fight Mode** or a challenge rule is on, add a WAF skip rule for `/api/v1/ingest`, or servers will be challenged instead of reporting.
5. Optional: allow inbound 443 only from [Cloudflare's IP ranges](https://www.cloudflare.com/ips/) in the cloud firewall, so the origin can't be reached around the WAF.

### Tailnet-only, with no public ports at all

If every server runs Tailscale, nothing needs to be public:
```sh
sudo tailscale serve --bg 8080                              # UI
sudo tailscale serve --bg --https 8443 http://127.0.0.1:8443  # ingest (set ingest.listen = "127.0.0.1:8443", no TLS)
```
Servers then use `HEIMDALL_URL=https://<hub>.<tailnet>.ts.net:8443`.

For a **local box** with a few servers off the tailnet, **Tailscale Funnel** can publish just the ingest port to the internet without opening your router:
```sh
sudo tailscale funnel --bg --https 8443 http://127.0.0.1:8443
```
Keep the UI on `serve`, never `funnel`.

---

## AWS

**Simplest:** **Lightsail**, Ubuntu 24.04, 1 GB or 2 GB plan.
**If the org requires EC2:** a `t4g.small` (ARM, using the `heimdall-linux-arm64` release binary) or a `t3.small`.

1. **Instance:** Ubuntu 24.04 with a 20 GB gp3 volume, **encrypted** (EBS encryption is on by default in most accounts; check that it is).
2. **Network:**
   - Lightsail: in the instance's networking tab, delete the default SSH rule and allow **TCP 443** only (or nothing, if tailnet-only).
   - EC2: a security group with **inbound 443 from 0.0.0.0/0** (or your servers' CIDRs) and **no port 22**.
3. **Access without SSH keys on the internet:** Tailscale (`tailscale up --ssh`), or AWS **Systems Manager Session Manager** on EC2. Attach `AmazonSSMManagedInstanceCore` and leave port 22 closed.
4. **Static address and DNS:** a Lightsail static IP, or an Elastic IP. Point `ingest.<yourdomain>` at it, and Caddy fetches the certificate.
5. **Backups:** copy the age-encrypted backups to a bucket. How the instance gets access depends on which one you used:
   - **Lightsail** has no IAM instance roles. Create a **Lightsail bucket** (private by default) and grant the instance access to it, so no keys are stored on the box:
     ```sh
     aws lightsail create-bucket --bucket-name heimdall-acme-backups --bundle-id small_1_0
     aws lightsail set-resource-access-for-bucket --bucket-name heimdall-acme-backups \
       --resource-name heimdall-acme --access read_write
     ```
   - **EC2:** a private S3 bucket with Block Public Access, versioning and an expiry lifecycle rule. Attach an **instance role** allowed only `s3:PutObject` on that bucket's prefix.
   - Then, on the hub (from cron or a systemd timer):
     ```sh
     heimdall backup --to /var/backups/h-$(date +%F).age --age-recipient age1… && \
       aws s3 cp /var/backups/h-$(date +%F).age s3://<bucket>/heimdall/
     ```
   - Lightsail/EBS snapshots are a good second layer, but they hold the live database unencrypted at the application level, so keep the age backups as the primary.
6. **SSO:** works the same as anywhere. Entra ID only needs the hub's UI URL reachable from your browser, i.e. over the tailnet.

**Skip:** load balancers, RDS, ECS/Fargate and NAT gateways. They add cost and attack surface and solve nothing here.

## Azure

**Simplest:** a **B1ms** or **B2s** Linux VM, Ubuntu 24.04.

1. **VM:** Ubuntu 24.04 with a Standard SSD managed disk. Managed disks are encrypted at rest by default (platform-managed keys). Add encryption at host if the org requires it.
2. **Network:**
   - A **Network Security Group** allowing inbound **443** (or nothing, if tailnet-only). Delete the default **SSH 22** rule the portal suggests.
   - Use a Standard SKU **static** public IP for the ingest DNS name.
3. **Access:** Tailscale, or **Azure Bastion** if the org standardizes on it. Don't open 22.
4. **Backups:**
   - A Storage Account with public access disabled, a private container, and lifecycle management for expiry.
   - Give the VM a **system-assigned managed identity** with **Storage Blob Data Contributor** on that container only, and upload the age files:
     ```sh
     az login --identity && \
       az storage blob upload --auth-mode login --account-name <acct> -c heimdall \
         -f /var/backups/h-$(date +%F).age -n h-$(date +%F).age
     ```
5. **SSO:** you're already in Entra. Register the app in the org's tenant (see the README's SSO section), and put the client secret in the systemd credential, not on the VM's disk in plain sight (`sudo heimdall sso set-secret` stores it root-only without it entering your shell history; the unit loads it with `LoadCredential=heimdall-entra:/etc/heimdall/entra-secret`).

**Skip:** App Service, Container Apps, Azure SQL and Application Gateway. One VM is the right shape.

---

## One hub per organization

The expected setup is one hub per organization, wherever that org wants it: the org's AWS account, its Azure subscription, or a VPS you run for it. Each hub has its own tailnet node, database, tokens and users, so nothing is shared between clients. Hostnames like `heimdall.acme.internal` and `ingest.heimdall.acme.example.com` keep them tidy.
