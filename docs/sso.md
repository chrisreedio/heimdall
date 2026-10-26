# Single sign-on and roles (Microsoft Entra ID)

Heimdall signs people in with Microsoft Entra ID over OpenID Connect, and decides what each person can do with three roles. Roles can be granted in Heimdall, or come from Entra **app roles**, so access is managed where the rest of your access already is: in Entra, through users or groups.

This page covers how roles work, how to set up app roles and groups in Entra, and what happens when someone signs in. The protocol details (token checks, PKCE, credentials) are in the README's [Single sign-on](../README.md#single-sign-on-microsoft-entra-id) section.

## Roles

| Role | Can |
|---|---|
| `viewer` | See everything in the org: hosts, findings, sites, anomalies, news, drift |
| `operator` | Also act: patch plans, anomaly triage, bans, Cloudflare and surface pages |
| `admin` | Also manage the org's hosts, tokens, IP labels and policy |
| **global admin** | Every org, plus user management. Not a per-org role; a flag on the user |

A role belongs to one **org**. On a hub with one org, that's the only org there is; on a hub with several (say one per client), a person can be an operator in one and a viewer in another. Everything is filtered by org in the data layer, so a viewer in `acme` never sees another org's hosts, findings or audit entries.

## Two ways to grant a role

**In Heimdall** (manual grants), on the Users page or from the CLI:

```sh
heimdall user grant --org acme --role operator alice@example.com
heimdall user revoke --org acme alice@example.com
```

**From Entra app roles** (on by default, `[auth.entra] app_role_mapping = true`). Each time someone signs in with Entra, Heimdall reads the `roles` claim in their ID token and sets their roles from it.

You can use both. The Users page marks roles that came from Entra with **(app role)**; those can't be revoked in Heimdall, only in Entra.

## App role names

| App role value | Gives |
|---|---|
| `Heimdall.Admin` | Global admin: every org, plus user management |
| `Heimdall.Operator` | `operator` in **every** org |
| `Heimdall.Viewer` | `viewer` in every org |
| `Heimdall.Org.<org>.Admin` | `admin` in one org, by its slug, e.g. `Heimdall.Org.acme.Admin` |
| `Heimdall.Org.<org>.Operator` | `operator` in that org |
| `Heimdall.Org.<org>.Viewer` | `viewer` in that org |

- The value (not the display name) is what counts. `Heimdall.`, `Org.` and `Heimdall.Admin` must match exactly; the role word (`Viewer`, `viewer`) and the org slug can be any case.
- Several roles for the same org: the **highest wins**. `Heimdall.Viewer` plus `Heimdall.Org.acme.Admin` makes someone an admin in `acme` and a viewer everywhere else.
- `Heimdall.Viewer` and `Heimdall.Operator` cover the orgs that exist **when the person signs in**. An org created later reaches them at their next sign-in.
- Unknown values (another app's roles, a typo, an org slug that doesn't exist) are ignored.

On a single-org hub, the first three are all you need.

## Setting up app roles in Entra

1. **Create the roles** in the app registration: **Entra admin center → App registrations → Heimdall → App roles → Create app role**. For each:
   - Display name: e.g. "Heimdall operator"
   - Allowed member types: **Users/Groups**
   - Value: e.g. `Heimdall.Operator` (exactly as in the table)
   - Description: anything
   - Enabled: yes

   Or in the manifest (`appRoles`), one entry per role:
   ```json
   {
     "allowedMemberTypes": ["User"],
     "displayName": "Heimdall operator",
     "description": "Operate Heimdall: patch plans, triage, bans",
     "id": "<a new GUID: uuidgen>",
     "isEnabled": true,
     "value": "Heimdall.Operator"
   }
   ```
2. **Assign them**: **Enterprise applications → Heimdall → Users and groups → Add user/group**, pick the people or groups, then the role.
3. **Require assignment** (recommended): **Enterprise applications → Heimdall → Properties → Assignment required? → Yes**. Then Entra refuses to sign in anyone without a role for Heimdall, before they ever reach it.

### Groups

Assign an app role **to a group** (step 2, pick the group). Everyone in it gets the role in their token, and adding or removing people from the group changes their Heimdall access at their next sign-in. That's the way to manage access by team: an `Ops` group with `Heimdall.Operator`, an `Auditors` group with `Heimdall.Viewer`.

- Assigning groups to an enterprise application needs **Entra ID P1** or higher. Without it, assign users one by one.
- Nested groups aren't expanded for app-role assignment: assign the group whose members are the people.
- Heimdall reads **app roles, not group claims**. Group claims list group IDs, and past about 200 groups Entra replaces them with a link to call Microsoft Graph (the "overage" claim). Heimdall calls no Graph APIs, so it would silently miss them. App roles stay small and always arrive in the token.

## What happens at sign-in

1. **Is this person provisioned?** Entra decides who *can* sign in; Heimdall still only lets in users it knows. Provision each person first:
   ```sh
   heimdall user create --entra --tenant <tenant-id> alice@example.com
   ```
   Their email binds to their Entra object ID on first sign-in (or pass `--oid`). Anyone else is turned away, and the attempt is in the audit log as `login.failure` with `not_provisioned`, even if Entra gave them a role. An app role never creates a user. One Entra user per person per tenant: provisioning an email or object ID that a user in that tenant already has is refused (see [Duplicate users](#duplicate-users)).
2. **Roles are replaced from the token.** Every role that came from app roles last time is removed, then the token's roles are added. A person whose role was removed in Entra loses it here.
3. **Manual grants are kept**, and for the same org a manual grant **wins**, even if it's lower: a manual `viewer` in `acme` stays `viewer` though the token says `Heimdall.Org.acme.Admin`. Revoke the manual grant to let the app role apply. Granting a role manually on an org where the person has an app role turns it into a manual grant.
4. **The global admin flag follows `Heimdall.Admin`**, on every sign-in: present makes the person a global admin, absent removes it. **This includes an admin flag set with `user create --entra --admin`**, which lasts only until the person's first sign-in unless their token has `Heimdall.Admin`. With app-role mapping on, give admins `Heimdall.Admin` in Entra. Local (break-glass) accounts aren't affected.
5. The sign-in is audited as `login.success`, with the roles from the token.

## When changes take effect

| Change | Takes effect |
|---|---|
| Manual grant or revoke in Heimdall | On the person's next page load |
| App role or group change in Entra | At the person's **next sign-in** |
| Disabling the user in Heimdall (`heimdall user disable`) | On their next page load: their sessions stop working |

Heimdall doesn't re-check Entra during a session. A session lasts at most `session_max` (12 hours by default) and ends after `session_idle` (30 minutes) without use, so a removed Entra role is gone within 12 hours. To cut someone off now, disable them in Heimdall as well.

## Turning mapping off

```toml
[auth.entra]
app_role_mapping = false
```

Then roles come only from Heimdall, and the `roles` claim is ignored. Roles synced from Entra earlier stay until revoked; the admin flag stays as it was last set. Use this if your tenant can't add app roles, or you'd rather manage access in Heimdall.

## Checking what someone has

- **Users page** (`/admin/users`, global admins): each user's roles per org, marked **(app role)** when they came from Entra, and whether they're a global admin.
- **CLI:** `heimdall user list` shows the same.
- **Audit log:** each `login.success` records the roles the token carried, so "why is Alice an operator?" is answered by her last sign-in.

## Troubleshooting

- **"Your account hasn't been set up in Heimdall"**: not provisioned (step 1), or disabled. Check `heimdall user list` and the audit log's `login.failure` reason. If the list shows their email twice, see [Duplicate users](#duplicate-users).
- **Signed in, but sees nothing**: provisioned with no role. Assign an app role in Entra (then sign in again) or grant one in Heimdall.
- **An app role doesn't show up**: check the role's **value** (not its display name) matches the table, that it's assigned in **Enterprise applications** (not just defined in the registration), and that the person signed in again after the change. The token's roles are in the `login.success` audit entry.
- **An admin lost admin after signing in**: the token had no `Heimdall.Admin` (step 4). Assign it in Entra.
- **A per-org role doesn't apply**: the slug in the value must match the org's slug (`heimdall org list`).

### Duplicate users

Sign-in looks a person up by tenant and object ID first, and only then by a pending (not yet signed in) email. So if a second Entra user with the same email was added after the first had signed in, the second could never bind: the person always landed on the first. Disable the first and they were locked out with "not provisioned", though a user with their email was right there.

Heimdall now refuses that second user, on the Users page and from `heimdall user create --entra`, and says which user is in the way:

```
an Entra user with that email already exists (#3, disabled): enable it or delete it first
```

Enable that user (`heimdall user enable '#3'`), or delete it and provision again.

A hub that already has duplicates keeps working as before. To clean up:

1. `heimdall user list` and find the rows with the same email and **KIND** `entra`. The one that has signed in (it has a **LAST LOGIN**) is bound to the person's object ID; the other never will be.
2. Keep the bound one: `heimdall user enable '#3'` if it's disabled, and grant it any roles the duplicate had.
3. Delete the duplicate: `heimdall user delete --yes '#7'`. Quote the `#`, or the shell treats it as a comment.

Deleting a user removes their roles, sessions and MCP tokens with them. Patch plans and acknowledgements they made stay, without an author, and the audit log keeps every entry, including a `user.delete` entry with the email, kind and admin flag. Deleted users' IDs aren't reused. You can't delete yourself, or the last active global admin who can sign in: with `local_login = false`, local admins don't count, since they can't sign in to the web UI. On the Users page, **delete** appears only for disabled users, behind a confirmation box: disable first (that ends their sessions and can be undone), then delete.

### "Sign-in failed" right after Microsoft's sign-in page

The person signing in sees only "Sign-in failed"; the reason is in the hub's log (`journalctl -u heimdall`), as `sso: sign-in rejected: token exchange failed` with Microsoft's `error`, `error_codes` (the AADSTS numbers), the first sentence of its description and a `hint`. The client secret, the authorization code and tokens are never logged. The usual causes, all in the app registration:

| Code | What it means | Fix |
|---|---|---|
| `AADSTS7000215` | Invalid client secret | You stored the secret's **ID**. Store its **Value** (shown only when the secret is created; make a new one if you didn't copy it) with `sudo heimdall sso set-secret`, then `sudo heimdall restart`. |
| `AADSTS7000222` | The client secret has expired | Create a new secret under **Certificates & secrets** and store its Value. |
| `AADSTS700025` | "Client is public" | The redirect URI is under **Mobile and desktop applications**. Remove it there and add it under **Authentication → Add a platform → Web**. |
| `AADSTS9002327` | Registered as a single-page application | The redirect URI is under **Single-page application**. Add it under **Web** instead. |
| `AADSTS50011` | Redirect URI mismatch | The **Web** redirect URIs must contain Heimdall's callback exactly: `ui.base_url` + `/auth/callback`, same scheme, host and path. |
| `AADSTS700016` | Application not found in the tenant | `client_id` is wrong, or `tenant` names another directory. Check both against the registration's **Overview**. |
