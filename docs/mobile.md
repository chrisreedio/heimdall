# The mobile app

Heimdall's UI installs on a phone as an app: an icon on the home screen that opens full screen, without the browser's address bar, and a layout made for a phone. It's the hub's own UI, not a separate app. There's no app store, no relay and nothing new for the hub to run: the phone talks to your hub over your tailnet, like a browser on your laptop does.

Each hub is its own app. If you run two hubs, install both, and give each its own name and icon on **Admin → Branding** (see [Branding](deployment.md#branding)) so they're easy to tell apart.

## What you need

- The hub's UI published on your tailnet with `tailscale serve`, which gives it a real HTTPS certificate (`https://<hub>.<tailnet>.ts.net`). `install-hub.sh` sets this up; see [Deployment, option A](deployment.md#option-a-tailscale-simplest). Phones only install apps from HTTPS sites, so a UI reached over plain HTTP (an SSH tunnel to `127.0.0.1:8080`, say) works in the phone's browser but can't be installed.
- The Tailscale app on the phone, signed in to the same tailnet.
- An account on the hub, as for the browser.

## Install it

**iPhone and iPad (Safari):**

1. Turn on Tailscale, open Safari and go to the hub's address, `https://<hub>.<tailnet>.ts.net`.
2. Tap the Share button, then **Add to Home Screen**. The name and icon are the hub's; you can change the name here.
3. Open it from the home screen and sign in. Tick **Keep me signed in on this device** so you don't have to sign in every time (see below).

Only Safari can add apps to the home screen on iOS 16.3 and earlier; on later versions other browsers can too, from their share menu.

**Android (Chrome):**

1. Turn on Tailscale, open Chrome and go to the hub's address.
2. Tap the ⋮ menu, then **Add to Home screen** (or **Install app**, when Chrome offers it). Edge and Samsung Internet have the same option in their menus.
3. Open it from the home screen and sign in, ticking **Keep me signed in on this device**.

## What's in it

On a phone, or any screen narrower than about 760 pixels, a tab bar at the bottom replaces the sidebar:

- **Home:** what needs attention, as cards, most urgent first: known-exploited findings, incidents in the news that affect your hosts, ban proposals waiting for a decision, open anomalies, privileged sessions from addresses nobody knows, and hosts that stopped reporting. Then the hosts most worth a look. When there's nothing, it says so: "All clear, 12 hosts reporting".
- **Hosts:** the host list, and each host's page.
- **Alerts:** open anomalies, privileged access from unknown addresses in the last 7 days, and incidents in the news that affect your hosts, newest first. Operators acknowledge or mute an anomaly right there (see below).
- **Defense:** for operators, ban proposals waiting, to approve or dismiss there, and the bans in force with when each ends; then repeat offenders from the failed-login watch.
- **More:** every other page, your devices, the theme switch and sign out.

Everything else works as it does on a computer, with the same roles and permissions; the pages are the same pages. Times are shown in the phone's time zone. On a computer, Alerts and Defense are in the sidebar too, under Security and Network.

## Acting from the phone

The phone does what the hub's pages already do, with the same roles, checks and audit log; nothing is phone-only.

- **Ban proposals** (Defense): each one is a card with what's needed to decide: the address or network, the action (challenge or block) and for how long, the score, the failed logins (how many, how many usernames, over how many days, the last one), the network and its prefix, the hosts it hit, and what IP awareness knows about it. **Approve** sends it to Cloudflare within a minute; **Dismiss** rejects it, as Reject on the Bans page does. Both need the operator role in an org whose hosts it hit, and both are in the ban audit log. Each card has the anchor `#ban-<id>` (`/defense#ban-42`), so a link can open the app at it. Approve is there only when `[bans] mode` writes to Cloudflare (`propose` or `auto`). Unbanning, pausing Cloudflare writes and the zones' rules stay on the Bans page.
- **Anomalies** (Alerts): **Acknowledge** with a note on what you found, or **Mute this signal** on that host for some days, as on the Anomalies page. They need the operator role in the host's org and are audited (`anomaly.ack`, `anomaly.suppress`).
- **Fix commands** (a host's page): the **Copy** buttons work on phones. Without the Clipboard API (a UI on plain HTTP, say), the command is copied the older way, and if the browser refuses that too, it's selected so a long press copies it.

The Discord ban card and its buttons work as before; the phone is one more place to decide.

## Step-up codes

A phone that's kept signed in for 30 days is convenient, and an unlocked phone is a risk. **Admin → Security** (`/admin/security`) lets an admin decide whether actions need a fresh code, not just the session:

- **Off** (the default): the session is enough.
- **Admin actions only**: before an admin changes users and their sessions, branding, which Cloudflare lists become labels, or this setting.
- **Every action**: those, and before anyone approves, dismisses or lifts a ban, pauses or resumes Cloudflare writes, turns a zone's ban rule on or off, or acknowledges or mutes an anomaly.

It applies on every screen, phone and computer. A code is fresh for 5 minutes after it's entered, so approving several bans in a row asks once; the code you signed in with counts too. When one's needed, the hub asks in a small dialog before the form is sent, then sends it with the code, so nothing you typed or chose is lost; without JavaScript it asks on a page of its own that keeps the form and carries it out. A wrong code, or one already used (to sign in, or for another step-up), is refused, and five failures in 15 minutes lock step-up for that account for a while, as at sign-in.

People who sign in with Microsoft have no code. For them, fresh means a Microsoft sign-in in the last 5 minutes that asked for their credentials again: the hub sends them to Microsoft with `prompt=login` and, when they're back, carries the action out. It must be the same account; signing in as someone else is refused. Signing in to the hub with Microsoft doesn't count by itself, because Microsoft often signs people in without asking anything.

Every change to the setting is in the audit log (`setting.stepup`), as is every code entered or Microsoft step-up (`stepup.success`, `stepup.failure`, with the reason).

**Offline:** when the hub can't be reached (Tailscale is off, or the phone has no signal), the app shows "Can't reach the hub. Is Tailscale connected?" with a **Try again** button, rather than the browser's error page.

**Not yet:** push notifications. Alerts reach you through [Slack, Discord or a webhook](deployment.md#notifications) for now.

## What's stored on the phone

A service worker (`/sw.js`) keeps copies of the hub's static files: its stylesheet, scripts, icons and the offline page. Nothing else. Pages and API answers are never cached: every page comes from the hub when you open it, and nothing about your fleet is kept on the phone. Signing out, or revoking the device, leaves nothing behind that shows your data.

## Staying signed in

**Keep me signed in on this device**, on the sign-in page, makes a device session: it lasts 30 days from the last time it's used, and each use pushes that out again, so a phone you open at least monthly stays signed in. Without the box, sessions end as they always have, after `ui.session_idle` without use (30 minutes by default) or `ui.session_max` (12 hours) at the latest. It works for local accounts and for Sign in with Microsoft. Only tick it on a device that's yours and locked.

**Devices** (click your email address at the bottom of the sidebar, or **More → Devices** on a phone) lists where you're signed in: "iPhone Safari", "Windows Edge" and so on, guessed from each browser's User-Agent, with when each was last used, where from, and whether it's kept signed in. The one you're using is marked. **Revoke** signs a device out at once: its next request goes to the sign-in page. Admins see everyone's sessions on **Admin → Users**, and can revoke any of them. Disabling a user ends all their sessions, as before. Every revoke is in the audit log (`session.revoke`), and a kept sign-in is noted on its `login.success` entry.

## Security notes

- The app is the hub's UI under the same strict Content Security Policy: no inline scripts or styles, nothing from other sites. The policy allows a service worker and a manifest from the hub itself (`worker-src 'self'; manifest-src 'self'`). The service worker's own script gets `connect-src 'self'`, so it can pass the hub's pages through.
- The manifest (`/manifest.webmanifest`), the icons and the offline page are public, as the sign-in page is: they show the hub's name and icons and nothing else.
- A device session is still a cookie that's `HttpOnly`, `Secure` and `SameSite=Strict`, as normal sessions are. The difference is only how long it lasts.
