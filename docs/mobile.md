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
- **More:** every other page, your devices and [notifications](#notifications), the theme switch and sign out.

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

## Notifications

The app can notify your phone (or a computer's browser) when something needs you. The hub sends them itself, with the browser's standard Web Push: there's no relay, no app-store account, and nothing for an admin to set up. Each message is encrypted for the one device that asked for it, so the push service in between (Apple's, Google's, Mozilla's or Microsoft's) sees only ciphertext. They're separate from the [Slack, Discord and webhook alerts](deployment.md#notifications), which keep working as before.

**Turning them on:** open **More → Notifications** (or the link on **Devices**) on the device, and tap **Turn on notifications**. The browser asks for permission; say Allow. **Send a test notification** checks it works. Do this on each device you want notified; **Turn off on this device** stops them there. A device's notifications belong to its sign-in: signing out, revoking the device on **Devices**, or the session ending turns them off, so tick **Keep me signed in on this device** on a phone.

- **iPhone and iPad:** notifications work only in the app added to the Home Screen (iOS and iPadOS 16.4 or later), not in a Safari tab. [Install it](#install-it) first, open it from the Home Screen, then turn them on. The page says so when it's opened in Safari.
- **Android:** Chrome, Edge, Firefox and Samsung Internet all work, in the installed app or the browser.
- **Computers:** Chrome, Edge, Firefox and Safari work too, as long as the hub is on HTTPS.

**What you're told about.** Only events in organizations your role lets you see, and never if your account is disabled. For each kind you choose **Immediate**, **Daily digest** or **Off**:

| Event | What it means | Default |
|---|---|---|
| Known-exploited finding | A finding that CISA lists as exploited in the wild newly appears on a host. | Immediate |
| Threat news | An incident being exploited now (see [threat news](threat-news.md)) newly matches one of your hosts. | Immediate |
| Anomaly | A high or critical anomaly fires, or one the chat alerts always send (change reporting switched off, privileged access outside a window...). The same rule as `[notify] alert_anomalies`. | Immediate |
| Privileged access from an unknown address | sudo or root SSH from an address nothing is known about ([IP awareness](ip-awareness.md)). | Immediate |
| Ban proposal | A ban is waiting for an operator's approval (operators only). Tapping it opens Defense at that ban; nothing is approved from the notification itself. | Immediate |
| Host stopped reporting | No report from a host past the stale threshold. | Immediate |
| Fleet summary | Hosts with pending security updates, software within 90 days of its end of life, and collectors to upgrade. | Daily digest |

The **daily digest** comes at 8 AM in your time zone: what you set to Daily digest since the last one, and the fleet summary. It isn't sent when there's nothing in it. Several hosts with the same kind of event at once come as one notification ("Known-exploited findings on 5 hosts"), and repeats of the same event on the same host within 10 minutes become one with a count ("3 anomalies on web-01"), replacing the first on your lock screen.

**Quiet hours** (10 PM to 7 AM by default, in your time zone) hold notifications until they end, then deliver them as one ("During quiet hours: 2 anomalies, 1 host stopped reporting"). Known-exploited findings and privileged access from an unknown address come through anyway. The time zone is taken from the browser when you turn notifications on; change it, the hours, or turn quiet hours off on the same page. A digest due during quiet hours waits for them to end.

**Lock-screen privacy.** **Kind and host** (the default) shows what happened and where: "Known-exploited finding on web-01". **Hidden** shows only "Heimdall needs attention" (or your hub's name), and the notification opens the home page. Either way a notification never contains package names, addresses, usernames or an anomaly's own summary: at most the kind of event, a host's name and a count. Tapping one opens the hub's page for it, behind the usual sign-in.

**Egress:** if you limit the hub's outbound traffic, allow HTTPS (443) to the push services of the browsers your people use: `fcm.googleapis.com` (Chrome, Edge and Samsung Internet on Android, Chrome on computers), `*.push.apple.com` (Safari, the iPhone and iPad app), `*.push.services.mozilla.com` (Firefox) and `*.notify.windows.com` (Edge on Windows). The hub accepts subscriptions only on those hosts, over HTTPS, and checks again on every send, so a subscription can't point it anywhere else; its outbound client is allowlisted the same way (`internal/netx`). A push service that answers that a subscription is gone (404 or 410) has it deleted; other failures are retried a couple of times and shown on the Notifications page.

The hub signs its messages with a key pair (VAPID) it makes on first use and keeps in its database; push services see only the public half. Restoring a backup keeps it. A new database means a new key, and each device has to turn notifications on again.

## What's stored on the phone

A service worker (`/sw.js`) keeps copies of the hub's static files: its stylesheet, scripts, icons and the offline page. Nothing else. Pages and API answers are never cached: every page comes from the hub when you open it, and nothing about your fleet is kept on the phone. Signing out, or revoking the device, leaves nothing behind that shows your data.

## Staying signed in

**Keep me signed in on this device**, on the sign-in page, makes a device session: it lasts 30 days from the last time it's used, and each use pushes that out again, so a phone you open at least monthly stays signed in. Without the box, sessions end as they always have, after `ui.session_idle` without use (30 minutes by default) or `ui.session_max` (12 hours) at the latest. It works for local accounts and for Sign in with Microsoft. Only tick it on a device that's yours and locked.

**Devices** (click your email address at the bottom of the sidebar, or **More → Devices** on a phone) lists where you're signed in: "iPhone Safari", "Windows Edge" and so on, guessed from each browser's User-Agent, with when each was last used, where from, and whether it's kept signed in. The one you're using is marked. **Revoke** signs a device out at once: its next request goes to the sign-in page. Admins see everyone's sessions on **Admin → Users**, and can revoke any of them. Disabling a user ends all their sessions, as before. Every revoke is in the audit log (`session.revoke`), and a kept sign-in is noted on its `login.success` entry.

## Security notes

- The app is the hub's UI under the same strict Content Security Policy: no inline scripts or styles, nothing from other sites. The policy allows a service worker and a manifest from the hub itself (`worker-src 'self'; manifest-src 'self'`). The service worker's own script gets `connect-src 'self'`, so it can pass the hub's pages through, and `img-src 'self'` for notifications' icons. The service worker shows a pushed notification and opens only a page of the hub when it's tapped (any other link becomes the home page); it keeps nothing from it.
- The manifest (`/manifest.webmanifest`), the icons and the offline page are public, as the sign-in page is: they show the hub's name and icons and nothing else.
- A device session is still a cookie that's `HttpOnly`, `Secure` and `SameSite=Strict`, as normal sessions are. The difference is only how long it lasts.
