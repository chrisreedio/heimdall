// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"crypto/sha256"
	"net/http"
	"slices"
	"strconv"

	"github.com/realmwatch/heimdall/internal/auth"
	"github.com/realmwatch/heimdall/internal/push"
	"github.com/realmwatch/heimdall/internal/store"
)

// Notifications (docs/mobile.md#notifications): turning Web Push on for
// this device, a test, and the user's settings: per event kind Immediate,
// Daily digest or Off, quiet hours, and what the lock screen shows. The
// browser subscribes with the hub's VAPID key (app.js) and posts the
// subscription as a normal form, CSRF token and all; the page's CSP allows
// no fetch. A subscription belongs to the session it was made in, so
// signing out or revoking the device ends it.

// PushService is the notifier (internal/push), as the pages use it.
type PushService interface {
	PublicKey(ctx context.Context) (string, error)
	// Test queues a test notification to each of a user's devices and
	// says how many.
	Test(ctx context.Context, userID int64) (int, error)
}

type pushKindRow struct {
	Kind, Label, Help string
	Mode              string
	Modes             []pushModeOpt
}

type pushModeOpt struct{ Value, Label string }

type pushDevice struct {
	store.PushSubscription
	Here bool // made in this session
}

type notificationsBody struct {
	On        bool   // push is set up on this hub
	Key       string // VAPID public key, for the browser
	Here      bool   // this device is subscribed
	Devices   []pushDevice
	Kinds     []pushKindRow
	Settings  store.PushSettings
	Hours     []pushModeOpt
	Notice    string
	Error     string
	Insecure  bool // the UI isn't on HTTPS, where browsers allow push
	AppName   string
	TimeZones []string
}

var pushModeLabels = map[string]string{push.Immediate: "Immediate", push.Digest: "Daily digest", push.Off: "Off"}

// pushKinds are the settings page's rows, in push.Kinds' order.
var pushKinds = map[string][2]string{
	push.KindKEV:       {"Known-exploited finding", "A finding CISA lists as exploited in the wild newly appears on a host."},
	push.KindNews:      {"Threat news", "An incident being exploited now newly matches one of your hosts."},
	push.KindAnomaly:   {"Anomaly", "A high or critical anomaly (a tripwire) fires, or one the chat alerts always send."},
	push.KindPrivilege: {"Privileged access from an unknown address", "Someone used sudo or root SSH from an address nothing is known about."},
	push.KindBan:       {"Ban proposal", "A ban is waiting for an operator's approval. It opens Defense at the ban; nothing is decided from the notification."},
	push.KindSilent:    {"Host stopped reporting", "No report from a host past the stale threshold."},
	push.KindFleet:     {"Fleet summary", "Hosts with pending security updates, software within 90 days of end of life, collectors to upgrade."},
}

var pushNotices = map[string]string{
	"on":    "Notifications are on for this device.",
	"off":   "Notifications are off for this device.",
	"test":  "Test notification sent. It should arrive within a few seconds.",
	"saved": "Saved.",
}

// commonTimeZones are offered in the time zone picker; the browser's own
// is added when it isn't one of them.
var commonTimeZones = []string{"America/New_York", "America/Chicago", "America/Denver", "America/Phoenix",
	"America/Los_Angeles", "America/Anchorage", "Pacific/Honolulu", "UTC", "Europe/London", "Europe/Berlin",
	"Asia/Tokyo", "Australia/Sydney"}

func (s *server) sessionHash(v *auth.Viewer) [32]byte { return sha256.Sum256([]byte(v.SessionToken)) }

func (s *server) notificationsPage(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	q := r.URL.Query()
	s.renderNotifications(w, r, v, http.StatusOK, pushNotices[q.Get("ok")], pushErrors[q.Get("err")])
}

var pushErrors = map[string]string{
	"blocked": "This browser blocked notifications for this site. Allow them in its settings, then try again.",
	"none":    "No device has notifications on yet.",
}

func (s *server) renderNotifications(w http.ResponseWriter, r *http.Request, v *auth.Viewer, status int, notice, errText string) {
	ctx := r.Context()
	body := notificationsBody{On: s.cfg.Push != nil, Notice: notice, Error: errText, Insecure: !s.secure && !loopbackOrigin(s.origin),
		AppName: s.brandView(ctx).Name}
	if body.On {
		key, err := s.cfg.Push.PublicKey(ctx)
		if err != nil {
			s.fail(w, r, v, err)
			return
		}
		body.Key = key
	}
	subs, err := s.st.UserPushSubscriptions(ctx, v.UserID)
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	here := s.sessionHash(v)
	for _, sub := range subs {
		d := pushDevice{PushSubscription: sub, Here: string(sub.SessionHash) == string(here[:])}
		body.Here = body.Here || d.Here
		body.Devices = append(body.Devices, d)
	}
	if body.Settings, err = s.st.PushSettings(ctx, v.UserID); err != nil {
		s.fail(w, r, v, err)
		return
	}
	for _, k := range push.Kinds {
		if k == push.KindBan && !canOperateAny(v) {
			continue // only operators get ban proposals
		}
		row := pushKindRow{Kind: k, Label: pushKinds[k][0], Help: pushKinds[k][1], Mode: push.ModeOf(body.Settings, k)}
		for _, m := range push.ModesFor(k) {
			row.Modes = append(row.Modes, pushModeOpt{Value: m, Label: pushModeLabels[m]})
		}
		body.Kinds = append(body.Kinds, row)
	}
	for h := range 24 {
		body.Hours = append(body.Hours, pushModeOpt{Value: strconv.Itoa(h), Label: hourLabel(h)})
	}
	body.TimeZones = commonTimeZones
	if tz := body.Settings.TimeZone; tz != "" && !slices.Contains(commonTimeZones, tz) {
		body.TimeZones = append([]string{tz}, commonTimeZones...)
	}
	s.render(w, r, status, "notifications", v, "Notifications", "notifications", body)
}

// loopbackOrigin: browsers treat http://localhost (and 127.0.0.1) as
// secure, so push works there without HTTPS.
func loopbackOrigin(origin string) bool { return len(loopbackAliases(origin)) > 1 }

// hourLabel is an hour of the day in US style: "10 PM", "12 AM".
func hourLabel(h int) string {
	switch {
	case h == 0:
		return "12 AM (midnight)"
	case h == 12:
		return "12 PM (noon)"
	case h < 12:
		return strconv.Itoa(h) + " AM"
	}
	return strconv.Itoa(h-12) + " PM"
}

// pushSubscribe stores this browser's subscription for this session.
func (s *server) pushSubscribe(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	if s.cfg.Push == nil {
		s.notFound(w, r, v)
		return
	}
	f := r.PostForm
	endpoint := f.Get("endpoint")
	if err := push.CheckEndpoint(endpoint); err != nil {
		s.log.Warn("push subscription refused: endpoint not on a known push service", "user", v.UserID)
		s.renderNotifications(w, r, v, http.StatusBadRequest, "", "This browser's push service isn't one the hub sends to. Use Safari, Chrome, Edge or Firefox.")
		return
	}
	p256dh, secret, err := push.ParseKeys(f.Get("p256dh"), f.Get("auth"))
	if err != nil {
		s.renderNotifications(w, r, v, http.StatusBadRequest, "", "The browser sent a subscription the hub can't use. Try again.")
		return
	}
	ctx := r.Context()
	if err := s.st.SavePushSubscription(ctx, v.UserID, s.sessionHash(v), endpoint, p256dh, secret,
		store.DeviceLabel(r.UserAgent()), s.now()); err != nil {
		s.fail(w, r, v, err)
		return
	}
	if tz := f.Get("tz"); push.ValidTimeZone(tz) {
		if err := s.st.SetPushTimeZoneIfUnset(ctx, v.UserID, tz); err != nil {
			s.fail(w, r, v, err)
			return
		}
	}
	http.Redirect(w, r, "/account/notifications?ok=on", http.StatusSeeOther)
}

// pushUnsubscribe turns notifications off for this device: the endpoint
// the browser had, and anything else subscribed in this session.
func (s *server) pushUnsubscribe(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	ctx := r.Context()
	if ep := r.PostForm.Get("endpoint"); ep != "" {
		if err := s.st.DeletePushSubscription(ctx, v.UserID, ep); err != nil {
			s.fail(w, r, v, err)
			return
		}
	}
	if err := s.st.DeleteSessionPushSubscriptions(ctx, s.sessionHash(v)); err != nil {
		s.fail(w, r, v, err)
		return
	}
	http.Redirect(w, r, "/account/notifications?ok=off", http.StatusSeeOther)
}

// pushTest sends a test notification to each of the viewer's devices. It
// only queues it: the page never waits on a push service.
func (s *server) pushTest(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	if s.cfg.Push == nil {
		s.notFound(w, r, v)
		return
	}
	n, err := s.cfg.Push.Test(r.Context(), v.UserID)
	if err != nil {
		s.renderNotifications(w, r, v, http.StatusServiceUnavailable, "", "Couldn't send: "+err.Error())
		return
	}
	if n == 0 {
		http.Redirect(w, r, "/account/notifications?err=none", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/account/notifications?ok=test", http.StatusSeeOther)
}

// pushSettings saves the viewer's settings.
func (s *server) pushSettings(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	ctx := r.Context()
	cur, err := s.st.PushSettings(ctx, v.UserID)
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	f := r.PostForm
	next := cur
	next.Modes = map[string]string{}
	for _, k := range push.Kinds {
		m := f.Get("mode_" + k)
		if m == "" {
			if old, ok := cur.Modes[k]; ok { // a row the page didn't show (bans, for a viewer)
				next.Modes[k] = old
			}
			continue
		}
		if !push.ValidMode(k, m) {
			s.renderNotifications(w, r, v, http.StatusBadRequest, "", "Unknown choice for "+pushKinds[k][0]+".")
			return
		}
		if m != push.DefaultMode(k) {
			next.Modes[k] = m
		}
	}
	next.Quiet = f.Get("quiet") == "1"
	start, err1 := strconv.Atoi(f.Get("quiet_start"))
	end, err2 := strconv.Atoi(f.Get("quiet_end"))
	if err1 != nil || err2 != nil || start < 0 || start > 23 || end < 0 || end > 23 {
		s.renderNotifications(w, r, v, http.StatusBadRequest, "", "Quiet hours must be whole hours.")
		return
	}
	next.QuietStart, next.QuietEnd = start, end
	if tz := f.Get("tz"); tz != "" {
		if !push.ValidTimeZone(tz) {
			s.renderNotifications(w, r, v, http.StatusBadRequest, "", "Unknown time zone "+strconv.Quote(tz)+".")
			return
		}
		next.TimeZone = tz
	}
	next.Detail = push.DetailHost
	if f.Get("detail") == push.DetailHidden {
		next.Detail = push.DetailHidden
	}
	if err := s.st.SetPushSettings(ctx, v.UserID, next); err != nil {
		s.fail(w, r, v, err)
		return
	}
	http.Redirect(w, r, "/account/notifications?ok=saved", http.StatusSeeOther)
}
