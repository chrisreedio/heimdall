// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/realmwatch/heimdall/internal/store"
)

// Step-up (docs/mobile.md): when an admin turns it on, some actions need
// the user to have proved it's them recently, not just a session cookie.
// Local users enter a TOTP code; Entra users sign in with Microsoft again
// (prompt=login). Either is recorded on the session and is fresh for
// StepUpWindow, so a run of actions asks once.

// StepUpWindow is how long a step-up lasts.
const StepUpWindow = 5 * time.Minute

// Fresh reports whether the viewer stepped up within StepUpWindow of now.
func (v *Viewer) Fresh(now time.Time) bool {
	return !v.SteppedUpAt.IsZero() && now.Sub(v.SteppedUpAt) < StepUpWindow && !v.SteppedUpAt.After(now.Add(time.Minute))
}

// StepUp checks a TOTP code from a signed-in local user and records the
// step-up on their session. It refuses a replayed code, as Login does,
// and after maxFailuresPerUser failures in throttleWindow, any code.
func (s *Service) StepUp(ctx context.Context, v *Viewer, code, ip string) error {
	now := s.Now()
	key := "stepup:" + strconv.FormatInt(v.UserID, 10)
	if s.throttled(key, maxFailuresPerUser, now) {
		return s.auditStepUp(ctx, v, false, "totp", "throttled", ip, ErrThrottled)
	}
	fail := func(reason string) error {
		s.recordFailure(key, now)
		return s.auditStepUp(ctx, v, false, "totp", reason, ip, ErrBadCode)
	}
	u, err := s.Store.UserByID(ctx, v.UserID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && (u.Kind != "local" || u.Disabled)) {
		return fail("no_totp")
	}
	if err != nil {
		return err
	}
	step, ok := VerifyTOTP(u.TOTPSecret, code, now)
	if !ok {
		return fail("bad_code")
	}
	fresh, err := s.Store.AcceptTOTPStep(ctx, u.ID, step)
	if err != nil {
		return err
	}
	if !fresh {
		return fail("replayed_code")
	}
	if err := s.Store.SetSessionStepUp(ctx, sha256.Sum256([]byte(v.SessionToken)), now); err != nil {
		return err
	}
	s.clearFailures(key)
	return s.auditStepUp(ctx, v, true, "totp", "", ip, nil)
}

// StepUpIdentity records a step-up on v's session after a Microsoft
// sign-in with prompt=login, once SSO has validated the identity. It must
// be v's own account.
func (s *Service) StepUpIdentity(ctx context.Context, v *Viewer, id store.EntraIdentity, ip string) error {
	u, err := s.Store.ResolveEntraUser(ctx, id)
	if errors.Is(err, store.ErrNotFound) || (err == nil && (u.ID != v.UserID || u.Disabled)) {
		return s.auditStepUp(ctx, v, false, "entra", "wrong_account", ip, ErrWrongAccount)
	}
	if err != nil {
		return err
	}
	if err := s.Store.SetSessionStepUp(ctx, sha256.Sum256([]byte(v.SessionToken)), s.Now()); err != nil {
		return err
	}
	return s.auditStepUp(ctx, v, true, "entra", "", ip, nil)
}

// auditStepUp records a step-up as "stepup.success" or "stepup.failure"
// and returns ret (or an audit error).
func (s *Service) auditStepUp(ctx context.Context, v *Viewer, ok bool, method, reason, ip string, ret error) error {
	e := store.AuditEntry{Actor: fmt.Sprintf("user:%d", v.UserID), Action: "stepup.success", Target: truncate(v.Email, 254), IP: ip,
		Detail: map[string]any{"method": method}}
	if !ok {
		e.Action, e.Detail["reason"] = "stepup.failure", reason
	}
	if err := s.Store.Audit(ctx, e); err != nil {
		return err
	}
	return ret
}
