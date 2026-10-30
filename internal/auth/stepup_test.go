// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"errors"
	"testing"
	"time"

	"github.com/realmwatch/heimdall/internal/store"
)

// A login's code counts as a step-up; it's fresh for StepUpWindow.
func TestLoginSteppedUp(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	tok, err := e.login(email, password, e.code())
	if err != nil {
		t.Fatal(err)
	}
	v, _ := e.svc.Session(t.Context(), tok)
	if !v.SteppedUpAt.Equal(e.now) || !v.Fresh(e.now.Add(StepUpWindow-time.Second)) || v.Fresh(e.now.Add(StepUpWindow)) {
		t.Errorf("stepped up at %v, fresh %v", v.SteppedUpAt, v.Fresh(e.now))
	}
}

func TestStepUp(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ctx := t.Context()
	tok, err := e.login(email, password, e.code())
	if err != nil {
		t.Fatal(err)
	}
	v, _ := e.svc.Session(ctx, tok)

	// The code that signed in was used: a replay is refused.
	if err := e.svc.StepUp(ctx, v, e.code(), "203.0.113.5"); !errors.Is(err, ErrBadCode) {
		t.Fatalf("replayed: %v", err)
	}
	if err := e.svc.StepUp(ctx, v, "000000", "203.0.113.5"); !errors.Is(err, ErrBadCode) {
		t.Fatalf("wrong: %v", err)
	}
	e.now = e.now.Add(10 * time.Minute)
	v, _ = e.svc.Session(ctx, tok)
	if v.Fresh(e.now) {
		t.Fatal("still fresh after 10 minutes")
	}
	code := e.code()
	if err := e.svc.StepUp(ctx, v, code, "203.0.113.5"); err != nil {
		t.Fatal(err)
	}
	if v, _ = e.svc.Session(ctx, tok); !v.Fresh(e.now) {
		t.Errorf("not fresh after a step-up: %v", v.SteppedUpAt)
	}
	if err := e.svc.StepUp(ctx, v, code, "203.0.113.5"); !errors.Is(err, ErrBadCode) {
		t.Errorf("same code twice: %v", err)
	}

	rows, _ := e.st.AuditFrom(ctx, "203.0.113.5", true, nil, 100)
	ok, failed := 0, 0
	for _, r := range rows {
		switch r.Action {
		case "stepup.success":
			ok++
		case "stepup.failure":
			failed++
		}
	}
	if ok != 1 || failed != 3 {
		t.Errorf("audit: %d successes, %d failures", ok, failed)
	}

	// Failures count toward a lockout, as at sign-in.
	for range maxFailuresPerUser {
		e.svc.StepUp(ctx, v, "000000", "203.0.113.5")
	}
	e.now = e.now.Add(30 * time.Second)
	if err := e.svc.StepUp(ctx, v, e.code(), "203.0.113.5"); !errors.Is(err, ErrThrottled) {
		t.Errorf("after %d failures: %v", maxFailuresPerUser, err)
	}
}

func TestStepUpIdentity(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ctx := t.Context()
	if _, err := e.st.CreateEntraUser(ctx, "test", testTenant, testOID, "alice@example.com", "Alice", false); err != nil {
		t.Fatal(err)
	}
	id := store.EntraIdentity{TenantID: testTenant, ObjectID: testOID, Email: "alice@example.com"}
	tok, err := e.svc.LoginIdentity(ctx, id, nil, "203.0.113.5", "ua", false)
	if err != nil {
		t.Fatal(err)
	}
	v, _ := e.svc.Session(ctx, tok)
	if v.Fresh(e.now) {
		t.Error("an SSO sign-in without prompt=login counts as a step-up")
	}
	other := store.EntraIdentity{TenantID: testTenant, ObjectID: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", Email: "bob@example.com"}
	if err := e.svc.StepUpIdentity(ctx, v, other, "203.0.113.5"); !errors.Is(err, ErrWrongAccount) {
		t.Errorf("someone else: %v", err)
	}
	if err := e.svc.StepUpIdentity(ctx, v, id, "203.0.113.5"); err != nil {
		t.Fatal(err)
	}
	if v, _ = e.svc.Session(ctx, tok); !v.Fresh(e.now) {
		t.Error("not fresh after the SSO step-up")
	}
	// An Entra user has no code.
	if err := e.svc.StepUp(ctx, v, e.code(), "203.0.113.5"); !errors.Is(err, ErrBadCode) {
		t.Errorf("code for an SSO user: %v", err)
	}
}
