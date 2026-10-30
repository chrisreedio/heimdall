// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/realmwatch/heimdall/internal/auth"
	"github.com/realmwatch/heimdall/internal/store"
)

type adminUser struct {
	store.User
	Roles  []store.Membership
	Self   bool
	Tokens []tokenRow // active MCP tokens, when MCP is on
	// Sessions are where they're signed in (devices.go).
	Sessions []deviceRow
}

type adminBody struct {
	Users   []adminUser
	Orgs    []store.Org
	Tenants []string
	Roles   []store.Role
	Notice  string
	Error   string
	MCP     bool // MCP is on: show each user's tokens
}

// adminNotices are the only messages a redirect can ask the page to show,
// so the query string can't inject text.
var adminNotices = map[string]string{
	"added":    "Entra user added. They can sign in with Microsoft once they have a role (or are an admin).",
	"granted":  "Role granted.",
	"revoked":  "Role revoked.",
	"disabled": "User disabled; their sessions have ended.",
	"enabled":  "User enabled.",
	"deleted":  "User deleted, with their roles, sessions and tokens. The audit log keeps their entries.",

	"token-revoked":   "MCP token revoked.",
	"session-revoked": "Session ended: that device is signed out.",
}

func (s *server) adminUsers(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	s.renderAdmin(w, r, v, http.StatusOK, adminNotices[r.URL.Query().Get("ok")], "")
}

func (s *server) renderAdmin(w http.ResponseWriter, r *http.Request, v *auth.Viewer, status int, notice, errMsg string) {
	ctx := r.Context()
	users, err := s.st.ListUsers(ctx)
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	orgs, err := s.st.ListOrgs(ctx)
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	body := adminBody{Orgs: orgs, Tenants: s.cfg.EntraTenants, Notice: notice, Error: errMsg,
		Roles: []store.Role{store.RoleViewer, store.RoleOperator, store.RoleAdmin}, MCP: s.cfg.MCP.Enabled}
	for _, u := range users {
		ms, err := s.st.Memberships(ctx, u.ID)
		if err != nil {
			s.fail(w, r, v, err)
			return
		}
		au := adminUser{User: u, Roles: ms, Self: u.ID == v.UserID}
		if au.Sessions, err = s.liveSessions(r, v, u.ID); err != nil {
			s.fail(w, r, v, err)
			return
		}
		if body.MCP {
			ts, err := s.st.ListMCPTokens(ctx, u.ID)
			if err != nil {
				s.fail(w, r, v, err)
				return
			}
			au.Tokens = activeTokens(ts)
		}
		body.Users = append(body.Users, au)
	}
	s.render(w, r, status, "admin_users", v, "Users", "users", body)
}

// adminAction handles the admin page's forms. requireAuth has already
// checked Origin and the CSRF token; requireAdmin the role.
func (s *server) adminAction(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	ctx := r.Context()
	actor := fmt.Sprintf("user:%d", v.UserID)
	f := func(k string) string { return strings.TrimSpace(r.PostForm.Get(k)) }
	var ok string
	var err error
	switch r.PathValue("action") {
	case "entra":
		tenant := strings.ToLower(f("tenant"))
		if !slices.Contains(lower(s.cfg.EntraTenants), tenant) {
			err = errors.New("choose one of the configured tenants")
			break
		}
		_, err = s.st.CreateEntraUser(ctx, actor, tenant, "", f("email"), f("name"), f("admin") == "on")
		ok = "added"
	case "grant":
		var role store.Role
		if role, err = store.ParseRole(f("role")); err == nil {
			err = s.st.Grant(ctx, actor, f("email"), f("org"), role)
		}
		ok = "granted"
	case "revoke":
		err = s.st.Revoke(ctx, actor, f("email"), f("org"))
		ok = "revoked"
	case "disable", "enable":
		disable := r.PathValue("action") == "disable"
		email, _ := store.NormalizeEmail(f("email"))
		if disable && (f("email") == store.UserRef(v.UserID) || (email != "" && email == v.Email)) {
			err = errors.New("you can't disable the account you're signed in with")
			break
		}
		err = s.st.SetUserDisabled(ctx, actor, f("email"), disable)
		ok = map[bool]string{true: "disabled", false: "enabled"}[disable]
	case "delete":
		// Only disabled users: disabling is the reversible step that ends
		// their sessions, and it keeps a mis-click from deleting someone
		// who's working. The checkbox is the confirmation.
		var id int64
		var u store.User
		if id, err = strconv.ParseInt(f("user"), 10, 64); err != nil || id <= 0 {
			err = &store.ValidationError{Field: "user", Msg: "missing or bad user ID"}
		} else if id == v.UserID {
			err = errors.New("you can't delete the account you're signed in with")
		} else if f("confirm") != "yes" {
			err = errors.New("you can't delete a user without ticking the box to confirm")
		} else if u, err = s.st.UserByID(ctx, id); errors.Is(err, store.ErrNotFound) {
			err = fmt.Errorf("user %s: %w", store.UserRef(id), store.ErrNotFound)
		} else if err == nil && !u.Disabled {
			err = errors.New("you can't delete an active user; disable them first")
		} else if err == nil {
			err = s.st.DeleteUser(ctx, actor, id, store.SignInMethods{Local: s.cfg.LocalLogin, Entra: s.cfg.SSO != nil})
		}
		ok = "deleted"
	default:
		s.notFound(w, r, v)
		return
	}
	if err != nil {
		s.log.Warn("admin action failed", "action", r.PathValue("action"), "actor", actor, "err", err)
		s.renderAdmin(w, r, v, http.StatusBadRequest, "", adminError(err))
		return
	}
	http.Redirect(w, r, "/admin/users?ok="+ok, http.StatusSeeOther)
}

// adminError turns store errors into messages for the admin. Only
// validation and not-found/exists errors are spelled out.
func adminError(err error) string {
	var ve *store.ValidationError
	switch {
	case errors.As(err, &ve), errors.Is(err, store.ErrNotFound), errors.Is(err, store.ErrExists):
		return err.Error()
	}
	msg := err.Error()
	if strings.HasPrefix(msg, "you can't") || strings.HasPrefix(msg, "choose one") || strings.HasPrefix(msg, "several users share") {
		return msg
	}
	return "That didn't work; see the server log."
}

func lower(ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = strings.ToLower(s)
	}
	return out
}
