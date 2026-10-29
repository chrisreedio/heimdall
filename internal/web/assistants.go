// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/realmwatch/heimdall/internal/auth"
	"github.com/realmwatch/heimdall/internal/config"
	"github.com/realmwatch/heimdall/internal/mcpb"
	"github.com/realmwatch/heimdall/internal/store"
)

// MCPSetup is what the UI needs to know about the [mcp] endpoint.
type MCPSetup struct {
	Enabled bool
	BaseURL string // mcp.base_url, the address clients use
	Name    string // mcp.name, what clients call the connection ("" = heimdall)
}

// connectorName is MCPSetup.Name, or "heimdall".
func (m MCPSetup) connectorName() string {
	if m.Name == "" {
		return config.DefaultConnectorName
	}
	return m.Name
}

const (
	maxMCPTokens     = 10               // active tokens per user
	tokenCreateLimit = 5                // creations per user...
	tokenCreateEvery = 10 * time.Minute // ...per this window
)

// tokenLimiter caps how fast one user can mint tokens (in memory; a
// restart resets it, which is fine for a speed bump on top of the cap).
type tokenLimiter struct {
	mu   sync.Mutex
	seen map[int64][]time.Time
}

func (l *tokenLimiter) allow(userID int64, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.seen == nil {
		l.seen = map[int64][]time.Time{}
	}
	var recent []time.Time
	for _, t := range l.seen[userID] {
		if now.Sub(t) < tokenCreateEvery {
			recent = append(recent, t)
		}
	}
	if len(recent) >= tokenCreateLimit {
		l.seen[userID] = recent
		return false
	}
	l.seen[userID] = append(recent, now)
	return true
}

type tokenRow struct {
	ID       int64
	Name     string
	Purpose  string // store.PurposeMCP or store.PurposeThreats
	Threats  bool   // a threat-list token
	Created  *time.Time
	LastUsed *time.Time // nil = never
}

type assistantsBody struct {
	Enabled  bool
	Endpoint string // <base_url>/mcp
	BaseURL  string
	Tokens   []tokenRow
	Max      int
	Full     bool // at the cap
	NewToken string
	NewName  string
	// NewThreats: the new token (or the form's choice) is a threat-list one.
	NewThreats  bool
	ThreatsURL  string // <base_url>/api/v1/threats
	ThreatsCurl string // how to pull it without the token on a command line
	Notice      string
	Error       string
	Desktop     string // claude_desktop_config.json fallback
	Code        string // Claude Code, POSIX shells
	CodePS      string // Claude Code, PowerShell
	// Name is the connection's name (mcp.name); Named: the hub set one.
	Name     string
	Named    bool
	FileName string // the extension's download name
}

var assistantNotices = map[string]string{
	"revoked": "Token revoked. Anything using it stops working on its next request.",
}

func (s *server) mcpEndpoint() string {
	return strings.TrimRight(s.cfg.MCP.BaseURL, "/") + "/mcp"
}

func (s *server) assistantsPage(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	if !s.cfg.MCP.Enabled && !v.IsAdmin {
		s.notFound(w, r, v)
		return
	}
	s.renderAssistants(w, r, v, http.StatusOK, assistantsBody{Notice: assistantNotices[r.URL.Query().Get("ok")]})
}

func (s *server) renderAssistants(w http.ResponseWriter, r *http.Request, v *auth.Viewer, status int, body assistantsBody) {
	body.Enabled, body.Max = s.cfg.MCP.Enabled, maxMCPTokens
	if !body.Enabled {
		s.render(w, r, status, "assistants", v, "AI assistants", "assistants", body)
		return
	}
	tokens, err := s.st.ListMCPTokens(r.Context(), v.UserID)
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	body.Tokens = activeTokens(tokens)
	body.Full = len(body.Tokens) >= maxMCPTokens
	body.BaseURL, body.Endpoint = s.cfg.MCP.BaseURL, s.mcpEndpoint()
	body.ThreatsURL = strings.TrimRight(s.cfg.MCP.BaseURL, "/") + "/api/v1/threats"
	body.ThreatsCurl = "read -rs HMD_TOKEN   # paste your token, then press Enter\n" +
		"printf 'header = \"Authorization: Bearer %s\"\\n' \"$HMD_TOKEN\" > ~/.heimdall-threats.curl\n" +
		"chmod 600 ~/.heimdall-threats.curl; unset HMD_TOKEN\n" +
		"curl -fsS --config ~/.heimdall-threats.curl '" + body.ThreatsURL + "?format=plain&min_score=12'"
	name := s.cfg.MCP.connectorName()
	body.Name, body.Named, body.FileName = name, s.cfg.MCP.Name != "" && name != config.DefaultConnectorName, mcpb.FileName(name)
	body.Desktop = desktopConfig(name, body.Endpoint)
	body.Code = "read -rs HMD_TOKEN   # paste your token, then press Enter\n" +
		"claude mcp add --scope user --transport http " + name + " " + body.Endpoint + " \\\n" +
		"  --header \"Authorization: Bearer $HMD_TOKEN\"\n" +
		"unset HMD_TOKEN"
	body.CodePS = "$t = Read-Host \"Heimdall token\" -MaskInput\n" +
		"claude mcp add --scope user --transport http " + name + " " + body.Endpoint + " --header \"Authorization: Bearer $t\"\n" +
		"Remove-Variable t"
	s.render(w, r, status, "assistants", v, "AI assistants", "assistants", body)
}

func activeTokens(ts []store.MCPToken) []tokenRow {
	var out []tokenRow
	for _, t := range ts {
		if !t.RevokedAt.IsZero() {
			continue
		}
		row := tokenRow{ID: t.ID, Name: t.Name, Purpose: t.Purpose, Threats: t.Purpose == store.PurposeThreats, Created: &t.CreatedAt}
		if !t.LastUsedAt.IsZero() {
			row.LastUsed = &t.LastUsedAt
		}
		out = append(out, row)
	}
	return out
}

// desktopConfig is the claude_desktop_config.json fallback through
// mcp-remote. The header is "Authorization:${AUTH_HEADER}" with no space
// because Claude Desktop on Windows splits arguments at spaces.
func desktopConfig(name, endpoint string) string {
	cfg := map[string]any{"mcpServers": map[string]any{name: map[string]any{
		"command": "npx",
		"args":    []string{"-y", "mcp-remote", endpoint, "--header", "Authorization:${AUTH_HEADER}"},
		"env":     map[string]string{"AUTH_HEADER": "Bearer <your token>"},
	}}}
	b, _ := json.MarshalIndent(cfg, "", "  ")
	return string(b)
}

// assistantCreate issues a token for the signed-in user and shows it once.
// The page is rendered from the POST (never a redirect), so the token is
// never in a URL or a cache (responses are no-store).
func (s *server) assistantCreate(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	if !s.cfg.MCP.Enabled {
		s.notFound(w, r, v)
		return
	}
	ctx := r.Context()
	name := strings.TrimSpace(r.PostForm.Get("name"))
	purpose := r.PostForm.Get("purpose")
	if purpose == "" {
		purpose = store.PurposeMCP
	}
	threatsToken := purpose == store.PurposeThreats
	fail := func(status int, msg string) {
		s.renderAssistants(w, r, v, status, assistantsBody{Error: msg, NewName: name, NewThreats: threatsToken})
	}
	if name == "" {
		fail(http.StatusBadRequest, "Give the token a name, like the device it's for.")
		return
	}
	if store.TokenPrefix(purpose) == "" {
		fail(http.StatusBadRequest, "Choose what the token is for: an AI assistant or the threat list.")
		return
	}
	tokens, err := s.st.ListMCPTokens(ctx, v.UserID)
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	if len(activeTokens(tokens)) >= maxMCPTokens {
		fail(http.StatusConflict, fmt.Sprintf("You already have %d tokens, the most allowed. Revoke one you no longer use first.", maxMCPTokens))
		return
	}
	if !s.tokenLimit.allow(v.UserID, s.now()) {
		fail(http.StatusTooManyRequests, "That's a lot of new tokens at once. Try again in a few minutes.")
		return
	}
	token, _, err := s.st.CreateToken(ctx, fmt.Sprintf("user:%d", v.UserID), v.UserID, name, purpose)
	if err != nil {
		var ve *store.ValidationError
		if errors.As(err, &ve) {
			fail(http.StatusBadRequest, ve.Error())
			return
		}
		s.fail(w, r, v, err)
		return
	}
	s.renderAssistants(w, r, v, http.StatusOK, assistantsBody{NewToken: token, NewName: name, NewThreats: threatsToken})
}

// assistantRevoke revokes one of the signed-in user's own tokens. The
// store matches on (token, user), so another user's token ID is not found.
func (s *server) assistantRevoke(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	if !s.cfg.MCP.Enabled {
		s.notFound(w, r, v)
		return
	}
	id, err := strconv.ParseInt(r.PostForm.Get("id"), 10, 64)
	if err == nil {
		err = s.st.RevokeMCPToken(r.Context(), fmt.Sprintf("user:%d", v.UserID), v.UserID, id)
	}
	if err != nil {
		if errors.Is(err, store.ErrNotFound) || id == 0 {
			s.renderAssistants(w, r, v, http.StatusNotFound, assistantsBody{Error: "That token doesn't exist or is already revoked."})
			return
		}
		s.fail(w, r, v, err)
		return
	}
	http.Redirect(w, r, "/account/assistants?ok=revoked", http.StatusSeeOther)
}

// assistantBundle serves the Claude Desktop extension, built for this
// hub's MCP address. It holds no token.
func (s *server) assistantBundle(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	if !s.cfg.MCP.Enabled {
		s.notFound(w, r, v)
		return
	}
	name := s.cfg.MCP.connectorName()
	b, err := mcpb.Build(s.cfg.MCP.BaseURL, s.cfg.Version, name)
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "application/zip")
	h.Set("Content-Disposition", `attachment; filename="`+mcpb.FileName(name)+`"`)
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Length", strconv.Itoa(len(b)))
	if r.Method != http.MethodHead {
		w.Write(b)
	}
}

// adminTokenRevoke lets an admin revoke any user's token from the Users
// page; requireAdmin has checked the role.
func (s *server) adminTokenRevoke(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	uid, err1 := strconv.ParseInt(r.PostForm.Get("user"), 10, 64)
	id, err2 := strconv.ParseInt(r.PostForm.Get("id"), 10, 64)
	err := errors.Join(err1, err2)
	if err == nil {
		err = s.st.RevokeMCPToken(r.Context(), fmt.Sprintf("user:%d", v.UserID), uid, id)
	}
	if err != nil {
		if errors.Is(err, store.ErrNotFound) || err1 != nil || err2 != nil {
			s.renderAdmin(w, r, v, http.StatusNotFound, "", "That token doesn't exist or is already revoked.")
			return
		}
		s.fail(w, r, v, err)
		return
	}
	http.Redirect(w, r, "/admin/users?ok=token-revoked", http.StatusSeeOther)
}
