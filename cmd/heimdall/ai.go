// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/chrisreedio/heimdall/internal/ai"
	"github.com/chrisreedio/heimdall/internal/config"
	"github.com/chrisreedio/heimdall/internal/netx"
	"github.com/chrisreedio/heimdall/internal/store"
)

// aiCredential is the systemd credential name holding the AI API key.
const aiCredential = "heimdall-ai"

// defaultAIKeyFile is where the unit's LoadCredential line reads it.
const defaultAIKeyFile = "/etc/heimdall/ai-key"

// aiHTTPClient builds the AI client's HTTP client: HTTPS to the endpoint's
// host only, with the configured timeout. A seam for tests.
var aiHTTPClient = func(cfg config.AI) *http.Client {
	hc := *netx.New([]string{cfg.Host()}, "heimdall/"+version).HTTPClient()
	hc.Timeout = cfg.Timeout.Duration
	return &hc
}

// cmdAISetKey stores the API key exactly like `sso set-secret` stores the
// Entra secret: read with echo off (or from stdin), written owner-only and
// atomically, and loaded by the hub as a systemd credential.
func cmdAISetKey(a *app, args []string) error {
	fs := a.flags("ai set-key", "[--file path] [--stdin] [--unit path]")
	path := fs.String("file", defaultAIKeyFile, "where to store the key (the unit's LoadCredential source)")
	fromStdin := fs.Bool("stdin", false, "read the key from stdin instead of a terminal prompt")
	unitFile := fs.String("unit", hubUnitFile, "the hub's systemd unit (gets the LoadCredential line)")
	if _, err := parse(fs, args, 0); err != nil {
		return err
	}
	var key string
	if *fromStdin {
		b, err := io.ReadAll(io.LimitReader(stdin, 4097))
		if err != nil {
			return err
		}
		key = strings.TrimSpace(string(b))
	} else {
		in, err := newInput(a, false)
		if err != nil {
			return errors.New("stdin is not a terminal; use --stdin to pipe the key")
		}
		if key, err = in.line("Azure AI API key (input hidden): ", true); err != nil {
			return err
		}
		key = strings.TrimSpace(key)
	}
	if key == "" {
		return errors.New("empty key")
	}
	if len(key) > 4096 || strings.ContainsFunc(key, func(r rune) bool { return r <= ' ' || r == 0x7f }) {
		return errors.New("that doesn't look like an API key (copy KEY 1 or KEY 2 from the resource's Keys and Endpoint page)")
	}
	if err := writePrivate(*path, key+"\n"); err != nil {
		return err
	}
	fmt.Fprintf(a.stderr, "Stored the AI API key in %s (owner-only).\n", *path)
	if *path == defaultAIKeyFile || *unitFile != hubUnitFile {
		changed, err := enableCredential(*unitFile, aiCredential, *path)
		switch {
		case err != nil:
			fmt.Fprintf(a.stderr, "Couldn't update the unit (%v).\nAdd `LoadCredential=%s:%s` to it yourself, then: sudo heimdall restart\n", err, aiCredential, *path)
			return nil
		case changed:
			fmt.Fprintf(a.stderr, "Added LoadCredential=%s to %s.\n", aiCredential, *unitFile)
			if *unitFile == hubUnitFile {
				if err := systemctl(a, "daemon-reload"); err != nil {
					fmt.Fprintf(a.stderr, "systemctl daemon-reload failed: %v\n", err)
				}
			}
		}
	}
	fmt.Fprintln(a.stderr, "Check it with `sudo heimdall ai test`, then apply with: sudo heimdall restart")
	return nil
}

// aiKey reads the API key from the systemd credential, or from
// HEIMDALL_AI_KEY_FILE. It is never read from the config file. With
// fallback (CLI as root), the default key file is used directly.
func aiKey(fallback bool) (string, string, error) {
	path, fromSystemd := os.Getenv("HEIMDALL_AI_KEY_FILE"), false
	if path == "" {
		if dir := os.Getenv("CREDENTIALS_DIRECTORY"); dir != "" {
			if _, err := os.Stat(filepath.Join(dir, aiCredential)); err == nil {
				path, fromSystemd = filepath.Join(dir, aiCredential), true
			}
		}
	}
	if path == "" && fallback {
		path = defaultAIKeyFile
	}
	if path == "" {
		return "", "", errors.New("no AI API key: run `sudo heimdall ai set-key` (it adds `LoadCredential=" + aiCredential +
			":" + defaultAIKeyFile + "` to the unit), or set HEIMDALL_AI_KEY_FILE")
	}
	fi, err := os.Stat(path)
	if err != nil {
		return "", path, fmt.Errorf("AI API key: %w", err)
	}
	if !fromSystemd && fi.Mode().Perm()&0o077 != 0 {
		return "", path, fmt.Errorf("AI API key %s is readable by other users; run `chmod 600 %s`", path, path)
	}
	if fi.Size() > 4096 {
		return "", path, fmt.Errorf("AI API key %s is suspiciously large", path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", path, err
	}
	key := strings.TrimSpace(string(b))
	if key == "" {
		return "", path, fmt.Errorf("AI API key %s is empty", path)
	}
	return key, path, nil
}

func newAIProvider(cfg config.AI, key string) *ai.Azure {
	return &ai.Azure{Endpoint: cfg.Endpoint, DeploymentName: cfg.Deployment, API: cfg.API, Key: key,
		MaxOutputTokens: cfg.MaxOutputTokens, ReasoningEffort: cfg.ReasoningEffort,
		HTTP: aiHTTPClient(cfg), UserAgent: "heimdall/" + version}
}

// newAIService builds the AI service for serve (nil when [ai] is off). A
// missing key doesn't stop the hub: runs then fail with a calm "check the
// key" message and the log says why.
func newAIService(cfg config.Config, s *store.Store, log *slog.Logger) *ai.Service {
	if !cfg.AI.Enabled {
		return nil
	}
	key, _, err := aiKey(false)
	if err != nil {
		log.Error("AI analysis is enabled but has no key", "err", err)
	}
	svc := &ai.Service{Provider: newAIProvider(cfg.AI, key), Store: s, Log: log.With("component", "ai"), Now: time.Now,
		StaleAfter: cfg.Hosts.StaleAfter.Duration, MaxInputTokens: cfg.AI.MaxInputTokens,
		Timeout: cfg.AI.Timeout.Duration, BriefEvery: cfg.AI.BriefEvery.Duration}
	svc.Init()
	log.Info("AI analysis on", "endpoint", newAIProvider(cfg.AI, "").URL(), "deployment", cfg.AI.Deployment,
		"api", cfg.AI.API, "brief_every", cfg.AI.BriefEvery.Duration.String())
	return svc
}

func cmdAIStatus(a *app, args []string) error {
	if _, err := parse(a.flags("ai status", ""), args, 0); err != nil {
		return err
	}
	cfg, err := config.Load(a.configPath)
	if err != nil {
		return err
	}
	c := cfg.AI
	out := a.stdout
	if !c.Enabled {
		fmt.Fprintln(out, "AI analysis: off (set enabled = true under [ai] in heimdall.toml)")
		return nil
	}
	p := newAIProvider(c, "")
	every := "on demand only"
	if c.BriefEvery.Duration > 0 {
		every = "every " + c.BriefEvery.Duration.String()
	}
	fmt.Fprintf(out, "AI analysis: on\nEndpoint:    %s\nDeployment:  %s\nAPI:         %s\nBrief:       %s\n", p.URL(), c.Deployment, c.API, every)
	fmt.Fprintf(out, "Limits:      %d output tokens, about %d input tokens, %s timeout\n", c.MaxOutputTokens, c.MaxInputTokens, c.Timeout.Duration)
	switch _, path, err := aiKey(false); {
	case err == nil:
		fmt.Fprintf(out, "Key:         loaded from %s\n", path)
	default:
		if fi, serr := os.Stat(defaultAIKeyFile); serr == nil && fi.Mode().IsRegular() {
			fmt.Fprintf(out, "Key:         stored in %s (the hub loads it as credential %q)\n", defaultAIKeyFile, aiCredential)
		} else {
			fmt.Fprintln(out, "Key:         not set (run `sudo heimdall ai set-key`)")
		}
	}
	s, err := a.openStore()
	if err != nil {
		return err
	}
	defer s.Close()
	orgs, err := s.ListOrgs(a.ctx)
	if err != nil {
		return err
	}
	var rows [][]string
	for _, o := range orgs {
		runs, err := s.AIRuns(a.ctx, o.ID, 0, 1)
		if err != nil {
			return err
		}
		if len(runs) == 0 {
			rows = append(rows, []string{o.Slug, "brief", "never", "", "", ""})
			continue
		}
		r := runs[0]
		rows = append(rows, []string{o.Slug, "brief", formatTime(r.CreatedAt), r.Status,
			strconv.Itoa(r.InputTokens) + "/" + strconv.Itoa(r.OutputTokens), r.Error})
	}
	fmt.Fprintln(out)
	return table(a, "ORG\tKIND\tLAST RUN\tSTATUS\tTOKENS IN/OUT\tERROR", rows)
}

// cmdAITest makes one tiny structured-output request and reports the HTTP
// status and latency. It never prints the key.
func cmdAITest(a *app, args []string) error {
	if _, err := parse(a.flags("ai test", ""), args, 0); err != nil {
		return err
	}
	cfg, err := config.Load(hubConfigPath(a.configPath))
	if err != nil {
		return err
	}
	c := cfg.AI
	if !c.Enabled {
		return errors.New("[ai] is off; set enabled = true, endpoint and deployment in heimdall.toml first")
	}
	key, path, err := aiKey(isRoot())
	if err != nil {
		return err
	}
	p := newAIProvider(c, key)
	p.MaxOutputTokens = min(c.MaxOutputTokens, 2048)
	p.MaxRetryWait = time.Second
	fmt.Fprintf(a.stderr, "POST %s (deployment %s, %s API, key from %s)\n", p.URL(), c.Deployment, c.API, path)
	ctx, cancel := context.WithTimeout(a.ctx, c.Timeout.Duration)
	defer cancel()
	resp, err := p.Complete(ctx, ai.Request{
		System:     "You are a connectivity test. Answer with the JSON object only.",
		User:       `Reply with {"ok": true}.`,
		SchemaName: "heimdall_test",
		Schema: map[string]any{"type": "object", "additionalProperties": false, "required": []string{"ok"},
			"properties": map[string]any{"ok": map[string]any{"type": "boolean"}}},
	})
	if err != nil {
		return fmt.Errorf("test failed: %w", err)
	}
	fmt.Fprintf(a.stdout, "OK: HTTP %d in %s, model %q, %d input / %d output tokens\n",
		resp.Status, resp.Latency.Round(time.Millisecond), resp.Model, resp.InputTokens, resp.OutputTokens)
	if !strings.Contains(strings.ReplaceAll(resp.Text, " ", ""), `"ok":true`) {
		fmt.Fprintf(a.stdout, "Note: the answer wasn't the expected JSON (structured output may not be supported by this deployment): %.80q\n", resp.Text)
	}
	return nil
}
