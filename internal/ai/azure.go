// SPDX-License-Identifier: AGPL-3.0-or-later

package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// Azure is a client for an Azure AI Foundry / Azure OpenAI deployment on
// the v1 API (https://<resource>.openai.azure.com/openai/v1/...), which
// needs no api-version and takes the deployment name as "model". It speaks
// the Responses API (the default) or Chat Completions. See docs/ai.md for
// the research behind each choice.
type Azure struct {
	Endpoint        string // resource base URL, optionally ending in /openai/v1
	DeploymentName  string
	API             string // "responses" or "chat"
	Key             string // sent as the api-key header; never logged
	MaxOutputTokens int
	ReasoningEffort string       // "" = don't send
	HTTP            *http.Client // allowlisted to the endpoint's host (netx)
	UserAgent       string
	// MaxRetryWait caps how long a 429/5xx retry waits (default 20s).
	MaxRetryWait time.Duration
}

// maxResponseBytes caps what the hub reads back from the provider.
const maxResponseBytes = 2 << 20

func (a *Azure) Deployment() string { return a.DeploymentName }

// BaseURL is the v1 API root for the configured endpoint.
func (a *Azure) BaseURL() string {
	base := strings.TrimRight(a.Endpoint, "/")
	switch {
	case strings.HasSuffix(base, "/openai/v1"):
		return base
	case strings.HasSuffix(base, "/openai"):
		return base + "/v1"
	}
	return base + "/openai/v1"
}

// URL is where requests go for the configured API style.
func (a *Azure) URL() string {
	if a.API == "chat" {
		return a.BaseURL() + "/chat/completions"
	}
	return a.BaseURL() + "/responses"
}

func (a *Azure) body(req Request) map[string]any {
	if a.API == "chat" {
		b := map[string]any{
			"model": a.DeploymentName,
			"messages": []map[string]string{
				{"role": "system", "content": req.System},
				{"role": "user", "content": req.User},
			},
			// Reasoning models accept only max_completion_tokens (and no
			// temperature/top_p), so neither of those is ever sent.
			"max_completion_tokens": a.MaxOutputTokens,
		}
		if req.Schema != nil {
			b["response_format"] = map[string]any{"type": "json_schema",
				"json_schema": map[string]any{"name": req.SchemaName, "strict": true, "schema": req.Schema}}
		}
		if a.ReasoningEffort != "" {
			b["reasoning_effort"] = a.ReasoningEffort
		}
		return b
	}
	b := map[string]any{
		"model":             a.DeploymentName,
		"instructions":      req.System,
		"input":             []map[string]string{{"role": "user", "content": req.User}},
		"max_output_tokens": a.MaxOutputTokens,
		// Don't keep the request and response on the provider side for
		// later retrieval (the Responses API stores them by default).
		"store": false,
	}
	if req.Schema != nil {
		b["text"] = map[string]any{"format": map[string]any{"type": "json_schema", "name": req.SchemaName, "strict": true, "schema": req.Schema}}
	}
	if a.ReasoningEffort != "" {
		b["reasoning"] = map[string]string{"effort": a.ReasoningEffort}
	}
	return b
}

// Complete sends the request, retrying once on 429 or a 5xx when the
// deadline allows.
func (a *Azure) Complete(ctx context.Context, req Request) (*Response, error) {
	if a.Key == "" {
		return nil, &APIError{Kind: ErrAuth, Message: "no API key (run: sudo heimdall ai set-key)"}
	}
	payload, err := json.Marshal(a.body(req))
	if err != nil {
		return nil, err
	}
	start := time.Now()
	var resp *Response
	for attempt := 0; ; attempt++ {
		var wait time.Duration
		resp, wait, err = a.once(ctx, payload)
		if err == nil || attempt > 0 || wait < 0 {
			break
		}
		maxWait := a.MaxRetryWait
		if maxWait == 0 {
			maxWait = 20 * time.Second
		}
		wait = min(max(wait, time.Second), maxWait)
		if dl, ok := ctx.Deadline(); ok && time.Until(dl) < wait+5*time.Second {
			break
		}
		select {
		case <-ctx.Done():
			return nil, err
		case <-time.After(wait):
		}
	}
	if resp != nil {
		resp.Latency = time.Since(start)
	}
	return resp, err
}

// once makes one request. wait >= 0 means the error is worth one retry
// after that long.
func (a *Azure) once(ctx context.Context, payload []byte) (*Response, time.Duration, error) {
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, a.URL(), bytes.NewReader(payload))
	if err != nil {
		return nil, -1, err
	}
	hr.Header.Set("Content-Type", "application/json")
	hr.Header.Set("Accept", "application/json")
	hr.Header.Set("api-key", a.Key)
	if a.UserAgent != "" {
		hr.Header.Set("User-Agent", a.UserAgent)
	}
	res, err := a.HTTP.Do(hr)
	if err != nil {
		return nil, -1, a.transportError(ctx, err)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxResponseBytes+1))
	if err != nil {
		return nil, -1, a.transportError(ctx, err)
	}
	if len(raw) > maxResponseBytes {
		return nil, -1, &APIError{Status: res.StatusCode, Kind: ErrTooLarge, Message: fmt.Sprintf("response larger than %d bytes", maxResponseBytes)}
	}
	if res.StatusCode < 200 || res.StatusCode > 299 {
		e := a.statusError(res.StatusCode, raw)
		if res.StatusCode == http.StatusTooManyRequests || res.StatusCode >= 500 {
			return nil, retryAfter(res.Header), e
		}
		return nil, -1, e
	}
	out, err := a.parse(raw)
	if err != nil {
		return nil, -1, err
	}
	out.Status = res.StatusCode
	return out, -1, nil
}

func (a *Azure) transportError(ctx context.Context, err error) error {
	var ne net.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil || (errors.As(err, &ne) && ne.Timeout()):
		return &APIError{Kind: ErrTimeout}
	}
	return &APIError{Kind: ErrNetwork, Message: a.clean(err.Error())}
}

// retryAfter reads retry-after-ms, then retry-after (seconds).
func retryAfter(h http.Header) time.Duration {
	if ms, err := strconv.Atoi(h.Get("retry-after-ms")); err == nil && ms >= 0 {
		return time.Duration(ms) * time.Millisecond
	}
	if s, err := strconv.Atoi(h.Get("retry-after")); err == nil && s >= 0 {
		return time.Duration(s) * time.Second
	}
	return 2 * time.Second
}

func (a *Azure) statusError(status int, raw []byte) error {
	var body struct {
		Error struct {
			Code    json.RawMessage `json:"code"`
			Message string          `json:"message"`
		} `json:"error"`
	}
	_ = json.Unmarshal(raw, &body)
	code := strings.Trim(string(body.Error.Code), `"`)
	if code == "null" || len(code) > 64 || strings.ContainsFunc(code, func(r rune) bool {
		return !(unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '-' || r == '.')
	}) {
		code = ""
	}
	e := &APIError{Status: status, Code: code, Message: a.clean(body.Error.Message)}
	switch {
	case code == "content_filter":
		e.Kind = ErrFiltered
	case status == 401 || status == 403:
		e.Kind = ErrAuth
	case status == 404:
		e.Kind = ErrNotFound
	case status == 429:
		e.Kind = ErrRateLimited
	case status >= 500:
		e.Kind = ErrServer
	default:
		e.Kind = ErrBadRequest
	}
	return e
}

// clean makes provider text safe for a log line: one line, short, no key.
func (a *Azure) clean(s string) string {
	if a.Key != "" {
		s = strings.ReplaceAll(s, a.Key, "[redacted]")
	}
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > 300 {
		s = string(r[:300]) + "…"
	}
	return s
}

func (a *Azure) parse(raw []byte) (*Response, error) {
	if a.API == "chat" {
		var c struct {
			Model   string `json:"model"`
			Choices []struct {
				FinishReason string `json:"finish_reason"`
				Message      struct {
					Content *string `json:"content"`
					Refusal *string `json:"refusal"`
				} `json:"message"`
			} `json:"choices"`
			Usage struct {
				Prompt     int `json:"prompt_tokens"`
				Completion int `json:"completion_tokens"`
			} `json:"usage"`
		}
		if err := json.Unmarshal(raw, &c); err != nil {
			return nil, &APIError{Status: 200, Kind: ErrBadOutput, Message: "response isn't valid JSON"}
		}
		out := &Response{Model: a.clean(c.Model), InputTokens: c.Usage.Prompt, OutputTokens: c.Usage.Completion}
		if len(c.Choices) == 0 {
			return out, &APIError{Status: 200, Kind: ErrBadOutput, Message: "no choices in the response"}
		}
		ch := c.Choices[0]
		switch {
		case ch.FinishReason == "content_filter":
			return out, &APIError{Status: 200, Kind: ErrFiltered}
		case ch.Message.Refusal != nil && *ch.Message.Refusal != "":
			return out, &APIError{Status: 200, Kind: ErrRefused, Message: a.clean(*ch.Message.Refusal)}
		case ch.FinishReason == "length":
			return out, &APIError{Status: 200, Kind: ErrTruncated}
		case ch.Message.Content == nil:
			return out, &APIError{Status: 200, Kind: ErrBadOutput, Message: "empty message"}
		}
		out.Text = *ch.Message.Content
		return out, nil
	}
	var r struct {
		Model             string `json:"model"`
		Status            string `json:"status"`
		IncompleteDetails *struct {
			Reason string `json:"reason"`
		} `json:"incomplete_details"`
		Error *struct {
			Code    json.RawMessage `json:"code"`
			Message string          `json:"message"`
		} `json:"error"`
		Output []struct {
			Type    string `json:"type"`
			Content []struct {
				Type    string `json:"type"`
				Text    string `json:"text"`
				Refusal string `json:"refusal"`
			} `json:"content"`
		} `json:"output"`
		OutputText *string `json:"output_text"`
		Usage      struct {
			Input  int `json:"input_tokens"`
			Output int `json:"output_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, &APIError{Status: 200, Kind: ErrBadOutput, Message: "response isn't valid JSON"}
	}
	out := &Response{Model: a.clean(r.Model), InputTokens: r.Usage.Input, OutputTokens: r.Usage.Output}
	var text strings.Builder
	for _, item := range r.Output {
		if item.Type != "message" {
			continue // e.g. reasoning items
		}
		for _, c := range item.Content {
			switch c.Type {
			case "output_text":
				text.WriteString(c.Text)
			case "refusal":
				return out, &APIError{Status: 200, Kind: ErrRefused, Message: a.clean(c.Refusal)}
			}
		}
	}
	if text.Len() == 0 && r.OutputText != nil {
		text.WriteString(*r.OutputText)
	}
	switch {
	case r.Status == "incomplete" && r.IncompleteDetails != nil && r.IncompleteDetails.Reason == "content_filter":
		return out, &APIError{Status: 200, Kind: ErrFiltered}
	case r.Status == "incomplete":
		return out, &APIError{Status: 200, Kind: ErrTruncated}
	case r.Status == "failed" || r.Error != nil && r.Status != "completed":
		msg := ""
		if r.Error != nil {
			msg = a.clean(r.Error.Message)
		}
		return out, &APIError{Status: 200, Kind: ErrServer, Message: msg}
	case r.Status != "" && r.Status != "completed":
		return out, &APIError{Status: 200, Kind: ErrBadOutput, Message: "response status " + a.clean(r.Status)}
	case text.Len() == 0:
		return out, &APIError{Status: 200, Kind: ErrBadOutput, Message: "no output text"}
	}
	out.Text = text.String()
	return out, nil
}
