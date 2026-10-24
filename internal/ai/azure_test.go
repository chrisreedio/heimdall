// SPDX-License-Identifier: AGPL-3.0-or-later

package ai

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testKey = "k3y-SECRET-0123456789"

// fakeAzure mimics the Azure OpenAI v1 API shapes researched for
// docs/ai.md. handle answers each request; the request is checked first.
func fakeAzure(t *testing.T, api string, handle func(w http.ResponseWriter, body map[string]any, n int)) (*Azure, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := int(calls.Add(1))
		want := "/openai/v1/responses"
		if api == "chat" {
			want = "/openai/v1/chat/completions"
		}
		if r.Method != http.MethodPost || r.URL.Path != want || r.URL.RawQuery != "" {
			t.Errorf("request %s %s?%s, want POST %s with no api-version", r.Method, r.URL.Path, r.URL.RawQuery, want)
		}
		if r.Header.Get("api-key") != testKey || r.Header.Get("Authorization") != "" {
			t.Errorf("auth headers: api-key %q, Authorization %q", r.Header.Get("api-key"), r.Header.Get("Authorization"))
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("content type %q", r.Header.Get("Content-Type"))
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("body: %v", err)
		}
		handle(w, body, n)
	}))
	t.Cleanup(srv.Close)
	return &Azure{Endpoint: srv.URL, DeploymentName: "6.1 sol", API: api, Key: testKey, MaxOutputTokens: 4000,
		HTTP: srv.Client(), MaxRetryWait: 50 * time.Millisecond}, &calls
}

func responsesOK(text string) string {
	b, _ := json.Marshal(map[string]any{
		"id": "resp_1", "object": "response", "status": "completed", "model": "gpt-sol-2026-10-01",
		"output": []any{
			map[string]any{"type": "reasoning", "summary": []any{}},
			map[string]any{"type": "message", "role": "assistant", "content": []any{
				map[string]any{"type": "output_text", "text": text, "annotations": []any{}}}},
		},
		"usage": map[string]any{"input_tokens": 1234, "output_tokens": 321, "total_tokens": 1555,
			"output_tokens_details": map[string]any{"reasoning_tokens": 200}},
	})
	return string(b)
}

func chatOK(text, finish string) string {
	b, _ := json.Marshal(map[string]any{
		"id": "chatcmpl-1", "object": "chat.completion", "model": "gpt-sol-2026-10-01",
		"choices": []any{map[string]any{"index": 0, "finish_reason": finish,
			"message": map[string]any{"role": "assistant", "content": text, "refusal": nil}}},
		"usage": map[string]any{"prompt_tokens": 900, "completion_tokens": 100, "total_tokens": 1000},
	})
	return string(b)
}

var testReq = Request{System: "sys", User: "user", SchemaName: SchemaName, Schema: Schema()}

func TestAzureResponses(t *testing.T) {
	a, _ := fakeAzure(t, "responses", func(w http.ResponseWriter, body map[string]any, _ int) {
		if body["model"] != "6.1 sol" || body["instructions"] != "sys" || body["max_output_tokens"] != float64(4000) || body["store"] != false {
			t.Errorf("body: %v", body)
		}
		for _, k := range []string{"temperature", "top_p", "max_tokens", "reasoning"} {
			if _, ok := body[k]; ok {
				t.Errorf("must not send %s", k)
			}
		}
		f := body["text"].(map[string]any)["format"].(map[string]any)
		if f["type"] != "json_schema" || f["name"] != SchemaName || f["strict"] != true || f["schema"] == nil {
			t.Errorf("format: %v", f)
		}
		io.WriteString(w, responsesOK(`{"summary":"ok","actions":[],"notes":null}`))
	})
	a.ReasoningEffort = ""
	resp, err := a.Complete(t.Context(), testReq)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Text != `{"summary":"ok","actions":[],"notes":null}` || resp.InputTokens != 1234 || resp.OutputTokens != 321 ||
		resp.Model != "gpt-sol-2026-10-01" || resp.Status != 200 {
		t.Errorf("response: %+v", resp)
	}
}

func TestAzureChatAndEffort(t *testing.T) {
	a, _ := fakeAzure(t, "chat", func(w http.ResponseWriter, body map[string]any, _ int) {
		msgs := body["messages"].([]any)
		if len(msgs) != 2 || msgs[0].(map[string]any)["role"] != "system" || body["max_completion_tokens"] != float64(4000) ||
			body["reasoning_effort"] != "low" || body["response_format"].(map[string]any)["type"] != "json_schema" {
			t.Errorf("body: %v", body)
		}
		if _, ok := body["max_tokens"]; ok {
			t.Error("must not send max_tokens")
		}
		io.WriteString(w, chatOK(`{"summary":"hi","actions":[],"notes":null}`, "stop"))
	})
	a.ReasoningEffort = "low"
	resp, err := a.Complete(t.Context(), testReq)
	if err != nil || resp.InputTokens != 900 || !strings.Contains(resp.Text, "hi") {
		t.Fatalf("%+v %v", resp, err)
	}
}

func TestAzureURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://r.openai.azure.com":             "https://r.openai.azure.com/openai/v1/responses",
		"https://r.openai.azure.com/":            "https://r.openai.azure.com/openai/v1/responses",
		"https://r.services.ai.azure.com/openai": "https://r.services.ai.azure.com/openai/v1/responses",
		"https://r.openai.azure.com/openai/v1/":  "https://r.openai.azure.com/openai/v1/responses",
	} {
		if got := (&Azure{Endpoint: in, API: "responses"}).URL(); got != want {
			t.Errorf("%s: %s", in, got)
		}
	}
}

func TestAzureErrors(t *testing.T) {
	type tc struct {
		name   string
		api    string
		handle func(w http.ResponseWriter, n int)
		kind   ErrorKind
		calls  int32
	}
	errBody := func(code, msg string) string {
		return `{"error":{"code":"` + code + `","message":"` + msg + `","param":null,"type":null}}`
	}
	for _, c := range []tc{
		{"401", "responses", func(w http.ResponseWriter, _ int) {
			w.WriteHeader(401)
			io.WriteString(w, errBody("401", "Access denied due to invalid subscription key "+testKey))
		}, ErrAuth, 1},
		{"404", "responses", func(w http.ResponseWriter, _ int) {
			w.WriteHeader(404)
			io.WriteString(w, errBody("DeploymentNotFound", "The API deployment for this resource does not exist."))
		}, ErrNotFound, 1},
		{"429 then 429", "responses", func(w http.ResponseWriter, _ int) {
			w.Header().Set("retry-after-ms", "10")
			w.WriteHeader(429)
			io.WriteString(w, errBody("429", "Requests to the Responses API have exceeded the rate limit."))
		}, ErrRateLimited, 2},
		{"500 twice", "chat", func(w http.ResponseWriter, _ int) { w.WriteHeader(500); io.WriteString(w, "<html>oops</html>") }, ErrServer, 2},
		{"content filter", "chat", func(w http.ResponseWriter, _ int) {
			w.WriteHeader(400)
			io.WriteString(w, `{"error":{"code":"content_filter","message":"The response was filtered","param":"prompt","status":400,"innererror":{"code":"ResponsibleAIPolicyViolation"}}}`)
		}, ErrFiltered, 1},
		{"malformed json", "responses", func(w http.ResponseWriter, _ int) { io.WriteString(w, `{"output": [`) }, ErrBadOutput, 1},
		{"oversized", "responses", func(w http.ResponseWriter, _ int) {
			io.WriteString(w, `{"x":"`+strings.Repeat("a", maxResponseBytes)+`"}`)
		}, ErrTooLarge, 1},
		{"incomplete", "responses", func(w http.ResponseWriter, _ int) {
			io.WriteString(w, `{"status":"incomplete","incomplete_details":{"reason":"max_output_tokens"},"output":[],"usage":{"input_tokens":5,"output_tokens":4000}}`)
		}, ErrTruncated, 1},
		{"filtered output", "responses", func(w http.ResponseWriter, _ int) {
			io.WriteString(w, `{"status":"incomplete","incomplete_details":{"reason":"content_filter"},"output":[]}`)
		}, ErrFiltered, 1},
		{"chat length", "chat", func(w http.ResponseWriter, _ int) { io.WriteString(w, chatOK("", "length")) }, ErrTruncated, 1},
		{"refusal", "responses", func(w http.ResponseWriter, _ int) {
			io.WriteString(w, `{"status":"completed","output":[{"type":"message","content":[{"type":"refusal","refusal":"I can't help with that."}]}]}`)
		}, ErrRefused, 1},
		{"no output", "responses", func(w http.ResponseWriter, _ int) { io.WriteString(w, `{"status":"completed","output":[]}`) }, ErrBadOutput, 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			a, calls := fakeAzure(t, c.api, func(w http.ResponseWriter, _ map[string]any, n int) { c.handle(w, n) })
			_, err := a.Complete(t.Context(), testReq)
			if KindOf(err) != c.kind {
				t.Fatalf("kind %v, want %v (err %v)", KindOf(err), c.kind, err)
			}
			if calls.Load() != c.calls {
				t.Errorf("%d calls, want %d", calls.Load(), c.calls)
			}
			if strings.Contains(err.Error(), testKey) {
				t.Errorf("error leaks the key: %v", err)
			}
		})
	}
}

func TestAzureRetrySucceeds(t *testing.T) {
	a, calls := fakeAzure(t, "responses", func(w http.ResponseWriter, _ map[string]any, n int) {
		if n == 1 {
			w.Header().Set("retry-after", "0")
			w.WriteHeader(429)
			return
		}
		io.WriteString(w, responsesOK(`{"summary":"s","actions":[],"notes":null}`))
	})
	if _, err := a.Complete(t.Context(), testReq); err != nil || calls.Load() != 2 {
		t.Fatalf("err %v after %d calls", err, calls.Load())
	}
}

func TestAzureTimeout(t *testing.T) {
	release := make(chan struct{})
	a, _ := fakeAzure(t, "responses", func(w http.ResponseWriter, _ map[string]any, _ int) { <-release })
	defer close(release)
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	if _, err := a.Complete(ctx, testReq); KindOf(err) != ErrTimeout {
		t.Fatalf("got %v", err)
	}
}

func TestAzureNoKey(t *testing.T) {
	a := &Azure{Endpoint: "https://x.openai.azure.com", API: "responses"}
	if _, err := a.Complete(t.Context(), testReq); KindOf(err) != ErrAuth {
		t.Fatalf("got %v", err)
	}
}
