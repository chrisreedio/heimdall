// SPDX-License-Identifier: AGPL-3.0-or-later

// Package ai is Heimdall's optional server-side analysis: a fleet brief per
// org and "explain this host", produced by the operator's own model
// deployment (Azure AI Foundry / Azure OpenAI).
//
// The design is advisory only. The hub sends compact, pre-aggregated
// facts (never raw snapshots), labelled as untrusted data; asks for
// structured output; validates it strictly; and keeps a suggested command
// only if it has the exact shape of the upgrade commands the host page
// already builds, naming packages the host really has. Nothing the model
// says is ever executed, and the UI renders it as escaped text.
package ai

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Provider is a model backend. Only the Azure OpenAI-compatible client is
// built; the interface keeps another backend a small addition.
type Provider interface {
	// Complete sends one request and returns the model's text.
	Complete(ctx context.Context, req Request) (*Response, error)
	// Deployment names what answers, for display and the audit log.
	Deployment() string
}

// Request is one structured-output call.
type Request struct {
	System     string         // instructions (rules, output format)
	User       string         // the task plus the delimited, untrusted data
	SchemaName string         // [a-zA-Z0-9_-], at most 64
	Schema     map[string]any // strict JSON schema for the output
}

// Response is what came back.
type Response struct {
	Text         string // the output text (JSON when a schema was given)
	Model        string // the model the API reports, if any
	InputTokens  int
	OutputTokens int
	Status       int // HTTP status
	Latency      time.Duration
}

// APIError is a failed call. Message is short and safe to show an admin
// on the CLI (it never contains the key); the UI shows only Kind's fixed
// text.
type APIError struct {
	Status  int    // HTTP status, 0 for transport errors
	Code    string // the API's error code, e.g. "content_filter", if any
	Message string // trimmed, single-line
	Kind    ErrorKind
}

func (e *APIError) Error() string {
	s := e.Kind.String()
	if e.Status != 0 {
		s += fmt.Sprintf(" (HTTP %d", e.Status)
		if e.Code != "" {
			s += ", " + e.Code
		}
		s += ")"
	}
	if e.Message != "" {
		s += ": " + e.Message
	}
	return s
}

// ErrorKind groups failures into a few calm, fixed messages.
type ErrorKind int

const (
	ErrUnknown     ErrorKind = iota
	ErrAuth                  // 401/403: key or permissions
	ErrNotFound              // 404: endpoint or deployment name
	ErrRateLimited           // 429
	ErrServer                // 5xx
	ErrTimeout               // deadline
	ErrNetwork               // couldn't connect
	ErrBadRequest            // other 4xx
	ErrFiltered              // content filter
	ErrTruncated             // ran out of output tokens
	ErrBadOutput             // not valid JSON / doesn't match the schema
	ErrTooLarge              // response bigger than the cap
	ErrRefused               // the model refused
)

// String is the fixed, user-facing description of the failure.
func (k ErrorKind) String() string {
	switch k {
	case ErrAuth:
		return "The AI provider rejected the key (check it with: heimdall ai status)"
	case ErrNotFound:
		return "The AI endpoint or deployment wasn't found (check [ai] endpoint and deployment)"
	case ErrRateLimited:
		return "The AI provider is rate limiting requests; try again in a few minutes"
	case ErrServer:
		return "The AI provider had a server error; try again later"
	case ErrTimeout:
		return "The AI provider didn't answer in time"
	case ErrNetwork:
		return "Couldn't reach the AI provider"
	case ErrBadRequest:
		return "The AI provider refused the request (see the hub log)"
	case ErrFiltered:
		return "The AI provider's content filter blocked this request"
	case ErrTruncated:
		return "The model ran out of output tokens (raise [ai] max_output_tokens)"
	case ErrBadOutput:
		return "The model's answer wasn't in the expected format"
	case ErrTooLarge:
		return "The model's answer was too large"
	case ErrRefused:
		return "The model declined to answer"
	}
	return "The analysis failed (see the hub log)"
}

// KindOf returns the error's kind (ErrUnknown for non-API errors).
func KindOf(err error) ErrorKind {
	var e *APIError
	if errors.As(err, &e) {
		return e.Kind
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return ErrTimeout
	}
	return ErrUnknown
}
