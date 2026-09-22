// Package httpx holds the small HTTP helpers shared by every gateway
// component: the JSON error envelope, request-id plumbing, and client IP
// resolution behind a trusted proxy.
package httpx

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
)

// ConfigError reports an invalid configuration value. It carries the field
// path so a failed start-up says which knob to fix instead of just "invalid
// config".
type ConfigError struct {
	Field string
	Value string
	Err   error
}

func (e *ConfigError) Error() string {
	msg := "invalid configuration for " + e.Field
	if e.Value != "" {
		msg += " (value " + e.Value + ")"
	}
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg
}

func (e *ConfigError) Unwrap() error { return e.Err }

// ErrorDetail is the machine-readable half of an error response. Clients are
// expected to branch on Code; Message is for humans and may change.
type ErrorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// ErrorBody is the envelope every gateway-generated response uses, so that a
// caller can parse failures without guessing at the upstream's error shape.
type ErrorBody struct {
	Error ErrorDetail `json:"error"`
}

// Error codes. Kept as constants so the tests and the docs cannot drift.
const (
	CodeUnauthorized     = "unauthorized"
	CodeForbidden        = "forbidden"
	CodeRateLimited      = "rate_limited"
	CodeNotFound         = "not_found"
	CodeBadGateway       = "bad_gateway"
	CodeTimeout          = "timeout"
	CodeServiceUnavail   = "service_unavailable"
	CodeInternal         = "internal_error"
	CodeBadRequest       = "bad_request"
	CodePayloadTooLarge  = "payload_too_large"
	CodeMethodNotAllowed = "method_not_allowed"
)

// WriteJSON serialises payload as JSON with the given status. A failure to
// encode is logged rather than silently dropped: by then the status line is
// already on the wire, so the only useful action left is to make the noise.
func WriteJSON(w http.ResponseWriter, logger *slog.Logger, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if payload == nil {
		return
	}
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		if logger != nil {
			logger.Error("encoding response body failed", "error", err)
		}
	}
}

// WriteError emits the standard error envelope. Every gateway rejection goes
// through here so the response shape is uniform.
//
// It returns the status and a nil error so that callers whose contract is
// (status, error) — the proxy, notably — can return its result directly.
func WriteError(w http.ResponseWriter, logger *slog.Logger, status int, code, message string) (int, error) {
	WriteJSON(w, logger, status, ErrorBody{Error: ErrorDetail{Code: code, Message: message}})
	return status, nil
}

// StatusForError maps a sentinel error from a leaf package onto the HTTP
// status the client should see. Anything unrecognised is a 500: the request
// was not obviously the caller's fault.
func StatusForError(err error) int {
	switch {
	case err == nil:
		return http.StatusOK
	case errors.Is(err, ErrUnauthorized):
		return http.StatusUnauthorized
	case errors.Is(err, ErrForbidden):
		return http.StatusForbidden
	case errors.Is(err, ErrRateLimited):
		return http.StatusTooManyRequests
	case errors.Is(err, ErrNotFound):
		return http.StatusNotFound
	case errors.Is(err, ErrMethodNotAllowed):
		return http.StatusMethodNotAllowed
	case errors.Is(err, ErrTimeout):
		return http.StatusGatewayTimeout
	case errors.Is(err, ErrUnavailable):
		return http.StatusServiceUnavailable
	case errors.Is(err, ErrBadRequest):
		return http.StatusBadRequest
	default:
		return http.StatusInternalServerError
	}
}

// Sentinel errors shared across packages so middleware can classify a
// rejection without importing the package that produced it.
var (
	ErrUnauthorized     = errors.New("unauthorized")
	ErrForbidden        = errors.New("forbidden")
	ErrRateLimited      = errors.New("rate limited")
	ErrNotFound         = errors.New("not found")
	ErrMethodNotAllowed = errors.New("method not allowed")
	ErrTimeout          = errors.New("upstream timeout")
	ErrUnavailable      = errors.New("upstream unavailable")
	ErrBadRequest       = errors.New("bad request")
)

// CodeForStatus returns the error code matching a status produced by
// StatusForError, keeping code and status in step.
func CodeForStatus(status int) string {
	switch status {
	case http.StatusUnauthorized:
		return CodeUnauthorized
	case http.StatusForbidden:
		return CodeForbidden
	case http.StatusTooManyRequests:
		return CodeRateLimited
	case http.StatusNotFound:
		return CodeNotFound
	case http.StatusMethodNotAllowed:
		return CodeMethodNotAllowed
	case http.StatusGatewayTimeout:
		return CodeTimeout
	case http.StatusServiceUnavailable:
		return CodeServiceUnavail
	case http.StatusBadRequest:
		return CodeBadRequest
	case http.StatusRequestEntityTooLarge:
		return CodePayloadTooLarge
	default:
		return CodeInternal
	}
}
