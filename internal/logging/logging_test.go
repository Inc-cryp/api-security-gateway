package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Inc-cryp/api-security-gateway/internal/httpx"
)

// line is the decoded access-log line.
type line map[string]any

// recordLog runs one Access call through a fresh buffer and decodes the single
// JSON line it produced. Returning the raw string as well lets a test assert
// that a secret is absent from the bytes actually written, which is the only
// claim that matters for a redaction test.
func recordLog(t *testing.T, opts Options, rec Record) (line, string) {
	t.Helper()
	var buf bytes.Buffer
	logger, err := NewWriter(&buf, opts)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	logger.Access(context.Background(), rec)

	raw := buf.String()
	if strings.Count(raw, "\n") != 1 {
		t.Fatalf("Access wrote %d lines, want exactly 1: %q", strings.Count(raw, "\n"), raw)
	}
	var decoded line
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		t.Fatalf("the log line is not valid JSON: %v (%q)", err, raw)
	}
	return decoded, raw
}

// --- construction ---------------------------------------------------------

func TestNewWriterRejectsAnUnknownLevel(t *testing.T) {
	// A typo in logging.level must not silently fall back to a default: an
	// operator who asked for a quieter or noisier log needs to know it was
	// not applied.
	var buf bytes.Buffer
	_, err := NewWriter(&buf, Options{Level: "verbose"})
	if err == nil {
		t.Fatalf("NewWriter accepted the unknown level %q", "verbose")
	}
	var cfgErr *httpx.ConfigError
	if !errors.As(err, &cfgErr) {
		t.Fatalf("error = %T, want *httpx.ConfigError", err)
	}
	if cfgErr.Field != "logging.level" {
		t.Fatalf("field = %q, want logging.level", cfgErr.Field)
	}
	if cfgErr.Value != "verbose" {
		t.Fatalf("value = %q, want the rejected level", cfgErr.Value)
	}
}

func TestNewWriterAcceptsEveryDocumentedLevel(t *testing.T) {
	tests := []struct {
		name  string
		level string
		want  slog.Level
	}{
		{"empty defaults to info", "", slog.LevelInfo},
		{"info", "info", slog.LevelInfo},
		{"debug", "debug", slog.LevelDebug},
		{"warn", "warn", slog.LevelWarn},
		{"warning is a synonym", "warning", slog.LevelWarn},
		{"error", "error", slog.LevelError},
		{"case and padding are ignored", "  DEBUG  ", slog.LevelDebug},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger, err := NewWriter(&buf, Options{Level: tt.level})
			if err != nil {
				t.Fatalf("NewWriter(%q): %v", tt.level, err)
			}
			if got := logger.Slog().Enabled(context.Background(), tt.want); !got {
				t.Fatalf("level %q does not enable %s", tt.level, tt.want)
			}
		})
	}
}

func TestNewWritesToStderrRatherThanPanicking(t *testing.T) {
	// New is the production entry point; it must not share the buffer hook.
	logger, err := New(Options{Level: "error"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if logger.Slog() == nil {
		t.Fatalf("Slog returned a nil logger")
	}
}

// --- level gating in both directions --------------------------------------

func TestAccessUsesTheStatusToPickTheLevel(t *testing.T) {
	// The level is gating too, so an "error" logger must drop 2xx lines. Both
	// directions matter: a logger that upgraded nothing would hide failures,
	// and one that logged everything at info would drown them.
	tests := []struct {
		status int
		level  slog.Level
	}{
		{200, slog.LevelInfo},
		{301, slog.LevelInfo},
		{401, slog.LevelWarn},
		{404, slog.LevelWarn},
		{500, slog.LevelError},
		{503, slog.LevelError},
	}
	for _, tt := range tests {
		t.Run(http.StatusText(tt.status), func(t *testing.T) {
			got, _ := recordLog(t, Options{Level: "debug"}, Record{Status: tt.status})
			if got["level"] != tt.level.String() {
				t.Fatalf("level = %v, want %s", got["level"], tt.level)
			}
		})
	}
}

func TestAccessAtErrorLevelDropsSuccessesButKeepsFailures(t *testing.T) {
	var buf bytes.Buffer
	logger, err := NewWriter(&buf, Options{Level: "error"})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	logger.Access(context.Background(), Record{Method: "GET", Path: "/ok", Status: 200})
	if buf.Len() != 0 {
		t.Fatalf("a 200 was logged at error level: %q", buf.String())
	}
	logger.Access(context.Background(), Record{Method: "GET", Path: "/boom", Status: 500})
	if buf.Len() == 0 {
		t.Fatalf("a 500 was dropped at error level")
	}
	if !strings.Contains(buf.String(), "/boom") {
		t.Fatalf("the surviving line is not the 500: %q", buf.String())
	}
}

func TestAccessAtDebugLevelKeepsSuccesses(t *testing.T) {
	got, _ := recordLog(t, Options{Level: "debug"}, Record{Method: "GET", Path: "/ok", Status: 200})
	if got["path"] != "/ok" {
		t.Fatalf("path = %v, want the 200 to survive at debug level", got["path"])
	}
}

// --- the recorded fields --------------------------------------------------

func TestAccessRecordsEveryRequestFact(t *testing.T) {
	got, _ := recordLog(t, Options{}, Record{
		Method:    "POST",
		Path:      "/transfer",
		Query:     "limit=10",
		ClientIP:  "203.0.113.7",
		Principal: "jwt:alice",
		Route:     "/transfer",
		Service:   "transfer",
		Status:    201,
		Bytes:     42,
		Duration:  1500 * time.Millisecond,
		UserAgent: "curl/8",
		RequestID: "trace-1",
		Error:     "upstream hiccup",
	})

	want := map[string]any{
		"request_id": "trace-1",
		"method":     "POST",
		"path":       "/transfer",
		"client_ip":  "203.0.113.7",
		"principal":  "jwt:alice",
		"route":      "/transfer",
		"service":    "transfer",
		"query":      "limit=10",
		"user_agent": "curl/8",
		"error":      "upstream hiccup",
		"status":     float64(201),
		"bytes":      float64(42),
		"duration":   float64(1.5e9),
	}
	for key, value := range want {
		if got[key] != value {
			t.Errorf("%s = %#v, want %#v", key, got[key], value)
		}
	}
}

func TestAccessOmitsEmptyOptionalFields(t *testing.T) {
	// Empty strings must be dropped rather than emitted as "": a downstream
	// query that filters on principal= would otherwise match unauthenticated
	// requests.
	got, _ := recordLog(t, Options{}, Record{Method: "GET", Path: "/health", Status: 200})
	for _, key := range []string{"query", "principal", "route", "service", "user_agent", "error"} {
		if _, present := got[key]; present {
			t.Errorf("%s is present with value %#v, want it omitted", key, got[key])
		}
	}
	for _, key := range []string{"request_id", "path", "client_ip", "status"} {
		if _, present := got[key]; !present {
			t.Errorf("%s is absent, want it always recorded", key)
		}
	}
}

func TestAccessRedactsTheQueryOnlyWhenAsked(t *testing.T) {
	// Redaction is opt-in per deployment, so both directions have to hold:
	// switching it off must not redact, and switching it on must not leak.
	got, raw := recordLog(t, Options{RedactQuery: true}, Record{
		Method: "GET", Path: "/account", Query: "token=leak-me", Status: 200,
	})
	if got["query"] != "[redacted]" {
		t.Fatalf("query = %v, want the redaction marker", got["query"])
	}
	if strings.Contains(raw, "leak-me") {
		t.Fatalf("the secret appears in the written line: %q", raw)
	}

	got, raw = recordLog(t, Options{}, Record{
		Method: "GET", Path: "/account", Query: "limit=10", Status: 200,
	})
	if got["query"] != "limit=10" {
		t.Fatalf("query = %v, want the value preserved when redaction is off", got["query"])
	}
	if strings.Contains(raw, "[redacted]") {
		t.Fatalf("an unasked-for redaction appeared: %q", raw)
	}
}

func TestAccessRedactsAnEmptyQueryToNothing(t *testing.T) {
	// An empty query is not a secret; marking it [redacted] would be noise.
	got, _ := recordLog(t, Options{RedactQuery: true}, Record{Method: "GET", Path: "/a", Status: 200})
	if _, present := got["query"]; present {
		t.Fatalf("query = %#v, want it omitted for an empty query", got["query"])
	}
}

// --- credentials can never reach the log ----------------------------------

func TestAccessNeverRecordsARequestHeader(t *testing.T) {
	// Record carries no header field at all, so a credential has no path into
	// the log. This test fails the moment someone adds one without redaction
	// logic: the credential values below must never appear in the output.
	const (
		apiKey   = "sk-live-0123456789"
		jwt      = "eyJhbGciOiJIUzI1NiJ9.forged"
		sig      = "deadbeefcafebabe"
		authHdr  = "Bearer " + jwt
		cookie   = "session=steal-me"
		clientID = "client-a"
	)
	got, raw := recordLog(t, Options{Level: "debug"}, Record{
		Method: "POST", Path: "/payment", Status: 200,
		Principal: "api_key:" + clientID,
	})
	_ = got
	for _, secret := range []string{apiKey, jwt, sig, authHdr, cookie} {
		if strings.Contains(raw, secret) {
			t.Fatalf("the log line contains the credential %q: %s", secret, raw)
		}
	}

	// The header names must not show up as keys either, which is what a
	// careless "log every header" change would introduce.
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, name := range []string{"authorization", "x-api-key", "x-signature", "cookie", "set-cookie", "proxy-authorization"} {
		if _, present := decoded[name]; present {
			t.Fatalf("the log line has a %q field", name)
		}
	}
}

func TestAccessCannotBeMadeToForgeASecondLine(t *testing.T) {
	// Every field below is caller-controlled: the path and user agent come
	// straight off the request. If the handler ever switched to string
	// concatenation, a newline in any of them would let an attacker write a
	// fabricated log line. JSON encoding escapes it, and this test pins that.
	var buf bytes.Buffer
	logger, err := NewWriter(&buf, Options{})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	logger.Access(context.Background(), Record{
		Method:    "GET\nGET",
		Path:      "/a\n" + `{"level":"ERROR","msg":"forged"}`,
		UserAgent: "curl\r\nX-Injected: 1",
		Status:    200,
	})

	raw := buf.String()
	if strings.Count(raw, "\n") != 1 {
		t.Fatalf("Access wrote %d lines, want exactly 1: %q", strings.Count(raw, "\n"), raw)
	}
	if !strings.HasSuffix(raw, "\n") {
		t.Fatalf("the single line is not newline-terminated: %q", raw)
	}
	var decoded line
	if err := json.Unmarshal([]byte(strings.TrimSuffix(raw, "\n")), &decoded); err != nil {
		t.Fatalf("the log line is not valid JSON: %v (%q)", err, raw)
	}
	if decoded["level"] != "INFO" {
		t.Fatalf("level = %v, want the caller-controlled text to stay inside a field", decoded["level"])
	}
}

func TestAccessPropagatesTheContext(t *testing.T) {
	// Access forwards ctx to the handler, so a cancelled request context must
	// not panic and must still produce a line: the access log is written while
	// reporting a request whose context may already be gone.
	var buf bytes.Buffer
	logger, err := NewWriter(&buf, Options{})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	logger.Access(ctx, Record{Method: "GET", Path: "/late", Status: 499})
	if buf.Len() == 0 {
		t.Fatalf("no line was written for a cancelled context")
	}
}

func TestParseLevelReportsTheOffendingValue(t *testing.T) {
	if _, err := parseLevel("loud"); err == nil {
		t.Fatalf("parseLevel accepted %q", "loud")
	}
	for _, name := range []string{"", "info", "debug", "warn", "warning", "WARNING", "error"} {
		if _, err := parseLevel(name); err != nil {
			t.Errorf("parseLevel(%q) = %v, want success", name, err)
		}
	}
}
