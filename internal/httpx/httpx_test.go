package httpx

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestConfigError(t *testing.T) {
	t.Run("renders field, value and cause", func(t *testing.T) {
		err := &ConfigError{Field: "security.jwt.secret", Value: "***", Err: errors.New("too short")}
		got := err.Error()
		for _, want := range []string{"security.jwt.secret", "***", "too short"} {
			if !strings.Contains(got, want) {
				t.Fatalf("Error() = %q, missing %q", got, want)
			}
		}
	})

	t.Run("omits the value when empty", func(t *testing.T) {
		err := &ConfigError{Field: "upstreams", Err: errors.New("required")}
		got := err.Error()
		if strings.Contains(got, "(value") {
			t.Fatalf("Error() = %q, want no value clause", got)
		}
		if !strings.Contains(got, "upstreams") {
			t.Fatalf("Error() = %q, want the field name", got)
		}
	})

	t.Run("unwraps to the cause", func(t *testing.T) {
		cause := errors.New("root cause")
		err := &ConfigError{Field: "x", Err: cause}
		if !errors.Is(err, cause) {
			t.Fatal("errors.Is did not find the wrapped cause")
		}
	})

	t.Run("survives a nil cause", func(t *testing.T) {
		err := &ConfigError{Field: "x"}
		if err.Error() == "" {
			t.Fatal("Error() returned an empty string")
		}
		if err.Unwrap() != nil {
			t.Fatal("Unwrap() = non-nil, want nil")
		}
	})
}

func TestStatusForError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{"nil is ok", nil, http.StatusOK},
		{"unauthorized", ErrUnauthorized, http.StatusUnauthorized},
		{"forbidden", ErrForbidden, http.StatusForbidden},
		{"rate limited", ErrRateLimited, http.StatusTooManyRequests},
		{"not found", ErrNotFound, http.StatusNotFound},
		{"method not allowed", ErrMethodNotAllowed, http.StatusMethodNotAllowed},
		{"timeout", ErrTimeout, http.StatusGatewayTimeout},
		{"unavailable", ErrUnavailable, http.StatusServiceUnavailable},
		{"bad request", ErrBadRequest, http.StatusBadRequest},
		{"unknown error is a 500", errors.New("boom"), http.StatusInternalServerError},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := StatusForError(tc.err); got != tc.want {
				t.Fatalf("StatusForError = %d, want %d", got, tc.want)
			}
		})
	}
}

// TestStatusForErrorThroughWrapping is the property that lets leaf packages
// return a sentinel wrapped with extra context and still get the right status.
func TestStatusForErrorThroughWrapping(t *testing.T) {
	wrapped := fmt.Errorf("verifying api key: %w", ErrUnauthorized)
	if got := StatusForError(wrapped); got != http.StatusUnauthorized {
		t.Fatalf("StatusForError(wrapped) = %d, want 401", got)
	}
}

// TestCodeForStatusMirrorsStatusForError pins the two tables together: every
// sentinel must map to a status that maps back to a code.
func TestCodeForStatusMirrorsStatusForError(t *testing.T) {
	sentinels := []error{
		ErrUnauthorized, ErrForbidden, ErrRateLimited, ErrNotFound,
		ErrMethodNotAllowed, ErrTimeout, ErrUnavailable, ErrBadRequest,
	}
	for _, sentinel := range sentinels {
		status := StatusForError(sentinel)
		code := CodeForStatus(status)
		if code == CodeInternal && status != http.StatusInternalServerError {
			t.Fatalf("%v maps to status %d which has no code", sentinel, status)
		}
	}

	// The reverse direction: a code must not be reused across statuses.
	seen := make(map[string]int)
	statuses := []int{
		http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests,
		http.StatusNotFound, http.StatusMethodNotAllowed, http.StatusGatewayTimeout,
		http.StatusServiceUnavailable, http.StatusBadRequest,
		http.StatusRequestEntityTooLarge,
	}
	for _, status := range statuses {
		code := CodeForStatus(status)
		if prev, dup := seen[code]; dup {
			t.Fatalf("code %q used for both status %d and %d", code, prev, status)
		}
		seen[code] = status
	}
}

func TestCodeForStatus(t *testing.T) {
	tests := []struct {
		status int
		want   string
	}{
		{http.StatusUnauthorized, CodeUnauthorized},
		{http.StatusForbidden, CodeForbidden},
		{http.StatusTooManyRequests, CodeRateLimited},
		{http.StatusNotFound, CodeNotFound},
		{http.StatusMethodNotAllowed, CodeMethodNotAllowed},
		{http.StatusGatewayTimeout, CodeTimeout},
		{http.StatusServiceUnavailable, CodeServiceUnavail},
		{http.StatusBadRequest, CodeBadRequest},
		{http.StatusRequestEntityTooLarge, CodePayloadTooLarge},
		{http.StatusInternalServerError, CodeInternal},
		{http.StatusTeapot, CodeInternal},
	}
	for _, tc := range tests {
		if got := CodeForStatus(tc.status); got != tc.want {
			t.Fatalf("CodeForStatus(%d) = %q, want %q", tc.status, got, tc.want)
		}
	}
}

func TestWriteJSON(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteJSON(rec, discardLogger(), http.StatusCreated, map[string]string{"status": "ok"})

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
		t.Fatalf("Content-Type = %q, want an application/json media type", got)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body["status"] != "ok" {
		t.Fatalf("body = %v, want status=ok", body)
	}
}

func TestWriteError(t *testing.T) {
	rec := httptest.NewRecorder()
	status, err := WriteError(rec, discardLogger(), http.StatusUnauthorized, CodeUnauthorized, "missing credentials")

	// The (status, nil) contract is what lets the proxy return the call
	// directly, so it is part of the API and not an accident.
	if status != http.StatusUnauthorized {
		t.Fatalf("returned status = %d, want 401", status)
	}
	if err != nil {
		t.Fatalf("returned err = %v, want nil", err)
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("written status = %d, want 401", rec.Code)
	}

	var body ErrorBody
	if uerr := json.Unmarshal(rec.Body.Bytes(), &body); uerr != nil {
		t.Fatalf("unmarshal: %v", uerr)
	}
	if body.Error.Code != CodeUnauthorized {
		t.Fatalf("code = %q, want %q", body.Error.Code, CodeUnauthorized)
	}
	if body.Error.Message != "missing credentials" {
		t.Fatalf("message = %q, want the supplied message", body.Error.Message)
	}
}

// TestWriteErrorEnvelopeShape pins the JSON key so clients keep working.
func TestWriteErrorEnvelopeShape(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteError(rec, discardLogger(), http.StatusForbidden, CodeForbidden, "denied")

	var raw map[string]map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := raw["error"]; !ok {
		t.Fatalf("body %s has no top-level \"error\" key", rec.Body.String())
	}
}

// --- Recorder -------------------------------------------------------------

func TestRecorderDefaultsStatusOnWrite(t *testing.T) {
	rec := NewRecorder(httptest.NewRecorder())
	if _, err := rec.Write([]byte("hello")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got := rec.Status(); got != http.StatusOK {
		t.Fatalf("Status() = %d, want 200", got)
	}
	if got := rec.Written(); got != 5 {
		t.Fatalf("Written() = %d, want 5", got)
	}
}

func TestRecorderKeepsFirstStatus(t *testing.T) {
	rec := NewRecorder(httptest.NewRecorder())
	rec.WriteHeader(http.StatusTeapot)
	rec.WriteHeader(http.StatusOK)
	if got := rec.Status(); got != http.StatusTeapot {
		t.Fatalf("Status() = %d, want the first status 418", got)
	}
}

// TestRecorderIsNotNested protects the single source of truth: the outermost
// recorder must remain the one the access log reads.
func TestRecorderIsNotNested(t *testing.T) {
	inner := NewRecorder(httptest.NewRecorder())
	outer := NewRecorder(inner)
	if outer != inner {
		t.Fatal("NewRecorder wrapped an existing Recorder")
	}
}

func TestRecorderAccumulatesAcrossWrites(t *testing.T) {
	rec := NewRecorder(httptest.NewRecorder())
	rec.WriteHeader(http.StatusAccepted)
	for _, part := range []string{"abc", "de", "f"} {
		if _, err := rec.Write([]byte(part)); err != nil {
			t.Fatalf("Write(%q): %v", part, err)
		}
	}
	if got := rec.Written(); got != 6 {
		t.Fatalf("Written() = %d, want 6", got)
	}
}

// TestRecorderWriteErrorIsSurfaced covers the append failure path: the status
// line is already on the wire, so the only thing left is to report it.
func TestRecorderWriteErrorIsSurfaced(t *testing.T) {
	failing := &failingWriter{status: http.StatusOK}
	rec := NewRecorder(failing)
	if _, err := rec.Write([]byte("body")); err == nil {
		t.Fatal("Write returned nil error, want the underlying failure")
	}
	rec.WriteHeader(http.StatusInternalServerError)
	if got := rec.Status(); got != http.StatusOK {
		t.Fatalf("Status() = %d, want the original 200", got)
	}
}

func TestRecorderFlushForwards(t *testing.T) {
	flusher := &flushRecorder{}
	rec := NewRecorder(flusher)
	rec.Flush()
	if !flusher.flushed {
		t.Fatal("Flush did not reach the underlying writer")
	}
}

// TestRecorderFlushOnPlainWriterIsNoop guards against a panic when the
// underlying writer does not implement http.Flusher.
func TestRecorderFlushOnPlainWriterIsNoop(t *testing.T) {
	rec := NewRecorder(httptest.NewRecorder())
	rec.Flush() // must not panic
}

func TestRecorderHijack(t *testing.T) {
	t.Run("unsupported writer errors", func(t *testing.T) {
		rec := NewRecorder(httptest.NewRecorder())
		if _, _, err := rec.Hijack(); err == nil {
			t.Fatal("Hijack returned nil error for a writer without hijack support")
		}
	})

	t.Run("supported writer is delegated", func(t *testing.T) {
		hijacker := &hijackRecorder{}
		rec := NewRecorder(hijacker)
		if _, _, err := rec.Hijack(); err != nil {
			t.Fatalf("Hijack: %v", err)
		}
		if !hijacker.called {
			t.Fatal("Hijack did not reach the underlying writer")
		}
	})
}

func TestRecorderUnwrap(t *testing.T) {
	underlying := httptest.NewRecorder()
	rec := NewRecorder(underlying)
	if rec.Unwrap() != http.ResponseWriter(underlying) {
		t.Fatal("Unwrap did not return the wrapped writer")
	}
}

func TestStatusFrom(t *testing.T) {
	rec := NewRecorder(httptest.NewRecorder())
	rec.WriteHeader(http.StatusNotFound)
	if got := StatusFrom(rec); got != http.StatusNotFound {
		t.Fatalf("StatusFrom = %d, want 404", got)
	}
	if got := StatusFrom(httptest.NewRecorder()); got != 0 {
		t.Fatalf("StatusFrom(plain writer) = %d, want 0", got)
	}
}

func TestRecordError(t *testing.T) {
	t.Run("keeps the first error", func(t *testing.T) {
		rec := NewRecorder(httptest.NewRecorder())
		first := errors.New("first")
		RecordError(rec, first)
		RecordError(rec, errors.New("second"))
		if got := ErrorFrom(rec); !errors.Is(got, first) {
			t.Fatalf("ErrorFrom = %v, want the first error", got)
		}
	})

	t.Run("nil error is ignored", func(t *testing.T) {
		rec := NewRecorder(httptest.NewRecorder())
		RecordError(rec, nil)
		if got := ErrorFrom(rec); got != nil {
			t.Fatalf("ErrorFrom = %v, want nil", got)
		}
	})

	t.Run("plain writer is a no-op", func(t *testing.T) {
		RecordError(httptest.NewRecorder(), errors.New("ignored")) // must not panic
		if got := ErrorFrom(httptest.NewRecorder()); got != nil {
			t.Fatalf("ErrorFrom(plain) = %v, want nil", got)
		}
	})
}

func TestRecordStatus(t *testing.T) {
	t.Run("overwrites the recorded status", func(t *testing.T) {
		rec := NewRecorder(httptest.NewRecorder())
		rec.WriteHeader(http.StatusOK)
		RecordStatus(rec, http.StatusBadGateway)
		if got := rec.Status(); got != http.StatusBadGateway {
			t.Fatalf("Status() = %d, want the upstream status 502", got)
		}
	})

	t.Run("non-positive status is ignored", func(t *testing.T) {
		rec := NewRecorder(httptest.NewRecorder())
		rec.WriteHeader(http.StatusOK)
		RecordStatus(rec, 0)
		if got := rec.Status(); got != http.StatusOK {
			t.Fatalf("Status() = %d, want 200", got)
		}
	})

	t.Run("plain writer is a no-op", func(t *testing.T) {
		RecordStatus(httptest.NewRecorder(), http.StatusTeapot) // must not panic
	})
}

// --- context plumbing -----------------------------------------------------

func TestRequestIDContext(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if got := RequestID(req.Context()); got != "" {
		t.Fatalf("RequestID on an empty context = %q, want empty", got)
	}
	ctx := WithRequestID(req.Context(), "abc-123")
	if got := RequestID(ctx); got != "abc-123" {
		t.Fatalf("RequestID = %q, want abc-123", got)
	}
}

func TestNewRequestIDIsUniqueHex(t *testing.T) {
	seen := make(map[string]bool)
	for range 128 {
		id := NewRequestID()
		if len(id) != 32 {
			t.Fatalf("NewRequestID() = %q, want 32 hex chars", id)
		}
		if seen[id] {
			t.Fatalf("NewRequestID() repeated %q", id)
		}
		seen[id] = true
	}
}

func TestIdentityString(t *testing.T) {
	tests := []struct {
		identity Identity
		want     string
	}{
		{Identity{ClientID: "svc-a", Scheme: "jwt"}, "jwt:svc-a"},
		{Identity{ClientID: "svc-a"}, ":svc-a"},
		{Identity{Scheme: "jwt"}, ""},
		{Identity{}, ""},
	}
	for _, tc := range tests {
		if got := tc.identity.String(); got != tc.want {
			t.Fatalf("Identity%+v.String() = %q, want %q", tc.identity, got, tc.want)
		}
	}
}

func TestPrincipalContext(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if _, ok := PrincipalFrom(req.Context()); ok {
		t.Fatal("PrincipalFrom reported a principal on an empty context")
	}

	ctx := WithPrincipal(req.Context(), Identity{ClientID: "svc-a", Scheme: "hmac"})
	got, ok := PrincipalFrom(ctx)
	if !ok {
		t.Fatal("PrincipalFrom did not find the stored principal")
	}
	if got.ClientID != "svc-a" || got.Scheme != "hmac" {
		t.Fatalf("PrincipalFrom = %+v, want the stored identity", got)
	}

	// An identity with no client id is not an authenticated principal, so it
	// must not be reported as one.
	ctx = WithPrincipal(req.Context(), Identity{Scheme: "hmac"})
	if _, ok := PrincipalFrom(ctx); ok {
		t.Fatal("PrincipalFrom accepted an identity with no client id")
	}
}

func TestClientIPContext(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.7:54321"
	if got := ClientIP(req); !got.Equal(net.ParseIP("203.0.113.7")) {
		t.Fatalf("ClientIP = %v, want the socket peer", got)
	}

	// A value stored on the context must win, so every stage agrees.
	stored := net.ParseIP("198.51.100.9")
	req = req.WithContext(WithClientIP(req.Context(), stored))
	if got := ClientIP(req); !got.Equal(stored) {
		t.Fatalf("ClientIP = %v, want the context value %v", got, stored)
	}
}

func TestClientIPNilRequest(t *testing.T) {
	if got := ClientIP(nil); got != nil {
		t.Fatalf("ClientIP(nil) = %v, want nil", got)
	}
}

// --- client IP resolution -------------------------------------------------

func TestClientIPResolverUntrustedPeerIgnoresForwardedHeader(t *testing.T) {
	resolver, err := NewClientIPResolver([]string{"10.0.0.0/8"}, "X-Forwarded-For")
	if err != nil {
		t.Fatalf("NewClientIPResolver: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.7:1234"
	req.Header.Set("X-Forwarded-For", "1.2.3.4")

	// 203.0.113.7 is not a trusted proxy, so its claim about the caller is
	// worthless and must be ignored.
	if got := resolver.ClientIP(req); !got.Equal(net.ParseIP("203.0.113.7")) {
		t.Fatalf("ClientIP = %v, want the untrusted peer 203.0.113.7", got)
	}
}

func TestClientIPResolverTrustedPeerWalksChainRightToLeft(t *testing.T) {
	resolver, err := NewClientIPResolver([]string{"10.0.0.0/8"}, "X-Forwarded-For")
	if err != nil {
		t.Fatalf("NewClientIPResolver: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.5:1234"
	// Supplied by a trusted proxy: client, then two intermediaries. The
	// rightmost untrusted hop is the real caller.
	req.Header.Set("X-Forwarded-For", "9.9.9.9, 8.8.8.8, 10.0.0.9")

	if got := resolver.ClientIP(req); !got.Equal(net.ParseIP("8.8.8.8")) {
		t.Fatalf("ClientIP = %v, want 8.8.8.8", got)
	}
}

func TestClientIPResolverNoTrustedProxiesIgnoresHeader(t *testing.T) {
	resolver, err := NewClientIPResolver(nil, "X-Forwarded-For")
	if err != nil {
		t.Fatalf("NewClientIPResolver: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.5:1234"
	req.Header.Set("X-Forwarded-For", "1.2.3.4")

	if got := resolver.ClientIP(req); !got.Equal(net.ParseIP("10.0.0.5")) {
		t.Fatalf("ClientIP = %v, want the peer 10.0.0.5", got)
	}
}

func TestClientIPResolverAllHopsTrustedFallsBackToPeer(t *testing.T) {
	resolver, err := NewClientIPResolver([]string{"10.0.0.0/8"}, "X-Forwarded-For")
	if err != nil {
		t.Fatalf("NewClientIPResolver: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.5:1234"
	req.Header.Set("X-Forwarded-For", "10.0.0.6, 10.0.0.7")

	// Every hop is a trusted proxy, so the chain carries no client address.
	if got := resolver.ClientIP(req); !got.Equal(net.ParseIP("10.0.0.5")) {
		t.Fatalf("ClientIP = %v, want the peer 10.0.0.5", got)
	}
}

func TestClientIPResolverSkipsUnparseableHops(t *testing.T) {
	resolver, err := NewClientIPResolver([]string{"10.0.0.0/8"}, "X-Forwarded-For")
	if err != nil {
		t.Fatalf("NewClientIPResolver: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.5:1234"
	req.Header.Set("X-Forwarded-For", "9.9.9.9, garbage, 8.8.8.8")

	if got := resolver.ClientIP(req); !got.Equal(net.ParseIP("8.8.8.8")) {
		t.Fatalf("ClientIP = %v, want 8.8.8.8", got)
	}
}

func TestClientIPResolverMultipleHeaderLines(t *testing.T) {
	resolver, err := NewClientIPResolver([]string{"10.0.0.0/8"}, "X-Forwarded-For")
	if err != nil {
		t.Fatalf("NewClientIPResolver: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.5:1234"
	req.Header.Add("X-Forwarded-For", "9.9.9.9")
	req.Header.Add("X-Forwarded-For", "8.8.8.8")

	if got := resolver.ClientIP(req); !got.Equal(net.ParseIP("8.8.8.8")) {
		t.Fatalf("ClientIP = %v, want the last hop 8.8.8.8", got)
	}
}

func TestClientIPResolverNilRequest(t *testing.T) {
	resolver, err := NewClientIPResolver(nil, "")
	if err != nil {
		t.Fatalf("NewClientIPResolver: %v", err)
	}
	if got := resolver.ClientIP(nil); got != nil {
		t.Fatalf("ClientIP(nil) = %v, want nil", got)
	}
}

func TestNewClientIPResolverRejectsBadCIDR(t *testing.T) {
	_, err := NewClientIPResolver([]string{"10.0.0.0/8", "not-a-cidr"}, "X-Forwarded-For")
	if err == nil {
		t.Fatal("expected a configuration error")
	}
	var cfgErr *ConfigError
	if !errors.As(err, &cfgErr) {
		t.Fatalf("error = %T, want *ConfigError", err)
	}
	if cfgErr.Field != "client_ip.trusted_proxies" {
		t.Fatalf("Field = %q, want client_ip.trusted_proxies", cfgErr.Field)
	}
}

func TestNewClientIPResolverSkipsBlankEntries(t *testing.T) {
	if _, err := NewClientIPResolver([]string{"", "  "}, "X-Forwarded-For"); err != nil {
		t.Fatalf("NewClientIPResolver: %v", err)
	}
}

func TestPeerIPWithoutPort(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	// httptest sets a host:port RemoteAddr; a bare address has no colon, so
	// SplitHostPort fails and the whole string must be parsed directly.
	req.RemoteAddr = "203.0.113.9"
	if got := ClientIP(req); !got.Equal(net.ParseIP("203.0.113.9")) {
		t.Fatalf("ClientIP = %v, want 203.0.113.9", got)
	}
}

func TestPeerIPIPv6WithPort(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "[2001:db8::1]:443"
	if got := ClientIP(req); !got.Equal(net.ParseIP("2001:db8::1")) {
		t.Fatalf("ClientIP = %v, want 2001:db8::1", got)
	}
}

func TestPeerIPUnparseableIsNil(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "not-an-address"
	if got := ClientIP(req); got != nil {
		t.Fatalf("ClientIP = %v, want nil", got)
	}
}

// --- test doubles ---------------------------------------------------------

// failingWriter fails every Write, exercising the recorder's error path.
type failingWriter struct {
	status int
}

func (f *failingWriter) Header() http.Header       { return http.Header{} }
func (f *failingWriter) WriteHeader(status int)    { f.status = status }
func (f *failingWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

type flushRecorder struct {
	httptest.ResponseRecorder
	flushed bool
}

func (f *flushRecorder) Flush() { f.flushed = true }

type hijackRecorder struct {
	httptest.ResponseRecorder
	called bool
}

func (h *hijackRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h.called = true
	return nil, nil, nil
}

// TestWriteJSONOnFailingWriterDoesNotPanic covers the encode path when the
// client has already gone away.
func TestWriteJSONOnFailingWriterDoesNotPanic(t *testing.T) {
	WriteJSON(&failingWriter{}, discardLogger(), http.StatusOK, map[string]string{"a": "b"})
}

// TestRecorderBodyMatchesUnderlying guards against the recorder swallowing the
// body it claims to be counting.
func TestRecorderBodyMatchesUnderlying(t *testing.T) {
	underlying := httptest.NewRecorder()
	rec := NewRecorder(underlying)
	payload := []byte(`{"hello":"world"}`)
	n, err := rec.Write(payload)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if int64(n) != rec.Written() {
		t.Fatalf("Written() = %d, want %d", rec.Written(), n)
	}
	if !bytes.Equal(underlying.Body.Bytes(), payload) {
		t.Fatalf("underlying body = %q, want %q", underlying.Body.Bytes(), payload)
	}
}
