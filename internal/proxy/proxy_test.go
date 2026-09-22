package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Inc-cryp/api-security-gateway/internal/breaker"
	"github.com/Inc-cryp/api-security-gateway/internal/httpx"
	"github.com/Inc-cryp/api-security-gateway/internal/router"
)

func mustProxy(t *testing.T, cfg Config) *Proxy {
	t.Helper()
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

func decodeError(t *testing.T, rec *httptest.ResponseRecorder) httpx.ErrorDetail {
	t.Helper()
	var body httpx.ErrorBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response body is not the JSON error envelope: %v (%q)", err, rec.Body.String())
	}
	return body.Error
}

// --- nil breaker registry -------------------------------------------------
// TestServeWithoutABreakerRegistryStillProxies is the regression test for a
// nil dereference: Config.Breaker documents that a nil registry disables the
// breaker, but Registry.Get used to lock a nil mutex, so every proxied
// request panicked. A deployment that never configures a breaker is the
// default, so this was the common path.
func TestServeWithoutABreakerRegistryStillProxies(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	p := mustProxy(t, Config{Services: map[string]string{"account": upstream.URL}})
	route := &router.Route{Path: "/a", Service: "account"}
	rec := httptest.NewRecorder()

	status, err := p.Serve(rec, httptest.NewRequest(http.MethodGet, "/a", nil), route)
	if err != nil {
		t.Fatalf("Serve with no breaker registry: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
}

// TestBreakerRegistryGetOnANilRegistry covers the same defect one level down,
// where it is unambiguous: the call must return a usable breaker rather than
// panic.
func TestBreakerRegistryGetOnANilRegistry(t *testing.T) {
	var registry *breaker.Registry
	b := registry.Get("account")
	if b == nil {
		t.Fatalf("Get on a nil registry returned a nil breaker")
	}
	if b.State() != breaker.Closed {
		t.Fatalf("state = %v, want the breaker disabled (closed)", b.State())
	}
	// A breaker that always allows traffic is what "disabled" means in
	// practice, so confirm nothing has started rejecting.
	if !b.Allow() {
		t.Fatalf("a nil registry must disable the breaker, but it is rejecting traffic")
	}
	b.Record(false)
	if !b.Allow() {
		t.Fatalf("a single failure opened the substituted breaker")
	}
}

func TestNewRejectsBadServiceConfig(t *testing.T) {
	tests := []struct {
		name  string
		cfg   Config
		field string
	}{
		{"no services", Config{}, "upstream.services"},
		{"empty service name", Config{Services: map[string]string{"": "http://127.0.0.1:1"}}, "upstream.services"},
		{"blank service name", Config{Services: map[string]string{"   ": "http://127.0.0.1:1"}}, "upstream.services"},
		{"bad scheme", Config{Services: map[string]string{"a": "ftp://127.0.0.1"}}, "upstream.services.a"},
		{"no scheme", Config{Services: map[string]string{"a": "127.0.0.1:9001"}}, "upstream.services.a"},
		{"no host", Config{Services: map[string]string{"a": "http://"}}, "upstream.services.a"},
		{"unparseable", Config{Services: map[string]string{"a": "http://[::1"}}, "upstream.services.a"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(tt.cfg)
			if err == nil {
				t.Fatalf("New accepted an invalid config")
			}
			var cfgErr *httpx.ConfigError
			if !errors.As(err, &cfgErr) {
				t.Fatalf("err = %T (%v), want *httpx.ConfigError", err, err)
			}
			if cfgErr.Field != tt.field {
				t.Fatalf("ConfigError.Field = %q, want %q", cfgErr.Field, tt.field)
			}
		})
	}
}

func TestNewDefaultsTheTimeout(t *testing.T) {
	p := mustProxy(t, Config{Services: map[string]string{"a": "http://127.0.0.1:1"}})
	if p.timeout != 30*time.Second {
		t.Fatalf("timeout = %s, want the 30s default", p.timeout)
	}
}

func TestServicesIsSortedAndStable(t *testing.T) {
	p := mustProxy(t, Config{Services: map[string]string{
		"transfer": "http://127.0.0.1:3",
		"account":  "http://127.0.0.1:1",
		"payment":  "http://127.0.0.1:2",
	}})
	got := p.Services()
	want := []string{"account", "payment", "transfer"}
	if len(got) != len(want) {
		t.Fatalf("Services() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Services() = %v, want %v", got, want)
		}
	}
}

// --- Serve ----------------------------------------------------------------

func TestServeForwardsMethodPathQueryAndBody(t *testing.T) {
	type seen struct {
		method string
		path   string
		query  string
		body   string
		header http.Header
	}
	got := make(chan seen, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got <- seen{r.Method, r.URL.Path, r.URL.RawQuery, string(body), r.Header.Clone()}
		w.Header().Set("X-Upstream", "yes")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	p := mustProxy(t, Config{Services: map[string]string{"account": upstream.URL}})
	route := &router.Route{Path: "/account", Service: "account"}

	req := httptest.NewRequest(http.MethodPost, "/account/123?q=1", strings.NewReader(`{"amount":5}`))
	req.Header.Set("Authorization", "Bearer token")
	req.Header.Set("X-Api-Key", "secret")
	rec := httptest.NewRecorder()

	status, err := p.Serve(rec, req, route)
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if status != http.StatusCreated {
		t.Fatalf("Serve status = %d, want 201", status)
	}
	if rec.Code != http.StatusCreated {
		t.Fatalf("recorder code = %d, want 201", rec.Code)
	}
	if rec.Body.String() != `{"ok":true}` {
		t.Fatalf("body = %q, want the upstream body", rec.Body.String())
	}
	if rec.Header().Get("X-Upstream") != "yes" {
		t.Fatalf("the upstream response header was not copied back")
	}

	select {
	case s := <-got:
		if s.method != http.MethodPost {
			t.Fatalf("upstream saw method %q, want POST", s.method)
		}
		if s.path != "/account/123" {
			t.Fatalf("upstream saw path %q, want /account/123", s.path)
		}
		if s.query != "q=1" {
			t.Fatalf("upstream saw query %q, want q=1", s.query)
		}
		if s.body != `{"amount":5}` {
			t.Fatalf("upstream saw body %q, want the original body", s.body)
		}
		if s.header.Get("Authorization") != "Bearer token" || s.header.Get("X-Api-Key") != "secret" {
			t.Fatalf("end-to-end credentials did not reach the upstream: %v", s.header)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("the upstream was never called")
	}
}

func TestServeAppliesStripPrefix(t *testing.T) {
	got := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	p := mustProxy(t, Config{Services: map[string]string{"account": upstream.URL}})
	route := &router.Route{Path: "/api/account", Service: "account", StripPrefix: true}
	if _, err := p.Serve(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/account/42", nil), route); err != nil {
		t.Fatalf("Serve: %v", err)
	}

	select {
	case path := <-got:
		if path != "/42" {
			t.Fatalf("upstream path = %q, want /42", path)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("the upstream was never called")
	}
}

func TestServePreservesTheUpstreamBasePath(t *testing.T) {
	got := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	p := mustProxy(t, Config{Services: map[string]string{"account": upstream.URL + "/base"}})
	route := &router.Route{Path: "/account", Service: "account"}
	if _, err := p.Serve(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/account/7", nil), route); err != nil {
		t.Fatalf("Serve: %v", err)
	}

	select {
	case path := <-got:
		if path != "/base/account/7" {
			t.Fatalf("upstream path = %q, want /base/account/7", path)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("the upstream was never called")
	}
}

func TestServeRejectsAnUnconfiguredService(t *testing.T) {
	p := mustProxy(t, Config{Services: map[string]string{"account": "http://127.0.0.1:1"}})
	route := &router.Route{Path: "/x", Service: "ghost"}
	rec := httptest.NewRecorder()

	status, err := p.Serve(rec, httptest.NewRequest(http.MethodGet, "/x", nil), route)
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if status != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", status)
	}
	if got := decodeError(t, rec).Code; got != httpx.CodeBadGateway {
		t.Fatalf("error code = %q, want %q", got, httpx.CodeBadGateway)
	}
}

func TestServeDoesNotFollowRedirects(t *testing.T) {
	// A followed redirect would replay the caller's credentials to whatever
	// host the upstream names.
	var otherHits int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&otherHits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer other.Close()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/stolen", http.StatusFound)
	}))
	defer upstream.Close()

	p := mustProxy(t, Config{Services: map[string]string{"account": upstream.URL}})
	route := &router.Route{Path: "/a", Service: "account"}
	req := httptest.NewRequest(http.MethodGet, "/a", nil)
	req.Header.Set("Authorization", "Bearer token")
	rec := httptest.NewRecorder()

	status, err := p.Serve(rec, req, route)
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if status != http.StatusFound {
		t.Fatalf("status = %d, want the upstream 302 to pass through", status)
	}
	if n := atomic.LoadInt32(&otherHits); n != 0 {
		t.Fatalf("the redirect target was contacted %d times; the gateway must not follow redirects", n)
	}
}

// --- header hygiene -------------------------------------------------------

func TestServeStripsHopByHopRequestHeaders(t *testing.T) {
	received := make(chan http.Header, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	p := mustProxy(t, Config{Services: map[string]string{"account": upstream.URL}})
	route := &router.Route{Path: "/a", Service: "account"}

	req := httptest.NewRequest(http.MethodGet, "/a", nil)
	// A Connection header nominates an extra, otherwise end-to-end header as
	// connection-specific. Missing that case is the classic hop-by-hop bug.
	req.Header.Set("Connection", "X-Client-Hop")
	req.Header.Set("X-Client-Hop", "must-not-forward")
	req.Header.Set("Keep-Alive", "timeout=5")
	req.Header.Set("Proxy-Authorization", "Basic zzz")
	req.Header.Set("Te", "trailers")
	req.Header.Set("Trailer", "X-Trailer")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Transfer-Encoding", "chunked")
	req.Header.Set("X-Api-Key", "secret")

	if _, err := p.Serve(httptest.NewRecorder(), req, route); err != nil {
		t.Fatalf("Serve: %v", err)
	}

	select {
	case header := <-received:
		for _, name := range hopByHopHeaders {
			if value := header.Get(name); value != "" {
				t.Fatalf("hop-by-hop header %s reached the upstream with value %q", name, value)
			}
		}
		if value := header.Get("X-Client-Hop"); value != "" {
			t.Fatalf("the header named by Connection (%q) reached the upstream", value)
		}
		if header.Get("X-Api-Key") != "secret" {
			t.Fatalf("X-Api-Key did not reach the upstream: end-to-end headers must survive")
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("the upstream was never called")
	}
}

func TestServeStripsHopByHopResponseHeaders(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "X-Upstream-Hop")
		w.Header().Set("X-Upstream-Hop", "must-not-reach-client")
		w.Header().Set("Keep-Alive", "timeout=5")
		w.Header().Set("X-End-To-End", "keep-me")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	p := mustProxy(t, Config{Services: map[string]string{"account": upstream.URL}})
	route := &router.Route{Path: "/a", Service: "account"}
	rec := httptest.NewRecorder()

	if _, err := p.Serve(rec, httptest.NewRequest(http.MethodGet, "/a", nil), route); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if value := rec.Header().Get("X-Upstream-Hop"); value != "" {
		t.Fatalf("the response header named by Connection (%q) reached the client", value)
	}
	if rec.Header().Get("Keep-Alive") != "" {
		t.Fatalf("Keep-Alive reached the client")
	}
	if rec.Header().Get("X-End-To-End") != "keep-me" {
		t.Fatalf("an end-to-end response header was stripped")
	}
}

func TestStripHopByHopDirectly(t *testing.T) {
	header := http.Header{}
	header.Set("Connection", "keep-alive, X-Custom ,X-Other")
	header.Set("X-Custom", "1")
	header.Set("X-Other", "2")
	header.Set("X-Keep", "3")
	header.Set("Keep-Alive", "timeout=5")

	stripHopByHop(header)

	for _, name := range []string{"Connection", "X-Custom", "X-Other", "Keep-Alive"} {
		if value := header.Get(name); value != "" {
			t.Fatalf("%s = %q, want it stripped", name, value)
		}
	}
	if header.Get("X-Keep") != "3" {
		t.Fatalf("X-Keep was stripped, want it kept")
	}
}

func TestServeSetsForwardingHeaders(t *testing.T) {
	received := make(chan http.Header, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	p := mustProxy(t, Config{Services: map[string]string{"account": upstream.URL}})
	route := &router.Route{Path: "/a", Service: "account"}

	ctx := httpx.WithClientIP(context.Background(), net.ParseIP("10.1.2.3"))
	ctx = httpx.WithRequestID(ctx, "req-123")
	req := httptest.NewRequest(http.MethodGet, "/a", nil).WithContext(ctx)
	// A spoofed X-Forwarded-For must be replaced, not appended to.
	req.Header.Set("X-Forwarded-For", "203.0.113.99")
	req.Header.Set("Forwarded", "for=203.0.113.99")

	if _, err := p.Serve(httptest.NewRecorder(), req, route); err != nil {
		t.Fatalf("Serve: %v", err)
	}

	select {
	case header := <-received:
		if got := header.Get("X-Forwarded-For"); got != "10.1.2.3" {
			t.Fatalf("X-Forwarded-For = %q, want the resolved client IP only", got)
		}
		if got := header.Get("X-Forwarded-Proto"); got != "http" {
			t.Fatalf("X-Forwarded-Proto = %q, want http", got)
		}
		if got := header.Get("X-Forwarded-Host"); got == "" {
			t.Fatalf("X-Forwarded-Host was not set")
		}
		if got := header.Get("Forwarded"); got != "" {
			t.Fatalf("Forwarded = %q, want it removed: it is trivially spoofable", got)
		}
		if got := header.Get(httpx.RequestIDHeader); got != "req-123" {
			t.Fatalf("%s = %q, want req-123", httpx.RequestIDHeader, got)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("the upstream was never called")
	}
}

// --- timeout --------------------------------------------------------------

func TestServeHonoursTheRouteTimeout(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer upstream.Close()

	p := mustProxy(t, Config{Services: map[string]string{"account": upstream.URL}})
	route := &router.Route{Path: "/a", Service: "account", Timeout: 50 * time.Millisecond}
	rec := httptest.NewRecorder()

	status, err := p.Serve(rec, httptest.NewRequest(http.MethodGet, "/a", nil), route)
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if status != http.StatusGatewayTimeout {
		t.Fatalf("status = %d, want 504", status)
	}
	if got := decodeError(t, rec).Code; got != httpx.CodeTimeout {
		t.Fatalf("error code = %q, want %q", got, httpx.CodeTimeout)
	}
}

func TestServeFallsBackToTheDefaultTimeout(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer upstream.Close()

	p := mustProxy(t, Config{Services: map[string]string{"account": upstream.URL}, DefaultTimeout: 40 * time.Millisecond})
	route := &router.Route{Path: "/a", Service: "account"}
	rec := httptest.NewRecorder()

	status, err := p.Serve(rec, httptest.NewRequest(http.MethodGet, "/a", nil), route)
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if status != http.StatusGatewayTimeout {
		t.Fatalf("status = %d, want 504 from the default timeout", status)
	}
}

// --- breaker --------------------------------------------------------------

func TestServeTripsTheBreakerOnServerErrors(t *testing.T) {
	var hits int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer upstream.Close()

	registry := breaker.NewRegistry(breaker.Config{FailureThreshold: 2, OpenTimeout: time.Minute})
	p := mustProxy(t, Config{Services: map[string]string{"account": upstream.URL}, Breaker: registry})
	route := &router.Route{Path: "/a", Service: "account"}

	for i := range 2 {
		if _, err := p.Serve(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/a", nil), route); err != nil {
			t.Fatalf("Serve %d: %v", i, err)
		}
	}
	if got := registry.Get("account").State(); got != breaker.Open {
		t.Fatalf("breaker state = %v, want Open after 2 consecutive 5xx", got)
	}
	before := atomic.LoadInt32(&hits)

	rec := httptest.NewRecorder()
	status, err := p.Serve(rec, httptest.NewRequest(http.MethodGet, "/a", nil), route)
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if status != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 while the circuit is open", status)
	}
	if got := decodeError(t, rec).Code; got != httpx.CodeServiceUnavail {
		t.Fatalf("error code = %q, want %q", got, httpx.CodeServiceUnavail)
	}
	if after := atomic.LoadInt32(&hits); after != before {
		t.Fatalf("the upstream was called %d more times while the circuit was open", after-before)
	}
}

func TestServeDoesNotTripTheBreakerOnClientErrors(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer upstream.Close()

	registry := breaker.NewRegistry(breaker.Config{FailureThreshold: 2, OpenTimeout: time.Minute})
	p := mustProxy(t, Config{Services: map[string]string{"account": upstream.URL}, Breaker: registry})
	route := &router.Route{Path: "/a", Service: "account"}

	for i := range 10 {
		if _, err := p.Serve(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/a", nil), route); err != nil {
			t.Fatalf("Serve %d: %v", i, err)
		}
	}
	if got := registry.Get("account").State(); got != breaker.Closed {
		t.Fatalf("breaker state = %v, want Closed: a 4xx is the caller's fault", got)
	}
}

func TestServeClosesTheBreakerAfterTheUpstreamRecovers(t *testing.T) {
	var fail atomic.Bool
	fail.Store(true)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	registry := breaker.NewRegistry(breaker.Config{
		FailureThreshold:  2,
		OpenTimeout:       20 * time.Millisecond,
		HalfOpenSuccesses: 1,
	})
	p := mustProxy(t, Config{Services: map[string]string{"account": upstream.URL}, Breaker: registry})
	route := &router.Route{Path: "/a", Service: "account"}

	for range 2 {
		if _, err := p.Serve(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/a", nil), route); err != nil {
			t.Fatalf("Serve: %v", err)
		}
	}
	if got := registry.Get("account").State(); got != breaker.Open {
		t.Fatalf("breaker state = %v, want Open", got)
	}

	// The breaker's transition is wall-clock driven, so this wait is inherent.
	time.Sleep(40 * time.Millisecond)
	fail.Store(false)

	rec := httptest.NewRecorder()
	status, err := p.Serve(rec, httptest.NewRequest(http.MethodGet, "/a", nil), route)
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200 once the upstream recovered", status)
	}
	if got := registry.Get("account").State(); got != breaker.Closed {
		t.Fatalf("breaker state = %v, want Closed after the probe succeeded", got)
	}
}

// --- transport failures ---------------------------------------------------

func TestServeReportsAnUnreachableUpstream(t *testing.T) {
	// Bind a listener and close it so the port refuses connections.
	closed := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	addr := closed.URL
	closed.Close()

	p := mustProxy(t, Config{Services: map[string]string{"account": addr}})
	route := &router.Route{Path: "/a", Service: "account"}
	rec := httptest.NewRecorder()

	status, err := p.Serve(rec, httptest.NewRequest(http.MethodGet, "/a", nil), route)
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if status != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", status)
	}
	if got := decodeError(t, rec).Code; got != httpx.CodeBadGateway {
		t.Fatalf("error code = %q, want %q", got, httpx.CodeBadGateway)
	}
}

func TestServePassesThroughAnUpstreamClientError(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":{"code":"not_found","message":"upstream says no"}}`))
	}))
	defer upstream.Close()

	p := mustProxy(t, Config{Services: map[string]string{"account": upstream.URL}})
	route := &router.Route{Path: "/a", Service: "account"}
	rec := httptest.NewRecorder()

	status, err := p.Serve(rec, httptest.NewRequest(http.MethodGet, "/a", nil), route)
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if status != http.StatusNotFound {
		t.Fatalf("status = %d, want the upstream 404 to pass through", status)
	}
	if got := rec.Body.String(); got != `{"error":{"code":"not_found","message":"upstream says no"}}` {
		t.Fatalf("body = %q, want the upstream body untouched", got)
	}
}

func TestTransportFailureMapping(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		wantState int
		wantCode  string
	}{
		{"deadline", context.DeadlineExceeded, http.StatusGatewayTimeout, httpx.CodeTimeout},
		{"wrapped deadline", fmt.Errorf("do: %w", context.DeadlineExceeded), http.StatusGatewayTimeout, httpx.CodeTimeout},
		{"cancelled", context.Canceled, http.StatusServiceUnavailable, httpx.CodeServiceUnavail},
		{"unreachable", &net.OpError{Op: "dial", Err: errors.New("connection refused")}, http.StatusBadGateway, httpx.CodeBadGateway},
		{"other", errors.New("boom"), http.StatusBadGateway, httpx.CodeBadGateway},
		// An oversized upload reaches the proxy as a transport error because
		// the body is streamed rather than buffered. It is the caller's fault,
		// so it must not be reported as an upstream failure.
		{"body too large", &http.MaxBytesError{Limit: 16}, http.StatusRequestEntityTooLarge, httpx.CodePayloadTooLarge},
		{"wrapped body too large", fmt.Errorf("do: %w", &http.MaxBytesError{Limit: 16}), http.StatusRequestEntityTooLarge, httpx.CodePayloadTooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, code, message := transportFailure(tt.err, "account", 30*time.Second, time.Millisecond)
			if status != tt.wantState {
				t.Fatalf("status = %d, want %d", status, tt.wantState)
			}
			if code != tt.wantCode {
				t.Fatalf("code = %q, want %q", code, tt.wantCode)
			}
			if message == "" {
				t.Fatalf("message is empty")
			}
		})
	}
}

func TestTransportFailureNamesTheTimeoutItApplied(t *testing.T) {
	_, _, message := transportFailure(context.DeadlineExceeded, "account", 1500*time.Millisecond, time.Second)
	if !strings.Contains(message, "1.5s") {
		t.Fatalf("message = %q, want it to name the timeout that was applied", message)
	}
}

func TestErrorsCopyUnwraps(t *testing.T) {
	inner := errors.New("broken pipe")
	err := &errorsCopy{err: fmt.Errorf("copying: %w", inner)}
	if !errors.Is(err, inner) {
		t.Fatalf("errorsCopy does not unwrap to the underlying error")
	}
}

// --- pure helpers ---------------------------------------------------------

func TestSingleJoin(t *testing.T) {
	tests := []struct{ base, extra, want string }{
		{"", "/a", "/a"},
		{"/", "/a", "/a"},
		{"/api", "", "/api"},
		{"/api", "/a", "/api/a"},
		{"/api/", "/a", "/api/a"},
		{"/api", "a", "/api/a"},
		{"/api/", "/", "/api/"},
	}
	for _, tt := range tests {
		if got := singleJoin(tt.base, tt.extra); got != tt.want {
			t.Fatalf("singleJoin(%q, %q) = %q, want %q", tt.base, tt.extra, got, tt.want)
		}
	}
}

func TestSchemeOf(t *testing.T) {
	if got := schemeOf(httptest.NewRequest(http.MethodGet, "/a", nil)); got != "http" {
		t.Fatalf("schemeOf = %q, want http", got)
	}
}

func TestNewTransportIsBounded(t *testing.T) {
	transport := newTransport()
	if transport.MaxIdleConns != 100 {
		t.Fatalf("MaxIdleConns = %d, want 100", transport.MaxIdleConns)
	}
	if transport.MaxIdleConnsPerHost != 32 {
		t.Fatalf("MaxIdleConnsPerHost = %d, want 32", transport.MaxIdleConnsPerHost)
	}
	if transport.IdleConnTimeout != 90*time.Second {
		t.Fatalf("IdleConnTimeout = %s, want 90s", transport.IdleConnTimeout)
	}
}

func TestBuildRequestClearsRequestURIAndHost(t *testing.T) {
	p := mustProxy(t, Config{Services: map[string]string{"account": "http://127.0.0.1:1"}})
	upstream, err := url.Parse("http://127.0.0.1:1")
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/a", nil)
	outbound := p.buildRequest(context.Background(), req, upstream, &router.Route{Path: "/a", Service: "account"})

	// A client request carries a RequestURI that net/http rejects on the
	// outbound side; leaving it set makes every proxied call fail.
	if outbound.RequestURI != "" {
		t.Fatalf("RequestURI = %q, want it cleared", outbound.RequestURI)
	}
	if outbound.Host != "" {
		t.Fatalf("Host = %q, want it cleared so the URL's host is used", outbound.Host)
	}
	if outbound.Close {
		t.Fatalf("Close = true, want connection reuse")
	}
	if outbound.URL.Fragment != "" {
		t.Fatalf("Fragment = %q, want it cleared", outbound.URL.Fragment)
	}
}
