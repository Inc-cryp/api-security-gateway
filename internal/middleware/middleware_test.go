package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Inc-cryp/api-security-gateway/internal/auth"
	"github.com/Inc-cryp/api-security-gateway/internal/breaker"
	"github.com/Inc-cryp/api-security-gateway/internal/config"
	"github.com/Inc-cryp/api-security-gateway/internal/httpx"
	"github.com/Inc-cryp/api-security-gateway/internal/logging"
	"github.com/Inc-cryp/api-security-gateway/internal/proxy"
	"github.com/Inc-cryp/api-security-gateway/internal/router"
)

const goodKey = "good-key"

// harness wires a Gateway exactly the way cmd/gatewayd does, against a real
// upstream server, so the tests exercise the assembled chain rather than a
// hand-stubbed stage.
type harness struct {
	gateway  *Gateway
	upstream *httptest.Server
	hits     *int32
	lastPath *string
}

// newHarness builds a gateway routing "/account" (and the given extra routes)
// to a recording upstream.
func newHarness(t *testing.T, routes []config.Route, tweak func(*config.Config)) *harness {
	t.Helper()

	var hits int32
	var lastPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		lastPath = r.URL.Path
		w.Header().Set("X-Upstream", "reached")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(upstream.Close)

	cfg := DefaultTestConfig(upstream.URL)
	cfg.Routes = routes
	if tweak != nil {
		tweak(&cfg)
	}
	return newHarnessWithConfig(t, cfg, upstream, &hits, &lastPath)
}

// DefaultTestConfig is a valid configuration carrying one api_key credential,
// so a test only has to state the part it cares about.
func DefaultTestConfig(upstreamURL string) config.Config {
	cfg := config.Defaults()
	cfg.Upstreams = map[string]string{"account": upstreamURL}
	cfg.Security.APIKeys = []config.APIKey{{Key: goodKey, ClientID: "client-a"}}
	return cfg
}

func newHarnessWithConfig(t *testing.T, cfg config.Config, upstream *httptest.Server, hits *int32, lastPath *string) *harness {
	t.Helper()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("the test fixture is not a valid config: %v", err)
	}
	g, err := buildForTest(cfg)
	if err != nil {
		t.Fatalf("building the gateway: %v", err)
	}
	return &harness{gateway: g, upstream: upstream, hits: hits, lastPath: lastPath}
}

// buildForTest mirrors cmd/gatewayd's wiring with the same constructors, so a
// divergence between the two shows up here.
func buildForTest(cfg config.Config) (*Gateway, error) {
	routes, err := testRoutes(cfg)
	if err != nil {
		return nil, err
	}
	rt, err := router.New(routes)
	if err != nil {
		return nil, err
	}
	px, err := proxy.New(proxy.Config{
		Services:       cfg.Upstreams,
		DefaultTimeout: mustDuration(cfg.Upstream.Timeout),
		Breaker: breaker.NewRegistry(breaker.Config{
			FailureThreshold:  cfg.Upstream.CircuitBreaker.FailureThreshold,
			OpenTimeout:       mustDuration(cfg.Upstream.CircuitBreaker.OpenTimeout),
			HalfOpenSuccesses: cfg.Upstream.CircuitBreaker.HalfOpenSuccesses,
		}),
	})
	if err != nil {
		return nil, err
	}
	authenticator, err := testAuthenticator(cfg)
	if err != nil {
		return nil, err
	}
	resolver, err := httpx.NewClientIPResolver(cfg.Security.ClientIP.TrustedProxies, cfg.Security.ClientIP.ForwardedHeader)
	if err != nil {
		return nil, err
	}
	logger, err := logging.New(logging.Options{Level: cfg.Logging.Level})
	if err != nil {
		return nil, err
	}
	return New(Options{
		Config:        cfg,
		Router:        rt,
		Proxy:         px,
		Authenticator: authenticator,
		ClientIP:      resolver,
		Logger:        logger,
	})
}

func mustDuration(value string) time.Duration {
	if value == "" {
		return 0
	}
	d, err := config.ParseDuration(value)
	if err != nil {
		return 0
	}
	return d
}

func testRoutes(cfg config.Config) ([]*router.Route, error) {
	out := make([]*router.Route, 0, len(cfg.Routes))
	for _, route := range cfg.Routes {
		out = append(out, &router.Route{
			Path:           route.Path,
			Service:        route.Service,
			Authenticators: route.Authenticators,
			Methods:        route.Methods,
			StripPrefix:    route.StripPrefix,
			Timeout:        mustDuration(route.Timeout),
			RateLimit:      route.RateLimit,
			RateBurst:      route.RateBurst,
			AllowedIPs:     route.AllowedIPs,
			DeniedIPs:      route.DeniedIPs,
		})
	}
	return out, nil
}

// testAuthenticator mirrors cmd/gatewayd's newVerifiers: every scheme named in
// the config gains a verifier, so a route may name any of them.
func testAuthenticator(cfg config.Config) (*auth.Authenticator, error) {
	var verifiers []auth.Verifier
	if cfg.Security.JWT.Secret != "" {
		verifier, err := auth.NewJWTVerifier(auth.JWTConfig{
			Secret:    cfg.Security.JWT.Secret,
			Issuer:    cfg.Security.JWT.Issuer,
			Audience:  cfg.Security.JWT.Audience,
			ClockSkew: mustDuration(cfg.Security.JWT.ClockSkew),
		})
		if err != nil {
			return nil, err
		}
		verifiers = append(verifiers, verifier)
	}
	if len(cfg.Security.APIKeys) > 0 {
		keys := make([]auth.APIKeyConfig, 0, len(cfg.Security.APIKeys))
		for _, key := range cfg.Security.APIKeys {
			keys = append(keys, auth.APIKeyConfig{Key: key.Key, ClientID: key.ClientID})
		}
		verifier, err := auth.NewAPIKeyVerifier(keys)
		if err != nil {
			return nil, err
		}
		verifiers = append(verifiers, verifier)
	}
	if len(cfg.Security.HMAC.Clients) > 0 {
		clients := make([]auth.HMACClient, 0, len(cfg.Security.HMAC.Clients))
		for _, client := range cfg.Security.HMAC.Clients {
			clients = append(clients, auth.HMACClient{ClientID: client.ClientID, Secret: client.Secret})
		}
		verifier, err := auth.NewHMACVerifier(auth.HMACConfig{
			Clients:         clients,
			MaxSkew:         mustDuration(cfg.Security.HMAC.MaxSkew),
			ClientHeader:    cfg.Security.HMAC.ClientHeader,
			TimestampHeader: cfg.Security.HMAC.TimestampHeader,
			SignatureHeader: cfg.Security.HMAC.SignatureHeader,
		})
		if err != nil {
			return nil, err
		}
		verifiers = append(verifiers, verifier)
	}
	return auth.NewAuthenticator(verifiers...)
}

func (h *harness) do(t *testing.T, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.gateway.ServeHTTP(rec, req)
	return rec
}

// authedGET builds an authenticated GET for path from addr.
func (h *harness) authedGET(path, addr string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set(auth.APIKeyHeader, goodKey)
	req.RemoteAddr = addr
	return req
}

func errorCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var body httpx.ErrorBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not the JSON error envelope: %v (%q)", err, rec.Body.String())
	}
	return body.Error.Code
}

func apiKeyRoute() []config.Route {
	return []config.Route{{
		Path:           "/account",
		Service:        "account",
		Authenticators: []string{auth.SchemeAPIKey},
	}}
}

// --- New ------------------------------------------------------------------

func TestNewBuildsOneLimiterPerLimitedRoute(t *testing.T) {
	h := newHarness(t, []config.Route{
		{Path: "/account", Service: "account", RateLimit: 5, RateBurst: 2},
		{Path: "/transfer", Service: "account", RateLimit: 0, RateBurst: 9},
	}, nil)

	if _, ok := h.gateway.limiters["/account"]; !ok {
		t.Fatalf("no limiter was built for the route that sets rate_limit")
	}
	// A route without a limit must stay unlimited rather than silently
	// acquiring the burst it configured for something else.
	if _, ok := h.gateway.limiters["/transfer"]; ok {
		t.Fatalf("a limiter was built for a route with rate_limit unset")
	}
}

func TestNewRejectsAnInvalidRateLimit(t *testing.T) {
	// config.Validate rejects this pair, so a configuration loaded from disk
	// can never reach New carrying it. A caller that assembles routes in Go
	// can, and the limiter constructor is then the last line of defence: it
	// must refuse rather than hand back a limiter with a zero burst, which
	// would reject every request forever.
	rt, err := router.New([]*router.Route{{
		Path:      "/account",
		Service:   "account",
		RateLimit: 1,
		RateBurst: 0,
	}})
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}
	px, err := proxy.New(proxy.Config{Services: map[string]string{"account": "http://127.0.0.1:1"}})
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	logger, err := logging.New(logging.Options{})
	if err != nil {
		t.Fatalf("logging.New: %v", err)
	}

	if _, err := New(Options{Config: DefaultTestConfig("http://127.0.0.1:1"), Router: rt, Proxy: px, Logger: logger}); err == nil {
		t.Fatalf("New accepted a route whose rate limit has no burst")
	}
}

func mustRoutes(t *testing.T, cfg config.Config) []*router.Route {
	t.Helper()
	routes, err := testRoutes(cfg)
	if err != nil {
		t.Fatalf("testRoutes: %v", err)
	}
	return routes
}

func TestServicesDelegatesToTheProxy(t *testing.T) {
	h := newHarness(t, apiKeyRoute(), nil)
	got := h.gateway.Services()
	if len(got) != 1 || got[0] != "account" {
		t.Fatalf("Services() = %v, want [account]", got)
	}
}

// --- happy path -----------------------------------------------------------

func TestServeForwardsAnAuthenticatedRequest(t *testing.T) {
	h := newHarness(t, apiKeyRoute(), nil)

	rec := h.do(t, h.authedGET("/account/42", "203.0.113.7:5000"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != `{"ok":true}` {
		t.Fatalf("body = %q, want the upstream body", rec.Body.String())
	}
	if rec.Header().Get("X-Upstream") != "reached" {
		t.Fatalf("the upstream response headers did not reach the client")
	}
	if n := atomic.LoadInt32(h.hits); n != 1 {
		t.Fatalf("the upstream was called %d times, want 1", n)
	}
}

func TestServeEchoesAnInboundRequestID(t *testing.T) {
	h := newHarness(t, apiKeyRoute(), nil)

	req := h.authedGET("/account", "203.0.113.7:5000")
	req.Header.Set(httpx.RequestIDHeader, "caller-supplied-id")
	rec := h.do(t, req)

	if got := rec.Header().Get(httpx.RequestIDHeader); got != "caller-supplied-id" {
		t.Fatalf("%s = %q, want the inbound id to be continued", httpx.RequestIDHeader, got)
	}
}

func TestServeMintsAUniqueRequestIDWhenNoneIsSupplied(t *testing.T) {
	h := newHarness(t, apiKeyRoute(), nil)

	first := h.do(t, h.authedGET("/account", "203.0.113.7:5000")).Header().Get(httpx.RequestIDHeader)
	second := h.do(t, h.authedGET("/account", "203.0.113.7:5000")).Header().Get(httpx.RequestIDHeader)

	if len(first) != 32 || len(second) != 32 {
		t.Fatalf("minted ids = %q, %q; want 32-char hex ids", first, second)
	}
	if first == second {
		t.Fatalf("both requests got the same id %q; ids must be unique per request", first)
	}
}

func TestRequestIDReplacesAnOversizedInboundValue(t *testing.T) {
	h := newHarness(t, apiKeyRoute(), nil)

	oversized := strings.Repeat("a", 129)
	req := h.authedGET("/account", "203.0.113.7:5000")
	req.Header.Set(httpx.RequestIDHeader, oversized)
	got := h.do(t, req).Header().Get(httpx.RequestIDHeader)

	if got == oversized {
		t.Fatalf("an oversized inbound request id was echoed back verbatim")
	}
	if len(got) != 32 {
		t.Fatalf("replacement request id = %q, want a freshly minted 32-char id", got)
	}
}

func TestSanitizeHeaderValueStripsControlCharacters(t *testing.T) {
	// A CRLF in a reflected header splits the response into two, which is how
	// a header echo turns into response splitting.
	got := sanitizeHeaderValue("abc\r\nX-Injected: yes\x00\x7fdef")
	if strings.ContainsAny(got, "\r\n") {
		t.Fatalf("sanitizeHeaderValue kept a line break: %q", got)
	}
	if got != "abcX-Injected: yesdef" {
		t.Fatalf("sanitizeHeaderValue = %q, want abcX-Injected: yesdef", got)
	}
}

// --- routing --------------------------------------------------------------

func TestServeReturns404WithoutTouchingTheUpstream(t *testing.T) {
	h := newHarness(t, apiKeyRoute(), nil)

	rec := h.do(t, h.authedGET("/nowhere", "203.0.113.7:5000"))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	if got := errorCode(t, rec); got != httpx.CodeNotFound {
		t.Fatalf("error code = %q, want %q", got, httpx.CodeNotFound)
	}
	if n := atomic.LoadInt32(h.hits); n != 0 {
		t.Fatalf("the upstream was called %d times for an unrouted path", n)
	}
}

func TestServeReturns405WithAnAllowHeader(t *testing.T) {
	h := newHarness(t, []config.Route{{
		Path:           "/account",
		Service:        "account",
		Authenticators: []string{auth.SchemeAPIKey},
		Methods:        []string{"GET", "POST"},
	}}, nil)

	req := h.authedGET("/account/7", "203.0.113.7:5000")
	req.Method = http.MethodDelete
	rec := h.do(t, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
	if got := errorCode(t, rec); got != httpx.CodeMethodNotAllowed {
		t.Fatalf("error code = %q, want %q", got, httpx.CodeMethodNotAllowed)
	}
	allow := rec.Header().Get("Allow")
	if !strings.Contains(allow, "GET") || !strings.Contains(allow, "POST") {
		t.Fatalf("Allow = %q, want it to name GET and POST", allow)
	}
	if n := atomic.LoadInt32(h.hits); n != 0 {
		t.Fatalf("the upstream was called %d times for a rejected method", n)
	}
}

func TestServeRejectsAMethodBeforeAuthenticating(t *testing.T) {
	// A 405 is a routing fact, not a permission, so it must not depend on the
	// caller presenting a credential; otherwise an anonymous prober learns
	// which methods exist only after authenticating.
	h := newHarness(t, []config.Route{{
		Path:           "/account",
		Service:        "account",
		Authenticators: []string{auth.SchemeAPIKey},
		Methods:        []string{"GET"},
	}}, nil)

	rec := h.do(t, httptest.NewRequest(http.MethodPost, "/account", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405 rather than 401", rec.Code)
	}
}

func TestServeDoesNotMatchARouteOnAStringPrefixAlone(t *testing.T) {
	h := newHarness(t, apiKeyRoute(), nil)

	rec := h.do(t, h.authedGET("/accounting", "203.0.113.7:5000"))

	// "/accounting" shares a string prefix with "/account" but not a path
	// segment boundary; matching it would put an unrelated system behind the
	// account route's security policy.
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404: /accounting is not under /account", rec.Code)
	}
	if n := atomic.LoadInt32(h.hits); n != 0 {
		t.Fatalf("the upstream was called %d times for /accounting", n)
	}
}

func TestServeStripsTheRoutePrefixWhenAsked(t *testing.T) {
	h := newHarness(t, []config.Route{{
		Path:           "/api/account",
		Service:        "account",
		Authenticators: []string{auth.SchemeAPIKey},
		StripPrefix:    true,
	}}, nil)

	rec := h.do(t, h.authedGET("/api/account/99", "203.0.113.7:5000"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if *h.lastPath != "/99" {
		t.Fatalf("upstream saw %q, want /99", *h.lastPath)
	}
}

func TestRouteFromContextRoundTrips(t *testing.T) {
	if got := routeFromContext(withRoute(t.Context(), nil)); got != nil {
		t.Fatalf("routeFromContext = %v, want nil for a stored nil route", got)
	}
	route := &router.Route{Path: "/x"}
	if got := routeFromContext(withRoute(t.Context(), route)); got != route {
		t.Fatalf("routeFromContext did not return the stored route")
	}
	if got := routeFromContext(t.Context()); got != nil {
		t.Fatalf("routeFromContext = %v on a bare context, want nil", got)
	}
}

func TestAllowHeader(t *testing.T) {
	if got := allowHeader(&router.Route{}); got != "" {
		t.Fatalf("allowHeader = %q for an unrestricted route, want empty", got)
	}
	if got := allowHeader(&router.Route{Methods: []string{"GET", "POST"}}); got != "GET, POST" {
		t.Fatalf("allowHeader = %q, want \"GET, POST\"", got)
	}
}

// --- authentication -------------------------------------------------------

func TestServeRejectsAMissingCredential(t *testing.T) {
	h := newHarness(t, apiKeyRoute(), nil)

	rec := h.do(t, httptest.NewRequest(http.MethodGet, "/account", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if got := errorCode(t, rec); got != httpx.CodeUnauthorized {
		t.Fatalf("error code = %q, want %q", got, httpx.CodeUnauthorized)
	}
	if n := atomic.LoadInt32(h.hits); n != 0 {
		t.Fatalf("the upstream was called %d times without a credential", n)
	}
}

func TestServeDoesNotEchoWhyTheCredentialFailed(t *testing.T) {
	h := newHarness(t, apiKeyRoute(), nil)

	req := httptest.NewRequest(http.MethodGet, "/account", nil)
	req.Header.Set(auth.APIKeyHeader, "wrong-key")
	rec := h.do(t, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	// Echoing the reason turns the gateway into an oracle for guessing keys.
	if body := rec.Body.String(); strings.Contains(body, "wrong-key") {
		t.Fatalf("the rejection body echoes the presented key: %q", body)
	}
}

func TestServeAllowsAnyOfTheRouteSchemes(t *testing.T) {
	// The route accepts either scheme; only one credential is presented, so a
	// 200 here proves the authenticator tries each accepted scheme rather than
	// requiring the first one to succeed.
	h := newHarness(t, []config.Route{{
		Path:           "/account",
		Service:        "account",
		Authenticators: []string{auth.SchemeJWT, auth.SchemeAPIKey},
	}}, func(cfg *config.Config) {
		cfg.Security.JWT.Secret = "a-test-secret-that-is-long-enough"
	})

	rec := h.do(t, h.authedGET("/account", "203.0.113.7:5000"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: api_key is one of the accepted schemes (%s)", rec.Code, rec.Body.String())
	}
}

func TestRouteNamingAnUnconfiguredSchemeRejectsEverything(t *testing.T) {
	// A route that names a scheme the gateway has no verifier for can never
	// authenticate anyone. The request must be rejected rather than falling
	// through to the schemes that are configured: an unconfigured scheme in
	// the list is an operator error, and treating it as absent would silently
	// widen the route's accepted credentials.
	h := newHarness(t, []config.Route{{
		Path:           "/account",
		Service:        "account",
		Authenticators: []string{auth.SchemeJWT},
	}}, nil)

	rec := h.do(t, h.authedGET("/account", "203.0.113.7:5000"))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if n := atomic.LoadInt32(h.hits); n != 0 {
		t.Fatalf("the upstream was called %d times, want 0", n)
	}
}

// --- client IP trust ------------------------------------------------------

func TestUntrustedPeerCannotSpoofItsAddress(t *testing.T) {
	// The spoofed header claims a privileged address. The socket peer is not a
	// configured trusted proxy, so the header must be ignored and the real
	// peer address is what the IP filter sees.
	h := newHarness(t, []config.Route{{
		Path:           "/account",
		Service:        "account",
		Authenticators: []string{auth.SchemeAPIKey},
		AllowedIPs:     []string{"10.0.0.0/8"},
	}}, nil)

	req := h.authedGET("/account", "203.0.113.7:5000")
	req.Header.Set("X-Forwarded-For", "10.0.0.5")
	rec := h.do(t, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403: X-Forwarded-For from an untrusted peer must be ignored", rec.Code)
	}
}

func TestTrustedProxyAddressIsHonoured(t *testing.T) {
	h := newHarness(t, []config.Route{{
		Path:           "/account",
		Service:        "account",
		Authenticators: []string{auth.SchemeAPIKey},
		AllowedIPs:     []string{"10.0.0.0/8"},
	}}, func(cfg *config.Config) {
		cfg.Security.ClientIP.ForwardedHeader = "X-Forwarded-For"
		cfg.Security.ClientIP.TrustedProxies = []string{"127.0.0.0/8"}
	})

	req := h.authedGET("/account", "127.0.0.1:5000")
	req.Header.Set("X-Forwarded-For", "10.0.0.5")
	rec := h.do(t, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: the forwarded address is trusted here", rec.Code)
	}
}

func TestForwardedChainIsReadRightToLeft(t *testing.T) {
	// A caller behind a trusted proxy can prepend whatever it likes to
	// X-Forwarded-For. Reading the list left-to-right would honour that
	// claim; the resolved client must be the rightmost untrusted hop. Both
	// cases below use a header whose leftmost entry and rightmost untrusted
	// entry are different addresses, and only one of the two is denied, so
	// each assertion fails if the list is read from the wrong end.
	withDenied := func(denied string) *harness {
		return newHarness(t, []config.Route{{
			Path:           "/account",
			Service:        "account",
			Authenticators: []string{auth.SchemeAPIKey},
			DeniedIPs:      []string{denied},
		}}, func(cfg *config.Config) {
			cfg.Security.ClientIP.ForwardedHeader = "X-Forwarded-For"
			cfg.Security.ClientIP.TrustedProxies = []string{"127.0.0.0/8"}
		})
	}
	spoofedHeader := func(h *harness) *http.Request {
		req := h.authedGET("/account", "127.0.0.1:5000")
		req.Header.Set("X-Forwarded-For", "10.0.0.5, 198.51.100.4")
		return req
	}

	// The rightmost untrusted hop is the denied one. Left-to-right reading
	// would have picked the spoofed 10.0.0.5 and let the request through.
	h := withDenied("198.51.100.4/32")
	if rec := h.do(t, spoofedHeader(h)); rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403: the client is the rightmost untrusted hop (198.51.100.4)", rec.Code)
	}

	// The mirror image: the denied address is the leftmost, spoofable entry.
	// Right-to-left reading resolves the untrusted 198.51.100.4 and allows the
	// request; a left-to-right reading would resolve 10.0.0.5 and deny it.
	h = withDenied("10.0.0.5/32")
	if rec := h.do(t, spoofedHeader(h)); rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: the prepended address must not be honoured", rec.Code)
	}
}

func TestDeniedIPIsRejectedEvenWhenAllowed(t *testing.T) {
	h := newHarness(t, []config.Route{{
		Path:           "/account",
		Service:        "account",
		Authenticators: []string{auth.SchemeAPIKey},
		AllowedIPs:     []string{"10.0.0.0/8"},
		DeniedIPs:      []string{"10.0.0.7/32"},
	}}, nil)

	rec := h.do(t, h.authedGET("/account", "10.0.0.7:5000"))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403: deny must win over allow", rec.Code)
	}
	if got := errorCode(t, rec); got != httpx.CodeForbidden {
		t.Fatalf("error code = %q, want %q", got, httpx.CodeForbidden)
	}
	if n := atomic.LoadInt32(h.hits); n != 0 {
		t.Fatalf("the upstream was called %d times for a filtered address", n)
	}
}

// --- rate limiting --------------------------------------------------------

func TestRateLimitRejectsWith429AndRetryAfter(t *testing.T) {
	h := newHarness(t, []config.Route{{
		Path:           "/account",
		Service:        "account",
		Authenticators: []string{auth.SchemeAPIKey},
		RateLimit:      0.5,
		RateBurst:      2,
	}}, nil)

	for i := range 2 {
		rec := h.do(t, h.authedGET("/account", "203.0.113.7:5000"))
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d within the burst got %d, want 200", i+1, rec.Code)
		}
	}
	rec := h.do(t, h.authedGET("/account", "203.0.113.7:5000"))

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429 once the burst is spent", rec.Code)
	}
	if got := errorCode(t, rec); got != httpx.CodeRateLimited {
		t.Fatalf("error code = %q, want %q", got, httpx.CodeRateLimited)
	}
	retry := rec.Header().Get("Retry-After")
	if retry == "" {
		t.Fatalf("Retry-After was not set on a 429")
	}
	if retry == "0" {
		t.Fatalf("Retry-After = 0, want at least one second so a naive client does not hot-loop")
	}
	if got := rec.Header().Get("X-RateLimit-Limit"); got != "2" {
		t.Fatalf("X-RateLimit-Limit = %q, want the burst size 2", got)
	}
}

func TestRateLimitIsKeyedPerClient(t *testing.T) {
	h := newHarness(t, []config.Route{{
		Path:           "/account",
		Service:        "account",
		Authenticators: []string{auth.SchemeAPIKey},
		RateLimit:      0.001,
		RateBurst:      1,
	}}, nil)

	if rec := h.do(t, h.authedGET("/account", "203.0.113.7:5000")); rec.Code != http.StatusOK {
		t.Fatalf("first client got %d, want 200", rec.Code)
	}
	if rec := h.do(t, h.authedGET("/account", "203.0.113.7:5000")); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("the same client got %d on its second call, want 429", rec.Code)
	}
	// A shared bucket would let one noisy caller lock every other client out.
	if rec := h.do(t, h.authedGET("/account", "198.51.100.9:5000")); rec.Code != http.StatusOK {
		t.Fatalf("a different client got %d, want 200: the bucket must be per client", rec.Code)
	}
}

func TestRateLimitIsCheckedBeforeAuthentication(t *testing.T) {
	h := newHarness(t, []config.Route{{
		Path:           "/account",
		Service:        "account",
		Authenticators: []string{auth.SchemeAPIKey},
		RateLimit:      0.001,
		RateBurst:      1,
	}}, nil)

	// Spend the burst with a good credential so the bucket is genuinely empty.
	if rec := h.do(t, h.authedGET("/account", "203.0.113.7:5000")); rec.Code != http.StatusOK {
		t.Fatalf("the first request got %d, want 200", rec.Code)
	}

	// A request carrying an invalid credential must now be turned away by the
	// limiter — a map lookup — rather than by the authenticator, which would
	// spend a credential verification on a caller that is already being
	// throttled. A 401 here would mean auth runs first.
	req := httptest.NewRequest(http.MethodGet, "/account", nil)
	req.Header.Set(auth.APIKeyHeader, "wrong-key")
	req.RemoteAddr = "203.0.113.7:5000"
	rec := h.do(t, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429: the limiter must run before authentication", rec.Code)
	}
	if n := atomic.LoadInt32(h.hits); n != 1 {
		t.Fatalf("the upstream was called %d times, want only the first request", n)
	}
}

// --- body limit -----------------------------------------------------------

func TestBodyLimitIsEnforced(t *testing.T) {
	h := newHarness(t, apiKeyRoute(), func(cfg *config.Config) {
		cfg.Server.MaxBodyBytes = 16
	})

	// The body is streamed to the upstream rather than buffered, so the cap is
	// enforced while proxying and the failure arrives as a transport error.
	// It must still be reported as the caller's fault: 413 payload too large,
	// not a 502 that blames the upstream for a request it never finished
	// receiving.
	req := httptest.NewRequest(http.MethodPost, "/account", strings.NewReader(strings.Repeat("x", 4096)))
	req.Header.Set(auth.APIKeyHeader, goodKey)
	req.ContentLength = 4096
	rec := h.do(t, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413 for a body over the cap (%s)", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); !strings.Contains(body, httpx.CodePayloadTooLarge) {
		t.Fatalf("body = %q, want the %s code", body, httpx.CodePayloadTooLarge)
	}
}

func TestBodyLimitAllowsAPayloadWithinTheCap(t *testing.T) {
	h := newHarness(t, apiKeyRoute(), func(cfg *config.Config) {
		cfg.Server.MaxBodyBytes = 1024
	})

	req := httptest.NewRequest(http.MethodPost, "/account", strings.NewReader(`{"amount":5}`))
	req.Header.Set(auth.APIKeyHeader, goodKey)
	rec := h.do(t, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for a body under the cap (%s)", rec.Code, rec.Body.String())
	}
}

// --- upstream failures ----------------------------------------------------

func TestUpstreamTimeoutBecomes504(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer upstream.Close()

	h := newHarness(t, []config.Route{{
		Path:           "/account",
		Service:        "account",
		Authenticators: []string{auth.SchemeAPIKey},
		Timeout:        "50ms",
	}}, func(cfg *config.Config) {
		cfg.Upstreams = map[string]string{"account": upstream.URL}
	})

	rec := h.do(t, h.authedGET("/account", "203.0.113.7:5000"))

	if rec.Code != http.StatusGatewayTimeout {
		t.Fatalf("status = %d, want 504", rec.Code)
	}
	if got := errorCode(t, rec); got != httpx.CodeTimeout {
		t.Fatalf("error code = %q, want %q", got, httpx.CodeTimeout)
	}
}

func TestUnreachableUpstreamBecomesBadGateway(t *testing.T) {
	closed := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	upstreamURL := closed.URL
	closed.Close()

	h := newHarness(t, apiKeyRoute(), func(cfg *config.Config) {
		cfg.Upstreams = map[string]string{"account": upstreamURL}
	})

	rec := h.do(t, h.authedGET("/account", "203.0.113.7:5000"))

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}
	if got := errorCode(t, rec); got != httpx.CodeBadGateway {
		t.Fatalf("error code = %q, want %q", got, httpx.CodeBadGateway)
	}
}

// --- response headers -----------------------------------------------------

func TestCustomResponseHeadersAreApplied(t *testing.T) {
	h := newHarness(t, apiKeyRoute(), func(cfg *config.Config) {
		cfg.Headers = map[string]string{"X-Frame-Options": "DENY"}
	})

	rec := h.do(t, h.authedGET("/account", "203.0.113.7:5000"))

	if got := rec.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Fatalf("X-Frame-Options = %q, want DENY on a successful response", got)
	}
}

func TestCustomResponseHeadersAreSetOnRejectionsToo(t *testing.T) {
	h := newHarness(t, apiKeyRoute(), func(cfg *config.Config) {
		cfg.Headers = map[string]string{"X-Frame-Options": "DENY"}
	})

	rec := h.do(t, httptest.NewRequest(http.MethodGet, "/account", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	// A rejection is still a browser-visible response, so the operator's
	// hardening headers must not depend on the request succeeding.
	if got := rec.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Fatalf("X-Frame-Options = %q, want it applied to error responses as well", got)
	}
}

// --- logging integration --------------------------------------------------

// capturedLog collects the JSON lines the access logger wrote.
type capturedLog struct {
	lines []string
}

func (c *capturedLog) Write(p []byte) (int, error) {
	c.lines = append(c.lines, string(p))
	return len(p), nil
}

func TestAccessLogRecordsTheResolvedRequestFacts(t *testing.T) {
	// Every stage below accessLog passes a derived request down the chain, so
	// the request id, the matched route and the principal are only visible to
	// the log if the stages hand them back out of band. A log line with an
	// empty request_id or route is unusable for correlating an incident.
	h := newHarness(t, []config.Route{{
		Path:           "/account",
		Service:        "account",
		Authenticators: []string{auth.SchemeAPIKey},
	}}, nil)

	var captured capturedLog
	logger, err := logging.NewWriter(&captured, logging.Options{Level: "info", RedactQuery: true})
	if err != nil {
		t.Fatalf("logging.NewWriter: %v", err)
	}
	h.gateway.logger = logger

	req := h.authedGET("/account/1?token=leak-me", "203.0.113.7:5000")
	req.Header.Set(httpx.RequestIDHeader, "trace-42")
	rec := h.do(t, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if len(captured.lines) == 0 {
		t.Fatalf("the access log wrote nothing")
	}

	var line map[string]any
	if err := json.Unmarshal([]byte(captured.lines[0]), &line); err != nil {
		t.Fatalf("the access log line is not valid JSON: %v (%q)", err, captured.lines[0])
	}
	for field, want := range map[string]any{
		"request_id": "trace-42",
		"method":     "GET",
		"path":       "/account/1",
		"client_ip":  "203.0.113.7",
		"principal":  "api_key:client-a",
		"route":      "/account",
		"service":    "account",
		"status":     float64(http.StatusOK),
	} {
		if got := line[field]; got != want {
			t.Fatalf("logged %s = %v, want %v (line: %s)", field, got, want, captured.lines[0])
		}
	}
	// The credential in the query string must not survive into the log.
	if got := line["query"]; got != "[redacted]" {
		t.Fatalf("logged query = %v, want it redacted", got)
	}
	if strings.Contains(captured.lines[0], "leak-me") {
		t.Fatalf("the query string was logged verbatim: %s", captured.lines[0])
	}
}

func TestAccessLogResolvesTheClientBehindATrustedProxy(t *testing.T) {
	// The log is an audit trail, so it must name the caller rather than the
	// proxy that forwarded it.
	h := newHarness(t, []config.Route{{
		Path:           "/account",
		Service:        "account",
		Authenticators: []string{auth.SchemeAPIKey},
	}}, func(cfg *config.Config) {
		cfg.Security.ClientIP.ForwardedHeader = "X-Forwarded-For"
		cfg.Security.ClientIP.TrustedProxies = []string{"127.0.0.0/8"}
	})

	var captured capturedLog
	logger, err := logging.NewWriter(&captured, logging.Options{Level: "info"})
	if err != nil {
		t.Fatalf("logging.NewWriter: %v", err)
	}
	h.gateway.logger = logger

	req := h.authedGET("/account", "127.0.0.1:5000")
	req.Header.Set("X-Forwarded-For", "198.51.100.4")
	if rec := h.do(t, req); rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var line map[string]any
	if err := json.Unmarshal([]byte(captured.lines[0]), &line); err != nil {
		t.Fatalf("the access log line is not valid JSON: %v (%q)", err, captured.lines[0])
	}
	if got := line["client_ip"]; got != "198.51.100.4" {
		t.Fatalf("logged client_ip = %v, want the forwarded client, not the proxy peer", got)
	}
}
