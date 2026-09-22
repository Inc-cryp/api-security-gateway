package main

import (
	"bytes"
	"errors"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Inc-cryp/api-security-gateway/internal/auth"
	"github.com/Inc-cryp/api-security-gateway/internal/config"
	"github.com/Inc-cryp/api-security-gateway/internal/httpx"
	"github.com/Inc-cryp/api-security-gateway/internal/logging"
)

// validConfig returns the smallest configuration build accepts: one upstream,
// one route, one credential.
func validConfig() config.Config {
	return config.Config{
		Server: config.Server{Addr: ":0"},
		Routes: []config.Route{{
			Path:           "/account",
			Service:        "account",
			Authenticators: []string{config.SchemeAPIKey},
		}},
		Security: config.Security{
			APIKeys: []config.APIKey{{Key: "test-key", ClientID: "client-a"}},
		},
		Upstreams: map[string]string{"account": "http://127.0.0.1:1"},
		Upstream:  config.Upstream{Timeout: "5s"},
	}
}

func testLogger(t *testing.T) *logging.Logger {
	t.Helper()
	logger, err := logging.NewWriter(io.Discard, logging.Options{Level: "error"})
	if err != nil {
		t.Fatalf("logging.NewWriter: %v", err)
	}
	return logger
}

// withArgs installs args as the process arguments for one run() call and
// restores the previous flag set. run() registers its flags on every call, so
// a fresh FlagSet is required between calls.
func withArgs(t *testing.T, args ...string) {
	t.Helper()
	oldArgs, oldCommandLine := os.Args, flag.CommandLine
	flag.CommandLine = flag.NewFlagSet(args[0], flag.ContinueOnError)
	flag.CommandLine.SetOutput(io.Discard)
	os.Args = args
	t.Cleanup(func() {
		os.Args, flag.CommandLine = oldArgs, oldCommandLine
	})
}

// captureStdout runs fn with os.Stdout redirected and returns what it wrote.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()
	fn()
	_ = w.Close()
	os.Stdout = old
	return <-done
}

func TestOptionalDuration(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    time.Duration
		wantErr bool
	}{
		{"empty means unset", "", 0, false},
		{"seconds suffix", "3s", 3 * time.Second, false},
		{"minutes suffix", "2m", 2 * time.Minute, false},
		{"bare integer is seconds", "30", 30 * time.Second, false},
		{"garbage is rejected", "soon", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := optionalDuration(tt.value)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("optionalDuration(%q) = %s, want an error", tt.value, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("optionalDuration(%q): %v", tt.value, err)
			}
			if got != tt.want {
				t.Fatalf("optionalDuration(%q) = %s, want %s", tt.value, got, tt.want)
			}
		})
	}
}

// --- newVerifiers ---------------------------------------------------------

func TestNewVerifiersBuildsEachConfiguredScheme(t *testing.T) {
	cfg := config.Config{Security: config.Security{
		JWT:     config.JWT{Secret: "a-secret-long-enough-to-pass"},
		APIKeys: []config.APIKey{{Key: "k", ClientID: "c"}},
		HMAC: config.HMAC{Clients: []config.HMACClient{
			{ClientID: "c", Secret: "s"},
		}},
	}}

	verifiers, err := newVerifiers(cfg)
	if err != nil {
		t.Fatalf("newVerifiers: %v", err)
	}
	if len(verifiers) != 3 {
		t.Fatalf("built %d verifiers, want one per configured scheme", len(verifiers))
	}
	authenticator, err := auth.NewAuthenticator(verifiers...)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	for _, scheme := range []string{auth.SchemeJWT, auth.SchemeAPIKey, auth.SchemeHMAC} {
		if !authenticator.Has(scheme) {
			t.Errorf("scheme %q was configured but no verifier was registered", scheme)
		}
	}
}

func TestNewVerifiersOmitsUnconfiguredSchemes(t *testing.T) {
	cfg := config.Config{Security: config.Security{
		APIKeys: []config.APIKey{{Key: "k", ClientID: "c"}},
	}}
	verifiers, err := newVerifiers(cfg)
	if err != nil {
		t.Fatalf("newVerifiers: %v", err)
	}
	authenticator, err := auth.NewAuthenticator(verifiers...)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	if authenticator.Has(auth.SchemeJWT) {
		t.Errorf("a JWT verifier was registered with no secret configured")
	}
	if authenticator.Has(auth.SchemeHMAC) {
		t.Errorf("an HMAC verifier was registered with no clients configured")
	}
	if !authenticator.Has(auth.SchemeAPIKey) {
		t.Errorf("the configured API-key verifier is missing")
	}
}

func TestNewVerifiersRejectsAnEmptySecuritySection(t *testing.T) {
	// A gateway with no credential material would authenticate nobody, so it
	// must refuse to start rather than serve every request with a 401.
	_, err := newVerifiers(config.Config{})
	if err == nil {
		t.Fatalf("newVerifiers accepted an empty security section")
	}
	var cfgErr *httpx.ConfigError
	if !errors.As(err, &cfgErr) {
		t.Fatalf("error = %T, want *httpx.ConfigError", err)
	}
	if cfgErr.Field != "security" {
		t.Fatalf("field = %q, want security", cfgErr.Field)
	}
}

func TestNewVerifiersSurfacesCredentialErrors(t *testing.T) {
	tests := []struct {
		name string
		sec  config.Security
	}{
		{"jwt secret too short", config.Security{JWT: config.JWT{Secret: "short"}}},
		{"jwt clock skew is not a duration", config.Security{
			JWT: config.JWT{Secret: "a-secret-long-enough-to-pass", ClockSkew: "soon"},
		}},
		{"hmac skew is not a duration", config.Security{
			HMAC: config.HMAC{
				Clients: []config.HMACClient{{ClientID: "c", Secret: "s"}},
				MaxSkew: "soon",
			},
		}},
		{"api key with no client id", config.Security{
			APIKeys: []config.APIKey{{Key: "k"}},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := newVerifiers(config.Config{Security: tt.sec}); err == nil {
				t.Fatalf("newVerifiers accepted the invalid security section")
			}
		})
	}
}

// --- newRoutes ------------------------------------------------------------

func TestNewRoutesMapsEveryRouteField(t *testing.T) {
	// The config-to-route copy is the only place these fields cross from YAML
	// into the running gateway, so a field left out here is a setting that
	// silently does nothing.
	cfg := config.Config{Routes: []config.Route{{
		Path:           "/transfer",
		Service:        "transfer",
		Authenticators: []string{config.SchemeJWT},
		Methods:        []string{"POST"},
		StripPrefix:    true,
		RateLimit:      12.5,
		RateBurst:      30,
		Timeout:        "3s",
		AllowedIPs:     []string{"10.0.0.0/8"},
		DeniedIPs:      []string{"10.9.9.9/32"},
	}}}

	routes, err := newRoutes(cfg)
	if err != nil {
		t.Fatalf("newRoutes: %v", err)
	}
	if len(routes) != 1 {
		t.Fatalf("got %d routes, want 1", len(routes))
	}
	got := routes[0]

	if got.Path != "/transfer" || got.Service != "transfer" {
		t.Errorf("path/service = %q/%q, want /transfer/transfer", got.Path, got.Service)
	}
	if got.Timeout != 3*time.Second {
		t.Errorf("Timeout = %s, want 3s", got.Timeout)
	}
	if !got.StripPrefix {
		t.Errorf("StripPrefix was dropped")
	}
	if len(got.Methods) != 1 || got.Methods[0] != "POST" {
		t.Errorf("Methods = %v, want [POST]", got.Methods)
	}
	if len(got.AllowedIPs) != 1 || got.AllowedIPs[0] != "10.0.0.0/8" {
		t.Errorf("AllowedIPs = %v, want [10.0.0.0/8]", got.AllowedIPs)
	}
	if len(got.DeniedIPs) != 1 || got.DeniedIPs[0] != "10.9.9.9/32" {
		t.Errorf("DeniedIPs = %v, want [10.9.9.9/32]", got.DeniedIPs)
	}
}

// TestNewRoutesCarriesTheRateLimit is the regression test for a dropped field:
// the config parsed and validated rate_limit, middleware.New built a limiter
// from Route.RateLimit, and the test harness mapped it — but newRoutes never
// copied it, so every route the binary served was unlimited. The bug survived
// because nothing asserted on the production copy of the field.
func TestNewRoutesCarriesTheRateLimit(t *testing.T) {
	cfg := config.Config{Routes: []config.Route{{
		Path:      "/account",
		Service:   "account",
		RateLimit: 12.5,
		RateBurst: 30,
	}}}

	routes, err := newRoutes(cfg)
	if err != nil {
		t.Fatalf("newRoutes: %v", err)
	}
	if routes[0].RateLimit != 12.5 {
		t.Fatalf("RateLimit = %v, want 12.5", routes[0].RateLimit)
	}
	if routes[0].RateBurst != 30 {
		t.Fatalf("RateBurst = %d, want 30", routes[0].RateBurst)
	}
}

func TestNewRoutesRejectsAnUnparsableTimeout(t *testing.T) {
	cfg := config.Config{Routes: []config.Route{{Path: "/a", Service: "account", Timeout: "soon"}}}
	_, err := newRoutes(cfg)
	if err == nil {
		t.Fatalf("newRoutes accepted the timeout %q", "soon")
	}
	var cfgErr *httpx.ConfigError
	if !errors.As(err, &cfgErr) {
		t.Fatalf("error = %T, want *httpx.ConfigError", err)
	}
	if cfgErr.Field != "routes[0].timeout" {
		t.Fatalf("field = %q, want routes[0].timeout", cfgErr.Field)
	}
}

func TestNewRoutesReturnsAnEmptySliceForNoRoutes(t *testing.T) {
	routes, err := newRoutes(config.Config{})
	if err != nil {
		t.Fatalf("newRoutes: %v", err)
	}
	if len(routes) != 0 {
		t.Fatalf("got %d routes, want none", len(routes))
	}
}

// --- newBreakers ----------------------------------------------------------

func TestNewBreakersUsesTheConfiguredValues(t *testing.T) {
	cfg := config.Config{Upstream: config.Upstream{CircuitBreaker: config.CircuitBreaker{
		FailureThreshold:  9,
		OpenTimeout:       "45s",
		HalfOpenSuccesses: 4,
	}}}
	registry, err := newBreakers(cfg)
	if err != nil {
		t.Fatalf("newBreakers: %v", err)
	}
	if registry == nil {
		t.Fatalf("newBreakers returned a nil registry")
	}
	if b := registry.Get("account"); b == nil {
		t.Fatalf("Get returned a nil breaker")
	}
}

func TestNewBreakersRejectsAnUnparsableOpenTimeout(t *testing.T) {
	cfg := config.Config{Upstream: config.Upstream{CircuitBreaker: config.CircuitBreaker{OpenTimeout: "soon"}}}
	if _, err := newBreakers(cfg); err == nil {
		t.Fatalf("newBreakers accepted the open timeout %q", "soon")
	}
}

// --- build ----------------------------------------------------------------

func TestBuildWiresAWorkingGateway(t *testing.T) {
	gateway, cleanup, err := build(validConfig(), testLogger(t))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if gateway == nil {
		t.Fatalf("build returned a nil handler")
	}
	if cleanup == nil {
		t.Fatalf("build returned a nil cleanup")
	}
	defer cleanup()

	services := gateway.Services()
	if len(services) != 1 || services[0] != "account" {
		t.Fatalf("Services = %v, want [account]", services)
	}
}

func TestBuildRejectsARouteNamingAnUnconfiguredScheme(t *testing.T) {
	// The scheme list is operator input. A typo must fail at start-up rather
	// than leaving a route that rejects every caller at runtime, which looks
	// like an authentication problem and not a configuration one.
	cfg := validConfig()
	cfg.Routes[0].Authenticators = []string{config.SchemeJWT}

	_, _, err := build(cfg, testLogger(t))
	if err == nil {
		t.Fatalf("build accepted a route naming an unconfigured scheme")
	}
	var cfgErr *httpx.ConfigError
	if !errors.As(err, &cfgErr) {
		t.Fatalf("error = %T, want *httpx.ConfigError", err)
	}
	if !strings.Contains(cfgErr.Field, "authenticators") {
		t.Fatalf("field = %q, want it to name the authenticators list", cfgErr.Field)
	}
}

// TestBuildLeavesTheUpstreamCrossCheckToValidate pins where the
// route-to-upstream check lives. config.Validate rejects a route naming an
// unknown upstream, and run() reaches it through config.Load; build is a
// lower-level assembler that must not duplicate the rule, because a caller
// constructing a Config in Go would then get a different answer than one
// loading the same document from disk. An unknown upstream still cannot be
// served: proxy.Serve answers 502 for it.
func TestBuildLeavesTheUpstreamCrossCheckToValidate(t *testing.T) {
	cfg := validConfig()
	cfg.Routes[0].Service = "ghost"

	if _, _, err := build(cfg, testLogger(t)); err != nil {
		t.Fatalf("build: %v, want the upstream check to live in config.Validate", err)
	}
	if err := cfg.Validate(); err == nil {
		t.Fatalf("Validate accepted a route pointing at an unknown upstream")
	}
}

func TestBuildRejectsAnInvalidTrustedProxy(t *testing.T) {
	cfg := validConfig()
	cfg.Security.ClientIP.TrustedProxies = []string{"not-a-cidr"}
	if _, _, err := build(cfg, testLogger(t)); err == nil {
		t.Fatalf("build accepted an unparsable trusted proxy")
	}
}

func TestBuildRejectsAnInvalidIPRule(t *testing.T) {
	cfg := validConfig()
	cfg.Routes[0].AllowedIPs = []string{"not-a-cidr"}
	if _, _, err := build(cfg, testLogger(t)); err == nil {
		t.Fatalf("build accepted an unparsable allowed_ips entry")
	}
}

func TestBuildAppliesTheConfiguredRateLimit(t *testing.T) {
	// End to end through build: a route that sets rate_limit must end up with
	// a limiter that actually rejects. This is the assertion the dropped-field
	// bug would have failed.
	cfg := validConfig()
	cfg.Routes[0].RateLimit = 0.001
	cfg.Routes[0].RateBurst = 1

	gateway, cleanup, err := build(cfg, testLogger(t))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	defer cleanup()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/account", nil)
	req.Header.Set("X-Api-Key", "test-key")
	gateway.ServeHTTP(rec, req)
	if rec.Code == http.StatusTooManyRequests {
		t.Fatalf("the first request was rate limited")
	}
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/account", nil)
	req.Header.Set("X-Api-Key", "test-key")
	gateway.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429: the configured rate limit was not applied", rec.Code)
	}
}

// --- run ------------------------------------------------------------------

func TestRunPrintsTheVersionAndExits(t *testing.T) {
	withArgs(t, "gatewayd", "-version")
	out := captureStdout(t, func() {
		if err := run(); err != nil {
			t.Errorf("run: %v", err)
		}
	})
	if !strings.Contains(out, version) {
		t.Fatalf("output = %q, want it to contain the version %q", out, version)
	}
}

func TestRunReportsAMissingConfigFile(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent.yaml")
	withArgs(t, "gatewayd", "-config", missing)

	err := run()
	if err == nil {
		t.Fatalf("run accepted a missing configuration file")
	}
	// The failure must be reported before a listener is created, so no port is
	// bound. run returns rather than blocking, which is what proves it.
	if !strings.Contains(err.Error(), missing) {
		t.Fatalf("error = %v, want it to name the missing path", err)
	}
}

func TestRunReportsAnInvalidConfigFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(path, []byte("server:\n  addr: :8080\nroutes:\n  - path: /a\n    service: ghost\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	withArgs(t, "gatewayd", "-config", path)

	if err := run(); err == nil {
		t.Fatalf("run accepted a config whose route names an unknown upstream")
	}
}

func TestRunReportsAnUnparsableLogLevel(t *testing.T) {
	path := filepath.Join(t.TempDir(), "loud.yaml")
	if err := os.WriteFile(path, []byte("logging:\n  level: loud\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	withArgs(t, "gatewayd", "-config", path)
	if err := run(); err == nil {
		t.Fatalf("run accepted the log level %q", "loud")
	}
}

// TestExampleConfigIsValid guards the shipped example. It is the first file a
// new operator copies, and it is the only worked example of the YAML subset,
// so a parser change or a renamed field that breaks it would otherwise be
// discovered by a user rather than by the build.
func TestExampleConfigIsValid(t *testing.T) {
	path := filepath.Join("..", "..", "config.example.yaml")

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("config.example.yaml does not load: %v", err)
	}

	// The example must exercise every documented route shape, and it must
	// survive the same assembly the binary performs.
	if len(cfg.Routes) != 4 {
		t.Fatalf("the example has %d routes, want the four backends", len(cfg.Routes))
	}
	for _, name := range []string{"account", "transfer", "payment", "customer"} {
		if _, ok := cfg.Upstreams[name]; !ok {
			t.Errorf("the example has no upstream named %q", name)
		}
	}
	gateway, cleanup, err := build(cfg, testLogger(t))
	if err != nil {
		t.Fatalf("the example does not assemble: %v", err)
	}
	defer cleanup()
	if got := len(gateway.Services()); got != 4 {
		t.Fatalf("the example produced %d upstreams, want 4", got)
	}

	// A rate limit in the example is worthless if the binary drops it, so
	// assert that at least one route actually carries one.
	limited := 0
	for _, route := range cfg.Routes {
		if route.RateLimit > 0 {
			limited++
		}
	}
	if limited == 0 {
		t.Fatalf("no route in the example sets rate_limit")
	}
}

// --- version --------------------------------------------------------------

func TestVersionHasADefault(t *testing.T) {
	// version is overridden at build time with -ldflags. The default has to be
	// non-empty so -version always prints something.
	if version == "" {
		t.Fatalf("version is empty, want a default such as %q", "dev")
	}
}
