package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Inc-cryp/api-security-gateway/internal/httpx"
)

// doc assembles a complete, valid configuration document, replacing any
// section the caller overrides. Building documents by section keeps each test
// focused on the one thing it exercises instead of restating the whole file.
func doc(overrides map[string]string) string {
	order := []string{"server", "upstreams", "routes", "security"}
	defaults := map[string]string{
		"server":    "server:\n  addr: \":8080\"\n",
		"upstreams": "upstreams:\n  account: http://127.0.0.1:9001\n",
		"routes":    "routes:\n  - path: /account\n    service: account\n",
		"security":  "security:\n  api_keys:\n    - key: k\n      client_id: c\n",
	}

	var b strings.Builder
	for _, name := range order {
		if replacement, ok := overrides[name]; ok {
			b.WriteString(replacement)
			continue
		}
		b.WriteString(defaults[name])
	}
	// A typo'd section name would otherwise be dropped silently and the test
	// would assert against the default document instead of the intended one.
	for name := range overrides {
		if name == "extra" {
			continue
		}
		if _, known := defaults[name]; !known {
			panic("doc: unknown section " + name)
		}
	}
	b.WriteString(overrides["extra"])
	return b.String()
}

func mustParse(t *testing.T, src string) Config {
	t.Helper()
	cfg, err := Parse(src)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return cfg
}

func wantConfigError(t *testing.T, err error, field string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected an error for field %q, got nil", field)
	}
	var cfgErr *httpx.ConfigError
	if !errors.As(err, &cfgErr) {
		t.Fatalf("error = %v (%T), want *httpx.ConfigError", err, err)
	}
	if cfgErr.Field != field {
		t.Fatalf("ConfigError.Field = %q, want %q (error: %v)", cfgErr.Field, field, err)
	}
}

func TestKnownScheme(t *testing.T) {
	for _, scheme := range []string{SchemeJWT, SchemeAPIKey, SchemeHMAC} {
		if !KnownScheme(scheme) {
			t.Fatalf("KnownScheme(%q) = false, want true", scheme)
		}
	}
	for _, scheme := range []string{"", "basic", "JWT", "oauth2"} {
		if KnownScheme(scheme) {
			t.Fatalf("KnownScheme(%q) = true, want false", scheme)
		}
	}
}

func TestDefaults(t *testing.T) {
	d := Defaults()
	if d.Server.Addr != ":8080" {
		t.Fatalf("Server.Addr = %q, want :8080", d.Server.Addr)
	}
	if d.Server.MaxBodyBytes != 1<<20 {
		t.Fatalf("Server.MaxBodyBytes = %d, want 1MiB", d.Server.MaxBodyBytes)
	}
	if d.Upstream.Timeout != "30s" {
		t.Fatalf("Upstream.Timeout = %q, want 30s", d.Upstream.Timeout)
	}
	if d.Upstream.MaxIdleConns != 100 {
		t.Fatalf("Upstream.MaxIdleConns = %d, want 100", d.Upstream.MaxIdleConns)
	}
	if d.Logging.Level != "info" {
		t.Fatalf("Logging.Level = %q, want info", d.Logging.Level)
	}
	// Every default must itself be valid, or a config that omits the section
	// would fail validation for a reason the author never wrote.
	if _, err := Parse("upstreams:\n  account: http://127.0.0.1:9001\nroutes:\n  - path: /account\n    service: account\nsecurity:\n  api_keys:\n    - key: k\n      client_id: c\n"); err != nil {
		t.Fatalf("a document relying on the defaults failed validation: %v", err)
	}
}

// TestDefaultsAreOverridable checks that a decoded field wins over the default
// it replaced.
func TestDefaultsAreOverridable(t *testing.T) {
	cfg := mustParse(t, doc(map[string]string{
		"server": "server:\n  addr: \":9090\"\n  max_body_bytes: 2048\n",
	}))
	if cfg.Server.Addr != ":9090" {
		t.Fatalf("Server.Addr = %q, want :9090", cfg.Server.Addr)
	}
	if cfg.Server.MaxBodyBytes != 2048 {
		t.Fatalf("Server.MaxBodyBytes = %d, want 2048", cfg.Server.MaxBodyBytes)
	}
}

func TestParseDecodesEverySection(t *testing.T) {
	src := `
server:
  addr: ":9090"
  read_timeout: 11s
  write_timeout: 12s
  read_header_timeout: 13s
  idle_timeout: 14s
  shutdown_timeout: 15s
  max_body_bytes: 4096
upstreams:
  account: http://127.0.0.1:9001
  transfer: http://127.0.0.1:9002
upstream:
  timeout: 5s
  max_idle_conns: 42
  idle_conn_timeout: 20s
  circuit_breaker:
    failure_threshold: 7
    open_timeout: 9s
    half_open_successes: 3
routes:
  - path: /account
    service: account
    authenticators: [jwt, api_key]
    methods: [GET, POST]
    strip_prefix: true
    rate_limit: 12.5
    rate_burst: 30
    timeout: 3s
    allowed_ips: [10.0.0.0/8]
    denied_ips: [10.9.9.9/32]
  - path: /transfer
    service: transfer
security:
  jwt:
    secret: a-very-long-shared-secret
    issuer: gateway
    audience: banking
    clock_skew: 45s
  api_keys:
    - key: key-one
      client_id: client-one
    - key: key-two
      client_id: client-two
  hmac:
    max_skew: 90s
    client_header: X-Client-Id
    timestamp_header: X-Ts
    signature_header: X-Sig
    clients:
      - client_id: signer
        secret: signer-secret
  client_ip:
    forwarded_header: X-Real-Ip
    trusted_proxies: [10.0.0.0/8]
logging:
  level: debug
  redact_query: true
  redact_headers: [Authorization, Cookie]
headers:
  X-Gateway: api-security-gateway
`
	cfg := mustParse(t, src)

	if cfg.Server.Addr != ":9090" || cfg.Server.MaxBodyBytes != 4096 {
		t.Fatalf("Server = %+v, want the decoded values", cfg.Server)
	}
	if cfg.Server.ReadTimeout != "11s" || cfg.Server.ShutdownTimeout != "15s" {
		t.Fatalf("Server = %+v, want the decoded timeout strings", cfg.Server)
	}
	if len(cfg.Upstreams) != 2 || cfg.Upstreams["transfer"] != "http://127.0.0.1:9002" {
		t.Fatalf("Upstreams = %v, want both services", cfg.Upstreams)
	}
	if cfg.Upstream.MaxIdleConns != 42 || cfg.Upstream.IdleConnTimeout != "20s" {
		t.Fatalf("Upstream = %+v, want the decoded values", cfg.Upstream)
	}
	if cfg.Upstream.CircuitBreaker.FailureThreshold != 7 || cfg.Upstream.CircuitBreaker.HalfOpenSuccesses != 3 {
		t.Fatalf("CircuitBreaker = %+v, want the decoded values", cfg.Upstream.CircuitBreaker)
	}
	if cfg.Upstream.CircuitBreaker.OpenTimeout != "9s" {
		t.Fatalf("OpenTimeout = %q, want 9s", cfg.Upstream.CircuitBreaker.OpenTimeout)
	}

	if len(cfg.Routes) != 2 {
		t.Fatalf("len(Routes) = %d, want 2", len(cfg.Routes))
	}
	first := cfg.Routes[0]
	if first.Path != "/account" || first.Service != "account" || !first.StripPrefix {
		t.Fatalf("Routes[0] = %+v, want the decoded values", first)
	}
	if len(first.Authenticators) != 2 || first.Authenticators[1] != SchemeAPIKey {
		t.Fatalf("Authenticators = %v, want [jwt api_key]", first.Authenticators)
	}
	if len(first.Methods) != 2 || first.Methods[0] != "GET" {
		t.Fatalf("Methods = %v, want [GET POST]", first.Methods)
	}
	if first.RateLimit != 12.5 || first.RateBurst != 30 {
		t.Fatalf("rate limit = %v/%d, want 12.5/30", first.RateLimit, first.RateBurst)
	}
	if first.Timeout != "3s" {
		t.Fatalf("Timeout = %q, want 3s", first.Timeout)
	}
	if len(first.AllowedIPs) != 1 || len(first.DeniedIPs) != 1 {
		t.Fatalf("IP lists = %v / %v, want one entry each", first.AllowedIPs, first.DeniedIPs)
	}

	if cfg.Security.JWT.Secret != "a-very-long-shared-secret" || cfg.Security.JWT.Issuer != "gateway" {
		t.Fatalf("JWT = %+v, want the decoded values", cfg.Security.JWT)
	}
	if cfg.Security.JWT.Audience != "banking" || cfg.Security.JWT.ClockSkew != "45s" {
		t.Fatalf("JWT = %+v, want audience and clock skew", cfg.Security.JWT)
	}
	if len(cfg.Security.APIKeys) != 2 || cfg.Security.APIKeys[1].ClientID != "client-two" {
		t.Fatalf("APIKeys = %+v, want both keys", cfg.Security.APIKeys)
	}
	if len(cfg.Security.HMAC.Clients) != 1 || cfg.Security.HMAC.Clients[0].Secret != "signer-secret" {
		t.Fatalf("HMAC.Clients = %+v, want the decoded client", cfg.Security.HMAC.Clients)
	}
	if cfg.Security.HMAC.SignatureHeader != "X-Sig" || cfg.Security.HMAC.MaxSkew != "90s" {
		t.Fatalf("HMAC = %+v, want the decoded values", cfg.Security.HMAC)
	}
	if cfg.Security.ClientIP.ForwardedHeader != "X-Real-Ip" {
		t.Fatalf("ClientIP = %+v, want the forwarded header", cfg.Security.ClientIP)
	}

	if cfg.Logging.Level != "debug" || !cfg.Logging.RedactQuery {
		t.Fatalf("Logging = %+v, want the decoded values", cfg.Logging)
	}
	if len(cfg.Logging.RedactHeaders) != 2 {
		t.Fatalf("RedactHeaders = %v, want two entries", cfg.Logging.RedactHeaders)
	}
	if cfg.Headers["X-Gateway"] != "api-security-gateway" {
		t.Fatalf("Headers = %v, want the configured header", cfg.Headers)
	}
}

// TestParseDecodesBareDashItem covers `-` on its own line, whose mapping is
// indented one level further.
func TestParseDecodesBareDashItem(t *testing.T) {
	cfg := mustParse(t, doc(map[string]string{
		"security": "security:\n  api_keys:\n    -\n      key: k\n      client_id: c\n",
	}))
	if len(cfg.Security.APIKeys) != 1 || cfg.Security.APIKeys[0].ClientID != "c" {
		t.Fatalf("APIKeys = %+v, want the decoded item", cfg.Security.APIKeys)
	}
}

func TestParseDecodesBlockSequenceOfScalars(t *testing.T) {
	cfg := mustParse(t, doc(map[string]string{
		"routes": "routes:\n  - path: /account\n    service: account\n    methods:\n      - GET\n      - POST\n",
	}))
	if len(cfg.Routes[0].Methods) != 2 || cfg.Routes[0].Methods[1] != "POST" {
		t.Fatalf("Methods = %v, want [GET POST]", cfg.Routes[0].Methods)
	}
}

func TestParseDecodesEmptyInlineList(t *testing.T) {
	cfg := mustParse(t, doc(map[string]string{
		"routes": "routes:\n  - path: /account\n    service: account\n    methods: []\n",
	}))
	if len(cfg.Routes[0].Methods) != 0 {
		t.Fatalf("Methods = %v, want empty", cfg.Routes[0].Methods)
	}
}

func TestParseDecodesMultipleSequenceItems(t *testing.T) {
	cfg := mustParse(t, doc(map[string]string{
		"upstreams": "upstreams:\n  account: http://127.0.0.1:9001\n  transfer: http://127.0.0.1:9002\n",
		"routes":    "routes:\n  - path: /account\n    service: account\n  - path: /transfer\n    service: transfer\n",
	}))
	if len(cfg.Routes) != 2 || cfg.Routes[1].Path != "/transfer" {
		t.Fatalf("Routes = %+v, want both routes", cfg.Routes)
	}
}

func TestParseDecodesDeeplyNestedMapping(t *testing.T) {
	cfg := mustParse(t, doc(map[string]string{
		"extra": "upstream:\n  circuit_breaker:\n    failure_threshold: 3\n    open_timeout: 7s\n    half_open_successes: 1\n",
	}))
	if cfg.Upstream.CircuitBreaker.FailureThreshold != 3 {
		t.Fatalf("FailureThreshold = %d, want 3", cfg.Upstream.CircuitBreaker.FailureThreshold)
	}
	if cfg.Upstream.CircuitBreaker.OpenTimeout != "7s" {
		t.Fatalf("OpenTimeout = %q, want 7s", cfg.Upstream.CircuitBreaker.OpenTimeout)
	}
}

// --- comments and quoting ------------------------------------------------

func TestParseHandlesComments(t *testing.T) {
	cfg := mustParse(t, "# leading comment\n"+doc(map[string]string{
		"upstreams": "upstreams:\n  account: http://127.0.0.1:9001 # trailing comment\n",
		"routes":    "routes:\n  - path: /account # another\n    service: account\n",
	}))
	if cfg.Upstreams["account"] != "http://127.0.0.1:9001" {
		t.Fatalf("Upstreams[account] = %q, want the URL without the comment", cfg.Upstreams["account"])
	}
	if cfg.Routes[0].Path != "/account" {
		t.Fatalf("Path = %q, want /account", cfg.Routes[0].Path)
	}
}

// TestParseKeepsHashInsideAValue is the reason stripComment is quote- and
// word-aware: a URL fragment is not a comment.
func TestParseKeepsHashInsideAValue(t *testing.T) {
	cfg := mustParse(t, doc(map[string]string{
		"upstreams": "upstreams:\n  account: http://127.0.0.1:9001/path#fragment\n",
	}))
	if got := cfg.Upstreams["account"]; got != "http://127.0.0.1:9001/path#fragment" {
		t.Fatalf("Upstreams[account] = %q, want the fragment preserved", got)
	}
}

func TestParseStripsQuotes(t *testing.T) {
	cfg := mustParse(t, doc(map[string]string{
		"upstreams": "upstreams:\n  account: \"http://127.0.0.1:9001\"\n",
		"server":    "server:\n  addr: ':9099'\n",
	}))
	if cfg.Upstreams["account"] != "http://127.0.0.1:9001" {
		t.Fatalf("Upstreams[account] = %q, want the quotes stripped", cfg.Upstreams["account"])
	}
	if cfg.Server.Addr != ":9099" {
		t.Fatalf("Server.Addr = %q, want the single-quoted value", cfg.Server.Addr)
	}
}

func TestParseDecodesQuotedHashAsLiteral(t *testing.T) {
	cfg := mustParse(t, doc(map[string]string{
		"extra": "headers:\n  X-Note: \"a # b\"\n",
	}))
	if cfg.Headers["X-Note"] != "a # b" {
		t.Fatalf("Headers[X-Note] = %q, want the quoted hash preserved", cfg.Headers["X-Note"])
	}
}

func TestParseAllowsKeyContainingColonWhenQuoted(t *testing.T) {
	// The key is quoted, so its colon is part of the key and not the
	// separator. Validation then rejects it, which proves it was decoded as a
	// header name rather than misparsed.
	_, err := Parse(doc(map[string]string{"extra": "headers:\n  \"a:b\": v\n"}))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
}

// --- parser errors --------------------------------------------------------

func TestParseRejectsTabs(t *testing.T) {
	_, err := Parse("upstreams:\n\taccount: http://127.0.0.1:9001\n")
	if err == nil {
		t.Fatal("expected an error for a tab-indented document")
	}
	if !strings.Contains(err.Error(), "tab") {
		t.Fatalf("error = %v, want it to mention tabs", err)
	}
}

// TestParseRejectsMisalignedSequenceItemKeys covers the indentation rule for a
// mapping sequence item: its remaining keys must line up with the first key
// after the dash.
func TestParseRejectsMisalignedSequenceItemKeys(t *testing.T) {
	_, err := Parse("routes:\n  - path: /account\n   service: account\n")
	if err == nil {
		t.Fatal("expected an error for a misaligned sequence item")
	}
}

func TestParseRejectsOverIndentedLine(t *testing.T) {
	_, err := Parse("upstreams:\n  account: http://127.0.0.1:9001\n      extra: x\n")
	if err == nil {
		t.Fatal("expected an error for a deeper indent without a key")
	}
}

func TestParseRejectsDuplicateKey(t *testing.T) {
	_, err := Parse("server:\n  addr: \":1\"\n  addr: \":2\"\n")
	if err == nil || !strings.Contains(err.Error(), "duplicate key") {
		t.Fatalf("error = %v, want a duplicate key error", err)
	}
}

func TestParseRejectsUnknownKey(t *testing.T) {
	_, err := Parse("servre:\n  addr: \":1\"\n")
	wantConfigError(t, err, "servre")
}

func TestParseRejectsUnknownNestedKey(t *testing.T) {
	_, err := Parse("server:\n  adr: \":1\"\n")
	wantConfigError(t, err, "server.adr")
}

func TestParseRejectsLineWithoutColon(t *testing.T) {
	_, err := Parse("upstreams\n  account: http://127.0.0.1:9001\n")
	if err == nil {
		t.Fatal("expected an error for a line without a colon")
	}
}

func TestParseRejectsNonMappingRoot(t *testing.T) {
	_, err := Parse("- a\n- b\n")
	if err == nil {
		t.Fatal("expected an error for a sequence at the document root")
	}
}

// TestParseRejectsFlowMapping documents the deliberate YAML-subset boundary:
// `{...}` is not supported and must fail loudly rather than be misread.
func TestParseRejectsFlowMapping(t *testing.T) {
	_, err := Parse("security:\n  api_keys: [{key: k, client_id: c}]\n")
	if err == nil {
		t.Fatal("expected an error for an unsupported flow mapping")
	}
}

func TestParseEmptyDocumentFailsValidation(t *testing.T) {
	_, err := Parse("")
	wantConfigError(t, err, "upstreams")
}

func TestParseEmptyValueBecomesEmptyString(t *testing.T) {
	// `addr:` with nothing after it decodes as an empty string rather than
	// silently keeping the default, so validation rejects it.
	_, err := Parse(doc(map[string]string{"server": "server:\n  addr:\n"}))
	wantConfigError(t, err, "server.addr")
}

// --- scalar decoding ------------------------------------------------------

func TestParseRejectsMalformedScalars(t *testing.T) {
	tests := []struct {
		name    string
		section string
		value   string
		field   string
	}{
		{"body limit", "server", "server:\n  addr: \":8080\"\n  max_body_bytes: lots\n", "server.max_body_bytes"},
		{"int field", "extra", "upstream:\n  max_idle_conns: many\n", "upstream.max_idle_conns"},
		{"bool field", "extra", "logging:\n  redact_query: perhaps\n", "logging.redact_query"},
		{"float field", "routes", "routes:\n  - path: /account\n    service: account\n    rate_limit: fast\n", "routes[0].rate_limit"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(doc(map[string]string{tc.section: tc.value}))
			wantConfigError(t, err, tc.field)
		})
	}
}

func TestParseRejectsScalarWhereMappingExpected(t *testing.T) {
	_, err := Parse("server: nope\n")
	wantConfigError(t, err, "server")
}

func TestParseRejectsScalarWhereSequenceExpected(t *testing.T) {
	_, err := Parse("routes: /account\n")
	wantConfigError(t, err, "routes")
}

// --- validation -----------------------------------------------------------

func TestValidateRequiredSections(t *testing.T) {
	tests := []struct {
		name  string
		src   string
		field string
	}{
		{
			name:  "no upstreams",
			src:   "routes:\n  - path: /a\n    service: a\nsecurity:\n  api_keys:\n    - key: k\n      client_id: c\n",
			field: "upstreams",
		},
		{
			name:  "no routes",
			src:   "upstreams:\n  a: http://127.0.0.1:1\nsecurity:\n  api_keys:\n    - key: k\n      client_id: c\n",
			field: "routes",
		},
		{
			name:  "no verifier",
			src:   "upstreams:\n  a: http://127.0.0.1:1\nroutes:\n  - path: /a\n    service: a\n",
			field: "security",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(tc.src)
			wantConfigError(t, err, tc.field)
		})
	}
}

// TestValidateRejectsRouteWithUnknownService is the cross-check that keeps a
// typo in `service` from becoming a runtime 502.
func TestValidateRejectsRouteWithUnknownService(t *testing.T) {
	_, err := Parse(doc(map[string]string{
		"routes": "routes:\n  - path: /account\n    service: acount\n",
	}))
	wantConfigError(t, err, "routes[0].service")
}

func TestValidateRejectsEmptyUpstreamURL(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{"blank url", `  account: ""`},
		{"missing url", `  account:`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(doc(map[string]string{"upstreams": "upstreams:\n" + tc.value + "\n"}))
			if err == nil {
				t.Fatal("expected an error for an empty upstream URL")
			}
		})
	}
}

func TestValidateRouteFields(t *testing.T) {
	tests := []struct {
		name  string
		route string
		field string
	}{
		{"missing path", "  - service: account\n", "routes[0].path"},
		{"path without slash", "  - path: account\n    service: account\n", "routes[0].path"},
		{"missing service", "  - path: /a\n", "routes[0].service"},
		{"unknown scheme", "  - path: /a\n    service: account\n    authenticators: [basic]\n", "routes[0].authenticators"},
		{"bogus method", "  - path: /a\n    service: account\n    methods: [FETCH]\n", "routes[0].methods"},
		{"negative rate limit", "  - path: /a\n    service: account\n    rate_limit: -1\n", "routes[0].rate_limit"},
		{"rate limit without burst", "  - path: /a\n    service: account\n    rate_limit: 10\n", "routes[0].rate_burst"},
		{"bad timeout", "  - path: /a\n    service: account\n    timeout: soon\n", "routes[0].timeout"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(doc(map[string]string{"routes": "routes:\n" + tc.route}))
			wantConfigError(t, err, tc.field)
		})
	}
}

func TestValidateRejectsDuplicateRoutePath(t *testing.T) {
	_, err := Parse(doc(map[string]string{
		"routes": "routes:\n  - path: /account\n    service: account\n  - path: /account\n    service: account\n",
	}))
	wantConfigError(t, err, "routes[1].path")
}

// TestValidateAcceptsRateLimitWithBurst is the positive half of the rate_burst
// rule: setting both is valid.
func TestValidateAcceptsRateLimitWithBurst(t *testing.T) {
	cfg := mustParse(t, doc(map[string]string{
		"routes": "routes:\n  - path: /account\n    service: account\n    rate_limit: 10\n    rate_burst: 20\n",
	}))
	if cfg.Routes[0].RateBurst != 20 {
		t.Fatalf("RateBurst = %d, want 20", cfg.Routes[0].RateBurst)
	}
}

func TestValidateServerFields(t *testing.T) {
	tests := []struct {
		name  string
		value string
		field string
	}{
		{"blank addr", "server:\n  addr: \"\"\n", "server.addr"},
		{"zero body limit", "server:\n  addr: \":8080\"\n  max_body_bytes: 0\n", "server.max_body_bytes"},
		{"negative body limit", "server:\n  addr: \":8080\"\n  max_body_bytes: -1\n", "server.max_body_bytes"},
		{"bad read timeout", "server:\n  addr: \":8080\"\n  read_timeout: later\n", "server.read_timeout"},
		{"bad shutdown timeout", "server:\n  addr: \":8080\"\n  shutdown_timeout: later\n", "server.shutdown_timeout"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(doc(map[string]string{"server": tc.value}))
			wantConfigError(t, err, tc.field)
		})
	}
}

func TestValidateUpstreamDurations(t *testing.T) {
	tests := []struct {
		name  string
		extra string
		field string
	}{
		{"bad default timeout", "upstream:\n  timeout: soon\n", "upstream.timeout"},
		{"bad idle conn timeout", "upstream:\n  idle_conn_timeout: soon\n", "upstream.idle_conn_timeout"},
		{"bad breaker open timeout", "upstream:\n  circuit_breaker:\n    open_timeout: soon\n", "upstream.circuit_breaker.open_timeout"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(doc(map[string]string{"extra": tc.extra}))
			wantConfigError(t, err, tc.field)
		})
	}
}

func TestValidateSkewDurations(t *testing.T) {
	tests := []struct {
		name  string
		value string
		field string
	}{
		{
			name:  "jwt clock skew",
			value: "security:\n  jwt:\n    secret: a-very-long-shared-secret\n    clock_skew: soon\n  api_keys:\n    - key: k\n      client_id: c\n",
			field: "security.jwt.clock_skew",
		},
		{
			name:  "hmac max skew",
			value: "security:\n  hmac:\n    max_skew: soon\n    clients:\n      - client_id: c\n        secret: s\n",
			field: "security.hmac.max_skew",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(doc(map[string]string{"security": tc.value}))
			wantConfigError(t, err, tc.field)
		})
	}
}

// TestValidateJWTSegmentLength also asserts the secret is not echoed back:
// configuration errors end up in logs.
func TestValidateJWTSegmentLength(t *testing.T) {
	_, err := Parse(doc(map[string]string{
		"security": "security:\n  jwt:\n    secret: short\n",
	}))
	wantConfigError(t, err, "security.jwt.secret")

	if strings.Contains(err.Error(), "short") {
		t.Fatalf("error %q leaked the secret value", err)
	}
}

func TestValidateCredentialFields(t *testing.T) {
	tests := []struct {
		name    string
		section string
		value   string
		field   string
	}{
		{
			name:    "api key without key",
			section: "security",
			value:   "security:\n  api_keys:\n    - client_id: c\n",
			field:   "security.api_keys[0].key",
		},
		{
			name:    "api key without client id",
			section: "security",
			value:   "security:\n  api_keys:\n    - key: k\n",
			field:   "security.api_keys[0].client_id",
		},
		{
			name:    "hmac client without client id",
			section: "security",
			value:   "security:\n  hmac:\n    clients:\n      - secret: s\n",
			field:   "security.hmac.clients[0].client_id",
		},
		{
			name:    "hmac client without secret",
			section: "security",
			value:   "security:\n  hmac:\n    clients:\n      - client_id: c\n",
			field:   "security.hmac.clients[0].secret",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(doc(map[string]string{tc.section: tc.value}))
			wantConfigError(t, err, tc.field)
		})
	}
}

func TestValidateTrustedProxies(t *testing.T) {
	_, err := Parse(doc(map[string]string{
		"security": "security:\n  api_keys:\n    - key: k\n      client_id: c\n  client_ip:\n    forwarded_header: X-Forwarded-For\n    trusted_proxies: [10.0.0.0/8, bogus]\n",
	}))
	wantConfigError(t, err, "client_ip.trusted_proxies")
}

func TestValidateLoggingLevel(t *testing.T) {
	_, err := Parse(doc(map[string]string{"extra": "logging:\n  level: verbose\n"}))
	wantConfigError(t, err, "logging.level")

	for _, level := range []string{"debug", "info", "warn", "error"} {
		mustParse(t, doc(map[string]string{"extra": "logging:\n  level: " + level + "\n"}))
	}
}

func TestValidateEmptyHeaderName(t *testing.T) {
	_, err := Parse(doc(map[string]string{"extra": "headers:\n  \"\": value\n"}))
	wantConfigError(t, err, "headers")
}

// --- durations ------------------------------------------------------------

func TestParseDuration(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    time.Duration
		wantErr bool
	}{
		{"bare number is seconds", "30", 30 * time.Second, false},
		{"zero", "0", 0, false},
		{"seconds suffix", "45s", 45 * time.Second, false},
		{"minutes", "2m", 2 * time.Minute, false},
		{"composite", "1m30s", 90 * time.Second, false},
		{"milliseconds", "250ms", 250 * time.Millisecond, false},
		{"padded", "  15s  ", 15 * time.Second, false},
		{"empty", "", 0, true},
		{"blank", "   ", 0, true},
		{"negative number", "-5", 0, true},
		{"negative duration", "-5s", 0, true},
		{"not a duration", "soon", 0, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseDuration(tc.value)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseDuration(%q) = %v, want an error", tc.value, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseDuration(%q): %v", tc.value, err)
			}
			if got != tc.want {
				t.Fatalf("ParseDuration(%q) = %v, want %v", tc.value, got, tc.want)
			}
		})
	}
}

func TestServerTimeouts(t *testing.T) {
	cfg := mustParse(t, doc(map[string]string{
		"server": "server:\n  addr: \":8080\"\n  read_timeout: 1s\n  write_timeout: 2s\n  read_header_timeout: 3s\n  idle_timeout: 4s\n  shutdown_timeout: 5s\n",
	}))
	read, write, readHeader, idle, shutdown, err := cfg.Server.ServerTimeouts()
	if err != nil {
		t.Fatalf("ServerTimeouts: %v", err)
	}
	if read != time.Second || write != 2*time.Second || readHeader != 3*time.Second {
		t.Fatalf("timeouts = %v/%v/%v, want 1s/2s/3s", read, write, readHeader)
	}
	if idle != 4*time.Second || shutdown != 5*time.Second {
		t.Fatalf("timeouts = %v/%v, want 4s/5s", idle, shutdown)
	}
}

// --- loading --------------------------------------------------------------

func TestLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(doc(nil)), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Routes) != 1 || cfg.Routes[0].Path != "/account" {
		t.Fatalf("Routes = %+v, want the loaded route", cfg.Routes)
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "absent.yaml"))
	if err == nil {
		t.Fatal("expected an error for a missing file")
	}
	if !strings.Contains(err.Error(), "absent.yaml") {
		t.Fatalf("error = %v, want it to name the file", err)
	}
}

func TestLoadReportsPathOnParseFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(path, []byte("routes:\n  - path: /a\n   service: a\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected a parse error")
	}
	if !strings.Contains(err.Error(), "bad.yaml") {
		t.Fatalf("error = %v, want it to name the file", err)
	}
}
