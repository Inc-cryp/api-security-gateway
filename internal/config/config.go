// Package config loads and validates the gateway's configuration file.
//
// The project is standard-library only, so the YAML subset and the decoder
// are hand-written. They support exactly what a gateway config needs —
// nested mappings by indentation, sequences, scalars, inline string lists and
// comments — and reject anything richer (anchors, flow mappings, block
// scalars, tabs) with a clear error rather than misreading it.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Inc-cryp/api-security-gateway/internal/httpx"
)

// Scheme names accepted in a route's authenticators list.
const (
	SchemeJWT    = "jwt"
	SchemeAPIKey = "api_key"
	SchemeHMAC   = "hmac"
)

// KnownScheme reports whether scheme is one the gateway can enforce.
func KnownScheme(scheme string) bool {
	switch scheme {
	case SchemeJWT, SchemeAPIKey, SchemeHMAC:
		return true
	default:
		return false
	}
}

// Config is the whole gateway configuration.
type Config struct {
	Server    Server            `yaml:"server"`
	Routes    []Route           `yaml:"routes"`
	Security  Security          `yaml:"security"`
	Upstreams map[string]string `yaml:"upstreams"`
	Upstream  Upstream          `yaml:"upstream"`
	Logging   Logging           `yaml:"logging"`
	Headers   map[string]string `yaml:"headers"`
}

// Server holds listener settings.
type Server struct {
	Addr              string `yaml:"addr"`
	ReadTimeout       string `yaml:"read_timeout"`
	WriteTimeout      string `yaml:"write_timeout"`
	ReadHeaderTimeout string `yaml:"read_header_timeout"`
	IdleTimeout       string `yaml:"idle_timeout"`
	ShutdownTimeout   string `yaml:"shutdown_timeout"`
	MaxBodyBytes      int64  `yaml:"max_body_bytes"`
}

// Route maps a path prefix to a named upstream, optionally restricting which
// authentication schemes and which HTTP methods it accepts.
type Route struct {
	Path           string   `yaml:"path"`
	Service        string   `yaml:"service"`
	Authenticators []string `yaml:"authenticators"`
	Methods        []string `yaml:"methods"`
	StripPrefix    bool     `yaml:"strip_prefix"`
	RateLimit      float64  `yaml:"rate_limit"`
	RateBurst      int      `yaml:"rate_burst"`
	Timeout        string   `yaml:"timeout"`
	AllowedIPs     []string `yaml:"allowed_ips"`
	DeniedIPs      []string `yaml:"denied_ips"`
}

// Security holds credential material and the client-IP trust policy.
type Security struct {
	JWT      JWT      `yaml:"jwt"`
	APIKeys  []APIKey `yaml:"api_keys"`
	HMAC     HMAC     `yaml:"hmac"`
	ClientIP ClientIP `yaml:"client_ip"`
}

// JWT configures the HS256 verifier.
type JWT struct {
	Secret    string `yaml:"secret"`
	Issuer    string `yaml:"issuer"`
	Audience  string `yaml:"audience"`
	ClockSkew string `yaml:"clock_skew"`
}

// APIKey is one issued API key and the client it identifies.
type APIKey struct {
	Key      string `yaml:"key"`
	ClientID string `yaml:"client_id"`
}

// HMAC configures request signing.
type HMAC struct {
	Clients         []HMACClient `yaml:"clients"`
	MaxSkew         string       `yaml:"max_skew"`
	ClientHeader    string       `yaml:"client_header"`
	TimestampHeader string       `yaml:"timestamp_header"`
	SignatureHeader string       `yaml:"signature_header"`
}

// HMACClient is one signing client's shared secret.
type HMACClient struct {
	ClientID string `yaml:"client_id"`
	Secret   string `yaml:"secret"`
}

// ClientIP configures how the caller's address is derived.
type ClientIP struct {
	ForwardedHeader string   `yaml:"forwarded_header"`
	TrustedProxies  []string `yaml:"trusted_proxies"`
}

// CircuitBreaker configures the per-upstream circuit breaker.
type CircuitBreaker struct {
	FailureThreshold  int    `yaml:"failure_threshold"`
	OpenTimeout       string `yaml:"open_timeout"`
	HalfOpenSuccesses int    `yaml:"half_open_successes"`
}

// Upstream holds defaults applied to every proxied request.
type Upstream struct {
	Timeout         string         `yaml:"timeout"`
	MaxIdleConns    int            `yaml:"max_idle_conns"`
	IdleConnTimeout string         `yaml:"idle_conn_timeout"`
	CircuitBreaker  CircuitBreaker `yaml:"circuit_breaker"`
}

// Logging configures the access log.
type Logging struct {
	Level         string   `yaml:"level"`
	RedactQuery   bool     `yaml:"redact_query"`
	RedactHeaders []string `yaml:"redact_headers"`
}

// Defaults returns the configuration used for any field the file leaves unset.
func Defaults() Config {
	return Config{
		Server: Server{
			Addr:              ":8080",
			ReadHeaderTimeout: "5s",
			ReadTimeout:       "30s",
			WriteTimeout:      "60s",
			IdleTimeout:       "120s",
			ShutdownTimeout:   "15s",
			MaxBodyBytes:      1 << 20,
		},
		Upstream: Upstream{
			Timeout:         "30s",
			MaxIdleConns:    100,
			IdleConnTimeout: "90s",
		},
		Logging: Logging{Level: "info"},
	}
}

// Load reads, parses and validates the file at path.
func Load(path string) (Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("reading config %s: %w", path, err)
	}
	cfg, err := Parse(string(raw))
	if err != nil {
		return Config{}, fmt.Errorf("config %s: %w", path, err)
	}
	return cfg, nil
}

// Parse turns a configuration document into a validated Config.
func Parse(src string) (Config, error) {
	root, err := parseYAML(src)
	if err != nil {
		return Config{}, err
	}
	cfg := Defaults()
	if err := decodeInto(root, &cfg, ""); err != nil {
		return Config{}, err
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// ServerTimeouts resolves the listener timeouts into real durations.
func (s Server) ServerTimeouts() (read, write, readHeader, idle, shutdown time.Duration, err error) {
	fields := []struct {
		name  string
		value string
		dst   *time.Duration
	}{
		{"server.read_timeout", s.ReadTimeout, &read},
		{"server.write_timeout", s.WriteTimeout, &write},
		{"server.read_header_timeout", s.ReadHeaderTimeout, &readHeader},
		{"server.idle_timeout", s.IdleTimeout, &idle},
		{"server.shutdown_timeout", s.ShutdownTimeout, &shutdown},
	}
	for _, f := range fields {
		d, err := ParseDuration(f.value)
		if err != nil {
			return 0, 0, 0, 0, 0, &httpx.ConfigError{Field: f.name, Value: f.value, Err: err}
		}
		*f.dst = d
	}
	return read, write, readHeader, idle, shutdown, nil
}

// Validate checks every value the gateway relies on being well-formed.
func (c Config) Validate() error {
	if strings.TrimSpace(c.Server.Addr) == "" {
		return &httpx.ConfigError{Field: "server.addr"}
	}
	if c.Server.MaxBodyBytes <= 0 {
		return &httpx.ConfigError{Field: "server.max_body_bytes", Value: strconv.FormatInt(c.Server.MaxBodyBytes, 10), Err: fmt.Errorf("must be positive")}
	}
	if _, _, _, _, _, err := c.Server.ServerTimeouts(); err != nil {
		return err
	}
	if _, err := ParseDuration(c.Upstream.Timeout); err != nil {
		return &httpx.ConfigError{Field: "upstream.timeout", Value: c.Upstream.Timeout, Err: err}
	}
	if c.Upstream.IdleConnTimeout != "" {
		if _, err := ParseDuration(c.Upstream.IdleConnTimeout); err != nil {
			return &httpx.ConfigError{Field: "upstream.idle_conn_timeout", Value: c.Upstream.IdleConnTimeout, Err: err}
		}
	}
	if c.Upstream.CircuitBreaker.OpenTimeout != "" {
		if _, err := ParseDuration(c.Upstream.CircuitBreaker.OpenTimeout); err != nil {
			return &httpx.ConfigError{Field: "upstream.circuit_breaker.open_timeout", Value: c.Upstream.CircuitBreaker.OpenTimeout, Err: err}
		}
	}
	if len(c.Upstreams) == 0 {
		return &httpx.ConfigError{Field: "upstreams", Value: "at least one upstream is required"}
	}
	for name, target := range c.Upstreams {
		if strings.TrimSpace(name) == "" {
			return &httpx.ConfigError{Field: "upstreams", Value: "empty service name"}
		}
		if strings.TrimSpace(target) == "" {
			return &httpx.ConfigError{Field: "upstreams." + name, Value: "empty upstream URL"}
		}
	}
	if len(c.Routes) == 0 {
		return &httpx.ConfigError{Field: "routes", Value: "at least one route is required"}
	}
	seen := make(map[string]bool, len(c.Routes))
	for i, route := range c.Routes {
		if err := route.validate(i, seen); err != nil {
			return err
		}
		if _, ok := c.Upstreams[route.Service]; !ok {
			return &httpx.ConfigError{
				Field: "routes[" + strconv.Itoa(i) + "].service",
				Value: route.Service,
				Err:   fmt.Errorf("no such upstream"),
			}
		}
	}
	if c.Security.JWT.Secret == "" && len(c.Security.APIKeys) == 0 && len(c.Security.HMAC.Clients) == 0 {
		return &httpx.ConfigError{Field: "security", Value: "no verifier configured"}
	}
	if err := c.Security.JWT.validate(); err != nil {
		return err
	}
	for i, key := range c.Security.APIKeys {
		if strings.TrimSpace(key.Key) == "" {
			return &httpx.ConfigError{Field: "security.api_keys[" + strconv.Itoa(i) + "].key"}
		}
		if strings.TrimSpace(key.ClientID) == "" {
			return &httpx.ConfigError{Field: "security.api_keys[" + strconv.Itoa(i) + "].client_id"}
		}
	}
	for i, client := range c.Security.HMAC.Clients {
		if strings.TrimSpace(client.ClientID) == "" {
			return &httpx.ConfigError{Field: "security.hmac.clients[" + strconv.Itoa(i) + "].client_id"}
		}
		if strings.TrimSpace(client.Secret) == "" {
			return &httpx.ConfigError{Field: "security.hmac.clients[" + strconv.Itoa(i) + "].secret"}
		}
	}
	if err := optionalDuration(c.Security.HMAC.MaxSkew, "security.hmac.max_skew"); err != nil {
		return err
	}
	if err := optionalDuration(c.Security.JWT.ClockSkew, "security.jwt.clock_skew"); err != nil {
		return err
	}
	if _, err := httpx.NewClientIPResolver(c.Security.ClientIP.TrustedProxies, c.Security.ClientIP.ForwardedHeader); err != nil {
		return err
	}
	switch c.Logging.Level {
	case "", "debug", "info", "warn", "error":
	default:
		return &httpx.ConfigError{Field: "logging.level", Value: c.Logging.Level, Err: fmt.Errorf("want debug, info, warn or error")}
	}
	for name := range c.Headers {
		if strings.TrimSpace(name) == "" {
			return &httpx.ConfigError{Field: "headers", Value: "empty header name"}
		}
	}
	return nil
}

func (r Route) validate(index int, seen map[string]bool) error {
	field := "routes[" + strconv.Itoa(index) + "]"
	if r.Path == "" {
		return &httpx.ConfigError{Field: field + ".path"}
	}
	if !strings.HasPrefix(r.Path, "/") {
		return &httpx.ConfigError{Field: field + ".path", Value: r.Path, Err: fmt.Errorf("must start with /")}
	}
	if seen[r.Path] {
		return &httpx.ConfigError{Field: field + ".path", Value: r.Path, Err: fmt.Errorf("duplicate route path")}
	}
	seen[r.Path] = true
	if r.Service == "" {
		return &httpx.ConfigError{Field: field + ".service"}
	}
	for _, scheme := range r.Authenticators {
		if !KnownScheme(scheme) {
			return &httpx.ConfigError{Field: field + ".authenticators", Value: scheme, Err: fmt.Errorf("unknown scheme")}
		}
	}
	for _, method := range r.Methods {
		if !validMethod(method) {
			return &httpx.ConfigError{Field: field + ".methods", Value: method, Err: fmt.Errorf("not an HTTP method")}
		}
	}
	if err := optionalDuration(r.Timeout, field+".timeout"); err != nil {
		return err
	}
	if r.RateLimit < 0 {
		return &httpx.ConfigError{Field: field + ".rate_limit", Value: strconv.FormatFloat(r.RateLimit, 'f', -1, 64), Err: fmt.Errorf("must not be negative")}
	}
	if r.RateLimit > 0 && r.RateBurst < 1 {
		return &httpx.ConfigError{Field: field + ".rate_burst", Value: strconv.Itoa(r.RateBurst), Err: fmt.Errorf("required when rate_limit is set")}
	}
	return nil
}

func (j JWT) validate() error {
	if j.Secret == "" {
		return nil
	}
	if len(j.Secret) < 16 {
		return &httpx.ConfigError{Field: "security.jwt.secret", Value: "***", Err: fmt.Errorf("must be at least 16 bytes")}
	}
	return nil
}

func optionalDuration(value, field string) error {
	if value == "" {
		return nil
	}
	if _, err := ParseDuration(value); err != nil {
		return &httpx.ConfigError{Field: field, Value: value, Err: err}
	}
	return nil
}

var knownMethods = map[string]bool{
	"GET": true, "HEAD": true, "POST": true, "PUT": true,
	"PATCH": true, "DELETE": true, "OPTIONS": true, "TRACE": true, "CONNECT": true,
}

func validMethod(method string) bool { return knownMethods[strings.ToUpper(strings.TrimSpace(method))] }

// ParseDuration parses a duration such as "30s" or a bare number of seconds,
// which is what a YAML scalar like `timeout: 30` becomes.
func ParseDuration(value string) (time.Duration, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, fmt.Errorf("empty duration")
	}
	if n, err := strconv.Atoi(value); err == nil {
		if n < 0 {
			return 0, fmt.Errorf("duration must not be negative")
		}
		return time.Duration(n) * time.Second, nil
	}
	d, err := time.ParseDuration(value)
	if err != nil {
		return 0, err
	}
	if d < 0 {
		return 0, fmt.Errorf("duration must not be negative")
	}
	return d, nil
}
