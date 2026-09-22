// Package proxy forwards matched requests to upstream services.
package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/Inc-cryp/api-security-gateway/internal/breaker"
	"github.com/Inc-cryp/api-security-gateway/internal/httpx"
	"github.com/Inc-cryp/api-security-gateway/internal/router"
)

// hopByHopHeaders are connection-scoped headers that must not be forwarded.
// Forwarding them lets a client rewrite the framing of the upstream
// connection, so they are stripped in both directions.
var hopByHopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// Config configures a Proxy.
type Config struct {
	// Services maps a service name to its upstream base URL, for example
	// "account" -> "http://127.0.0.1:9001".
	Services map[string]string
	// DefaultTimeout applies to routes that do not set their own.
	DefaultTimeout time.Duration
	// Breaker guards each upstream. A nil registry disables the breaker.
	Breaker *breaker.Registry
}

// Proxy forwards requests to the configured upstreams.
type Proxy struct {
	services map[string]*url.URL
	client   *http.Client
	breaker  *breaker.Registry
	timeout  time.Duration
}

// New validates cfg and builds a Proxy.
//
// The transport deliberately does not follow redirects: a gateway forwards
// the upstream's answer, it does not adjudicate it, and following a redirect
// would let an upstream point the gateway at an unrelated host.
func New(cfg Config) (*Proxy, error) {
	if len(cfg.Services) == 0 {
		return nil, &httpx.ConfigError{Field: "upstream.services", Value: "no upstream configured"}
	}
	services := make(map[string]*url.URL, len(cfg.Services))
	for name, raw := range cfg.Services {
		if strings.TrimSpace(name) == "" {
			return nil, &httpx.ConfigError{Field: "upstream.services", Value: "empty service name"}
		}
		parsed, err := url.Parse(strings.TrimRight(raw, "/"))
		if err != nil {
			return nil, &httpx.ConfigError{Field: "upstream.services." + name, Value: raw, Err: err}
		}
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			return nil, &httpx.ConfigError{Field: "upstream.services." + name, Value: raw, Err: fmt.Errorf("scheme must be http or https")}
		}
		if parsed.Host == "" {
			return nil, &httpx.ConfigError{Field: "upstream.services." + name, Value: raw, Err: fmt.Errorf("missing host")}
		}
		services[name] = parsed
	}
	timeout := cfg.DefaultTimeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &Proxy{
		services: services,
		timeout:  timeout,
		breaker:  cfg.Breaker,
		client: &http.Client{
			Transport: newTransport(),
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

func newTransport() *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConns = 100
	transport.MaxIdleConnsPerHost = 32
	transport.IdleConnTimeout = 90 * time.Second
	transport.ResponseHeaderTimeout = 0 // governed by the per-request context
	return transport
}

// Services returns the configured service names, sorted.
func (p *Proxy) Services() []string {
	names := make([]string, 0, len(p.services))
	for name := range p.services {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// errorsCopy reports that the upstream status was written and the body copy
// failed. The status line is already on the wire, so the failure is reported
// to the caller for logging rather than turned into a gateway error response.
type errorsCopy struct{ err error }

func (e *errorsCopy) Error() string { return e.err.Error() }
func (e *errorsCopy) Unwrap() error { return e.err }

// Serve forwards r to the route's upstream and writes the response to w. It
// returns the upstream status code and any error encountered.
func (p *Proxy) Serve(w http.ResponseWriter, r *http.Request, route *router.Route) (int, error) {
	upstream, ok := p.services[route.Service]
	if !ok {
		return httpx.WriteError(w, nil, http.StatusBadGateway, httpx.CodeBadGateway,
			fmt.Sprintf("service %q is not configured", route.Service))
	}

	circuit := p.breaker.Get(route.Service)
	if !circuit.Allow() {
		return httpx.WriteError(w, nil, http.StatusServiceUnavailable, httpx.CodeServiceUnavail,
			fmt.Sprintf("upstream %q is unavailable", route.Service))
	}

	timeout := route.Timeout
	if timeout <= 0 {
		timeout = p.timeout
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	outbound := p.buildRequest(ctx, r, upstream, route)
	started := time.Now()
	resp, err := p.client.Do(outbound)
	if err != nil {
		circuit.Record(false)
		status, code, message := transportFailure(err, route.Service, timeout, time.Since(started))
		return httpx.WriteError(w, nil, status, code, message)
	}
	defer resp.Body.Close()

	// A 5xx from the upstream means the dependency is unhealthy; 4xx is the
	// caller's fault and must not trip the breaker.
	circuit.Record(resp.StatusCode < 500)

	return copyResponse(w, resp)
}

// buildRequest constructs the upstream request, copying only what should be
// forwarded.
func (p *Proxy) buildRequest(ctx context.Context, r *http.Request, upstream *url.URL, route *router.Route) *http.Request {
	target := *upstream
	target.Path = singleJoin(upstream.Path, route.ForwardPath(r.URL.Path))
	target.RawPath = ""
	target.RawQuery = r.URL.RawQuery
	target.Fragment = ""

	outbound := r.Clone(ctx)
	outbound.URL = &target
	outbound.RequestURI = ""
	outbound.Host = ""
	outbound.Close = false

	if clientIP := httpx.ClientIP(r); clientIP != nil {
		// Replaced, not appended: the header the gateway sets is the only
		// address downstream services can trust, and appending would leave
		// whatever the client sent in front of it.
		outbound.Header.Set("X-Forwarded-For", clientIP.String())
	}
	outbound.Header.Set("X-Forwarded-Proto", schemeOf(r))
	outbound.Header.Set("X-Forwarded-Host", r.Host)
	if id := httpx.RequestID(r.Context()); id != "" {
		outbound.Header.Set(httpx.RequestIDHeader, id)
	}
	stripHopByHop(outbound.Header)
	outbound.Header.Del("Forwarded")
	return outbound
}

// copyResponse writes the upstream response back to the client.
func copyResponse(w http.ResponseWriter, resp *http.Response) (int, error) {
	stripHopByHop(resp.Header)
	header := w.Header()
	for name, values := range resp.Header {
		for _, value := range values {
			header.Add(name, value)
		}
	}
	w.WriteHeader(resp.StatusCode)
	written, err := io.Copy(w, resp.Body)
	if err != nil {
		// The status line is already sent, so this cannot become a gateway
		// error page; surface it for the access log instead.
		return resp.StatusCode, &errorsCopy{err: fmt.Errorf("copying upstream body after %d bytes: %w", written, err)}
	}
	return resp.StatusCode, nil
}

// stripHopByHop removes connection-scoped headers, including any header the
// Connection header nominates as connection-specific.
func stripHopByHop(header http.Header) {
	for _, nomination := range header.Values("Connection") {
		for _, name := range strings.Split(nomination, ",") {
			if name = strings.TrimSpace(name); name != "" {
				header.Del(name)
			}
		}
	}
	for _, name := range hopByHopHeaders {
		header.Del(name)
	}
}

// transportFailure maps a client error onto a gateway response.
func transportFailure(err error, service string, timeout time.Duration, elapsed time.Duration) (int, string, string) {
	// An oversized upload fails while the body is streamed to the upstream, so
	// it arrives here as a transport error rather than from the body-limit
	// stage. It is the caller's fault and no upstream was ever reached, so
	// blaming the upstream would misreport both the cause and the fix.
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		return http.StatusRequestEntityTooLarge, httpx.CodePayloadTooLarge,
			fmt.Sprintf("request body exceeds the %d byte limit", tooLarge.Limit)
	}
	if errors.Is(err, context.DeadlineExceeded) || isTimeout(err) {
		return http.StatusGatewayTimeout, httpx.CodeTimeout,
			fmt.Sprintf("upstream %q did not respond within %s", service, timeout)
	}
	if errors.Is(err, context.Canceled) {
		// The client hung up; there is nobody left to answer.
		return http.StatusServiceUnavailable, httpx.CodeServiceUnavail, "request cancelled by the client"
	}
	var netErr *net.OpError
	if errors.As(err, &netErr) {
		return http.StatusBadGateway, httpx.CodeBadGateway,
			fmt.Sprintf("cannot reach upstream %q after %s", service, elapsed.Round(time.Millisecond))
	}
	return http.StatusBadGateway, httpx.CodeBadGateway,
		fmt.Sprintf("upstream %q failed: %v", service, err)
}

func isTimeout(err error) bool {
	var netErr net.Error
	if errors.As(err, &netErr) {
		return netErr.Timeout()
	}
	return false
}

func schemeOf(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

// singleJoin concatenates two URL path fragments with exactly one separator.
func singleJoin(base, extra string) string {
	switch {
	case base == "" || base == "/":
		return extra
	case extra == "":
		return base
	default:
		return strings.TrimRight(base, "/") + "/" + strings.TrimLeft(extra, "/")
	}
}
