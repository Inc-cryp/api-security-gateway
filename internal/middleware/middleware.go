// Package middleware assembles the gateway's request pipeline.
package middleware

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"github.com/Inc-cryp/api-security-gateway/internal/auth"
	"github.com/Inc-cryp/api-security-gateway/internal/config"
	"github.com/Inc-cryp/api-security-gateway/internal/httpx"
	"github.com/Inc-cryp/api-security-gateway/internal/logging"
	"github.com/Inc-cryp/api-security-gateway/internal/proxy"
	"github.com/Inc-cryp/api-security-gateway/internal/ratelimit"
	"github.com/Inc-cryp/api-security-gateway/internal/router"
)

// context keys used to carry per-request facts between stages.
type ctxKey int

const (
	routeKey ctxKey = iota
	statusKey
	errorKey
)

// Gateway is the assembled request handler.
type Gateway struct {
	router        *router.Router
	proxy         *proxy.Proxy
	authenticator *auth.Authenticator
	clientIP      *httpx.ClientIPResolver
	logger        *logging.Logger
	headers       map[string]string
	maxBodyBytes  int64
	limiters      map[string]*ratelimit.Limiter
	rateLimits    map[string]rateLimitSpec
}

type rateLimitSpec struct {
	rps   float64
	burst int
}

// requestState is the one piece of per-request state that flows *upward*.
//
// Every stage below accessLog derives a new request with r.WithContext and
// passes it down the chain, so a fact a stage records on its own context is
// visible only to that stage's callees. accessLog has to report the request
// id, the matched route and the authenticated principal after the chain
// returns, so those stages write into a shared holder instead of relying on
// context propagation back to the caller. The holder is per request and is
// only ever touched by the goroutine serving it.
type requestState struct {
	requestID    string
	route        *router.Route
	clientIP     net.IP
	principal    httpx.Identity
	hasPrincipal bool
}

type stateKey struct{}

func withState(ctx context.Context, state *requestState) context.Context {
	return context.WithValue(ctx, stateKey{}, state)
}

// stateFrom returns the holder accessLog installed, or nil when a stage is
// exercised directly by a test.
func stateFrom(ctx context.Context) *requestState {
	state, _ := ctx.Value(stateKey{}).(*requestState)
	return state
}

// Options carries everything the gateway needs to serve traffic.
type Options struct {
	Config        config.Config
	Router        *router.Router
	Proxy         *proxy.Proxy
	Authenticator *auth.Authenticator
	ClientIP      *httpx.ClientIPResolver
	Logger        *logging.Logger
}

// New assembles the middleware chain.
//
// The order is deliberate:
//
//	Recover -> AccessLog -> RequestID -> IPFilter -> RateLimit -> Route -> Auth -> Proxy
//
// Recover is outermost so a panic anywhere becomes a 500 instead of a dropped
// connection. AccessLog is next so it sees every outcome, including the ones
// produced by the stages inside it. IPFilter and RateLimit run before Auth so
// that rejecting an abusive caller costs a map lookup rather than a signature
// verification.
func New(opts Options) (*Gateway, error) {
	g := &Gateway{
		router:        opts.Router,
		proxy:         opts.Proxy,
		authenticator: opts.Authenticator,
		clientIP:      opts.ClientIP,
		logger:        opts.Logger,
		headers:       opts.Config.Headers,
		maxBodyBytes:  opts.Config.Server.MaxBodyBytes,
		limiters:      make(map[string]*ratelimit.Limiter),
		rateLimits:    make(map[string]rateLimitSpec),
	}
	for _, route := range g.router.Routes() {
		if route.RateLimit <= 0 {
			continue
		}
		limiter, err := ratelimit.New(route.RateLimit, route.RateBurst)
		if err != nil {
			return nil, err
		}
		g.limiters[route.Path] = limiter
		g.rateLimits[route.Path] = rateLimitSpec{rps: route.RateLimit, burst: route.RateBurst}
	}
	return g, nil
}

// Services returns the configured upstream service names, sorted. It exists
// so the start-up log can name what the gateway routes to.
func (g *Gateway) Services() []string { return g.proxy.Services() }

// ServeHTTP implements http.Handler.
func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.recoverPanic(w, r)
}

func (g *Gateway) recoverPanic(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if recovered := recover(); recovered != nil {
			g.logger.Slog().Error("panic while serving request",
				"panic", fmt.Sprint(recovered),
				"stack", string(debug.Stack()),
			)
			// The response may already be partially written; httpx.WriteError
			// is best-effort and will not corrupt a completed response.
			httpx.WriteError(w, g.logger.Slog(), http.StatusInternalServerError, httpx.CodeInternal, "internal error")
		}
	}()
	g.accessLog(w, r)
}

// accessLog records the outcome of every request exactly once.
func (g *Gateway) accessLog(w http.ResponseWriter, r *http.Request) {
	recorder := httpx.NewRecorder(w)
	// Operator-configured response headers are set here, before the chain
	// runs, so they land on every response the gateway produces — including a
	// rejection or a panic. Hardening headers such as X-Frame-Options or
	// Content-Security-Policy protect the error page just as much as the
	// success page, so they must not depend on the request reaching the
	// upstream.
	for name, value := range g.headers {
		recorder.Header().Set(name, value)
	}
	started := time.Now()
	// The holder is installed before the first stage runs so every stage can
	// write to it on the way down.
	state := &requestState{}
	g.requestID(recorder, r.WithContext(withState(r.Context(), state)))

	status, err := httpx.StatusFrom(recorder), httpx.ErrorFrom(recorder)

	entry := logging.Record{
		Method:    r.Method,
		Path:      r.URL.Path,
		Query:     r.URL.RawQuery,
		UserAgent: r.UserAgent(),
		RequestID: state.requestID,
		Status:    status,
		Bytes:     recorder.Written(),
		Duration:  time.Since(started),
	}
	if state.route != nil {
		entry.Route = state.route.Path
		entry.Service = state.route.Service
	}
	if state.clientIP != nil {
		entry.ClientIP = state.clientIP.String()
	}
	if state.hasPrincipal {
		entry.Principal = state.principal.Scheme + ":" + state.principal.ClientID
	}
	if err != nil {
		entry.Error = err.Error()
	}
	g.logger.Access(r.Context(), entry)
}

// requestID continues an inbound correlation id or mints a new one.
func (g *Gateway) requestID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.Header.Get(httpx.RequestIDHeader))
	if id == "" || len(id) > 128 {
		id = httpx.NewRequestID()
	} else {
		id = sanitizeHeaderValue(id)
	}
	w.Header().Set(httpx.RequestIDHeader, id)
	if state := stateFrom(r.Context()); state != nil {
		state.requestID = id
	}
	g.ipFilter(w, r.WithContext(httpx.WithRequestID(r.Context(), id)))
}

// ipFilter derives the client address and resolves the route.
//
// The route is resolved here rather than later because both the IP rules and
// the rate limit key are per route.
func (g *Gateway) ipFilter(w http.ResponseWriter, r *http.Request) {
	ip := g.clientIP.ClientIP(r)
	r = r.WithContext(httpx.WithClientIP(r.Context(), ip))
	if state := stateFrom(r.Context()); state != nil {
		state.clientIP = ip
	}

	route := g.router.Match(r.URL.Path)
	if route == nil {
		httpx.WriteError(w, g.logger.Slog(), http.StatusNotFound, httpx.CodeNotFound, "no route matches this path")
		httpx.RecordError(w, httpx.ErrNotFound)
		return
	}
	r = r.WithContext(withRoute(r.Context(), route))
	if state := stateFrom(r.Context()); state != nil {
		state.route = route
	}

	if !route.AllowsIP(ip) {
		httpx.WriteError(w, g.logger.Slog(), http.StatusForbidden, httpx.CodeForbidden, "client address is not permitted")
		httpx.RecordError(w, httpx.ErrForbidden)
		return
	}
	g.rateLimit(w, r, route, ip)
}

// rateLimit applies the route's token bucket, keyed by client address.
func (g *Gateway) rateLimit(w http.ResponseWriter, r *http.Request, route *router.Route, ip net.IP) {
	limiter, limited := g.limiters[route.Path]
	if !limited {
		g.bodyLimit(w, r, route)
		return
	}
	key := "anonymous"
	if ip != nil {
		key = ip.String()
	}
	if !limiter.Allow(key) {
		retry := limiter.RetryAfter(key)
		seconds := int(retry.Seconds())
		if retry > 0 && seconds == 0 {
			seconds = 1
		}
		if seconds > 0 {
			w.Header().Set("Retry-After", fmt.Sprint(seconds))
		}
		w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", g.rateLimits[route.Path].burst))
		httpx.WriteError(w, g.logger.Slog(), http.StatusTooManyRequests, httpx.CodeRateLimited, "rate limit exceeded")
		httpx.RecordError(w, httpx.ErrRateLimited)
		return
	}
	g.bodyLimit(w, r, route)
}

// bodyLimit caps the request body and rejects methods the route excludes.
func (g *Gateway) bodyLimit(w http.ResponseWriter, r *http.Request, route *router.Route) {
	if !route.AllowsMethod(r.Method) {
		w.Header().Set("Allow", allowHeader(route))
		httpx.WriteError(w, g.logger.Slog(), http.StatusMethodNotAllowed, httpx.CodeMethodNotAllowed, "method not allowed for this route")
		httpx.RecordError(w, httpx.ErrMethodNotAllowed)
		return
	}
	// MaxBytesReader both caps the body and tells the upstream reader that the
	// limit was hit, so an oversized upload fails fast instead of being
	// buffered.
	if g.maxBodyBytes > 0 && r.Body != nil {
		r.Body = http.MaxBytesReader(w, r.Body, g.maxBodyBytes)
	}
	g.authenticate(w, r, route)
}

// authenticate enforces the route's credential requirements.
func (g *Gateway) authenticate(w http.ResponseWriter, r *http.Request, route *router.Route) {
	principal, err := g.authenticator.Authenticate(r, route.Authenticators)
	if err != nil {
		// The client address is named in the log line, but the reason a
		// credential failed is never echoed back: that would turn the gateway
		// into an oracle for guessing keys and signatures.
		httpx.WriteError(w, g.logger.Slog(), http.StatusUnauthorized, httpx.CodeUnauthorized, "authentication failed")
		httpx.RecordError(w, err)
		return
	}
	if state := stateFrom(r.Context()); state != nil {
		state.principal = principal
		state.hasPrincipal = true
	}
	g.proxyRequest(w, r.WithContext(httpx.WithPrincipal(r.Context(), principal)), route)
}

// proxyRequest forwards the request and records the upstream status.
func (g *Gateway) proxyRequest(w http.ResponseWriter, r *http.Request, route *router.Route) {
	status, err := g.proxy.Serve(w, r, route)
	if err != nil {
		httpx.RecordError(w, err)
	}
	if status > 0 {
		httpx.RecordStatus(w, status)
	}
}

func allowHeader(route *router.Route) string {
	if len(route.Methods) == 0 {
		return ""
	}
	return strings.Join(route.Methods, ", ")
}

// sanitizeHeaderValue strips anything that could break a response header or
// split it into a second one.
func sanitizeHeaderValue(value string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, value)
}

func withRoute(ctx context.Context, route *router.Route) context.Context {
	return context.WithValue(ctx, routeKey, route)
}

func routeFromContext(ctx context.Context) *router.Route {
	route, _ := ctx.Value(routeKey).(*router.Route)
	return route
}
