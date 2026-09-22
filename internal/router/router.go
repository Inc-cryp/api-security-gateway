// Package router maps request paths to upstream services.
package router

import (
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/Inc-cryp/api-security-gateway/internal/httpx"
	"github.com/Inc-cryp/api-security-gateway/internal/ipfilter"
)

// Route is one compiled routing rule.
type Route struct {
	// Path is the prefix the rule matches, always starting with "/".
	Path string
	// Service names the upstream the request is forwarded to.
	Service string
	// Authenticators restricts which credential schemes are accepted.
	// Empty means "any configured scheme".
	Authenticators []string
	// Methods restricts the accepted HTTP methods. Empty means "any".
	Methods []string
	// StripPrefix removes Path from the forwarded URL.
	StripPrefix bool
	// Timeout overrides the upstream timeout for this route. Zero means the
	// upstream default applies.
	Timeout time.Duration
	// RateLimit is the sustained per-second allowance for this route, and
	// RateBurst its bucket size. Zero disables limiting for the route.
	RateLimit float64
	RateBurst int
	// AllowedIPs and DeniedIPs restrict the caller's address.
	AllowedIPs []string
	DeniedIPs  []string

	methods map[string]bool
	filter  *ipfilter.Filter
}

// Router resolves a request path to a Route.
type Router struct {
	// routes is sorted by descending path length so the first match is the
	// longest one.
	routes []*Route
}

// New compiles routes into a Router. Routes are matched on segment
// boundaries, so "/account" matches "/account" and "/account/x" but never
// "/accounting".
func New(routes []*Route) (*Router, error) {
	compiled := make([]*Route, 0, len(routes))
	seen := make(map[string]bool, len(routes))
	for i, route := range routes {
		if route == nil {
			return nil, &httpx.ConfigError{Field: fmt.Sprintf("routes[%d]", i), Value: "nil route"}
		}
		path := route.Path
		if path == "" || !strings.HasPrefix(path, "/") {
			return nil, &httpx.ConfigError{Field: fmt.Sprintf("routes[%d].path", i), Value: path, Err: fmt.Errorf("must start with /")}
		}
		if seen[path] {
			return nil, &httpx.ConfigError{Field: fmt.Sprintf("routes[%d].path", i), Value: path, Err: fmt.Errorf("duplicate route path")}
		}
		seen[path] = true
		if strings.TrimSpace(route.Service) == "" {
			return nil, &httpx.ConfigError{Field: fmt.Sprintf("routes[%d].service", i), Value: ""}
		}
		if route.Timeout < 0 {
			return nil, &httpx.ConfigError{Field: fmt.Sprintf("routes[%d].timeout", i), Value: route.Timeout.String()}
		}
		filter, err := ipfilter.New(route.AllowedIPs, route.DeniedIPs)
		if err != nil {
			return nil, err
		}
		route.filter = filter
		if len(route.Methods) > 0 {
			route.methods = make(map[string]bool, len(route.Methods))
			for _, method := range route.Methods {
				route.methods[strings.ToUpper(strings.TrimSpace(method))] = true
			}
		}
		// Normalize trailing slashes except for the root route, so "/account/"
		// and "/account" behave the same.
		if len(path) > 1 {
			route.Path = strings.TrimRight(path, "/")
		}
		compiled = append(compiled, route)
	}
	sort.SliceStable(compiled, func(i, j int) bool {
		return len(compiled[i].Path) > len(compiled[j].Path)
	})
	return &Router{routes: compiled}, nil
}

// Match returns the route serving path, or nil when nothing matches. The
// comparison is on segment boundaries, so a prefix never matches inside a
// longer segment.
func (r *Router) Match(path string) *Route {
	if r == nil {
		return nil
	}
	if path == "" {
		path = "/"
	}
	if len(path) > 1 {
		path = strings.TrimRight(path, "/")
		if path == "" {
			path = "/"
		}
	}
	for _, route := range r.routes {
		if route.Path == "/" {
			return route
		}
		if path == route.Path {
			return route
		}
		if strings.HasPrefix(path, route.Path) && strings.HasPrefix(path[len(route.Path):], "/") {
			return route
		}
	}
	return nil
}

// Routes returns the compiled routes, longest prefix first.
func (r *Router) Routes() []*Route {
	if r == nil {
		return nil
	}
	return append([]*Route(nil), r.routes...)
}

// AllowsMethod reports whether the route accepts method. A route with no
// method list accepts every method.
func (r *Route) AllowsMethod(method string) bool {
	if len(r.methods) == 0 {
		return true
	}
	if r.methods[strings.ToUpper(method)] {
		return true
	}
	// HEAD is served by the GET handler unless the route explicitly says
	// otherwise, which is what net/http itself does.
	return method == http.MethodHead && r.methods[http.MethodGet]
}

// AllowsIP reports whether ip may reach this route.
func (r *Route) AllowsIP(ip net.IP) bool { return r.filter.Allowed(ip) }

// ForwardPath returns the path to send upstream after prefix stripping.
func (r *Route) ForwardPath(path string) string {
	if !r.StripPrefix {
		if path == "" {
			return "/"
		}
		return path
	}
	out := strings.TrimPrefix(path, r.Path)
	if out == "" {
		return "/"
	}
	if !strings.HasPrefix(out, "/") {
		out = "/" + out
	}
	return out
}
