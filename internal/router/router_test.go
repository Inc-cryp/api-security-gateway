package router

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/Inc-cryp/api-security-gateway/internal/httpx"
)

// --- New ------------------------------------------------------------------

func TestNewCompilesRoutes(t *testing.T) {
	r, err := New([]*Route{
		{Path: "/account", Service: "account"},
		{Path: "/transfer", Service: "transfer", Methods: []string{"post", " get "}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := len(r.Routes()); got != 2 {
		t.Fatalf("Routes() len = %d, want 2", got)
	}
}

func TestNewSortsLongestPrefixFirst(t *testing.T) {
	// Routes are given shortest-first on purpose: if New sorted by arrival
	// order, Match("/account/statement") would return the "/account" rule.
	r, err := New([]*Route{
		{Path: "/account", Service: "account"},
		{Path: "/account/statement", Service: "statement"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got := r.Routes()
	if len(got) != 2 {
		t.Fatalf("Routes() len = %d, want 2", len(got))
	}
	if got[0].Path != "/account/statement" {
		t.Fatalf("Routes()[0].Path = %q, want the longest prefix first", got[0].Path)
	}
	if match := r.Match("/account/statement/2026"); match == nil || match.Service != "statement" {
		t.Fatalf("Match = %v, want the /account/statement route", match)
	}
}

func TestNewRejectsBadRoutes(t *testing.T) {
	tests := []struct {
		name  string
		route *Route
		field string
	}{
		{"nil route", nil, "routes[0]"},
		{"empty path", &Route{Path: "", Service: "s"}, "routes[0].path"},
		{"path without slash", &Route{Path: "account", Service: "s"}, "routes[0].path"},
		{"empty service", &Route{Path: "/a", Service: "   "}, "routes[0].service"},
		{"negative timeout", &Route{Path: "/a", Service: "s", Timeout: -time.Second}, "routes[0].timeout"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New([]*Route{tt.route})
			if err == nil {
				t.Fatalf("New accepted an invalid route")
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

func TestNewRejectsDuplicatePath(t *testing.T) {
	_, err := New([]*Route{
		{Path: "/account", Service: "account"},
		{Path: "/account", Service: "other"},
	})
	var cfgErr *httpx.ConfigError
	if !errors.As(err, &cfgErr) {
		t.Fatalf("err = %T (%v), want *httpx.ConfigError", err, err)
	}
	if cfgErr.Field != "routes[1].path" {
		t.Fatalf("ConfigError.Field = %q, want routes[1].path", cfgErr.Field)
	}
}

func TestNewPropagatesIPFilterError(t *testing.T) {
	_, err := New([]*Route{{Path: "/a", Service: "s", AllowedIPs: []string{"not-an-ip"}}})
	var cfgErr *httpx.ConfigError
	if !errors.As(err, &cfgErr) {
		t.Fatalf("err = %T (%v), want *httpx.ConfigError", err, err)
	}
	if cfgErr.Field != "allowed_ips[0]" {
		t.Fatalf("ConfigError.Field = %q, want allowed_ips[0]", cfgErr.Field)
	}
}

func TestNewReportsTheFailingIndex(t *testing.T) {
	// The index in the field name must reflect the caller's slice, not the
	// position among valid routes.
	_, err := New([]*Route{
		{Path: "/a", Service: "s"},
		{Path: "/b", Service: "s"},
		{Path: "", Service: "s"},
	})
	var cfgErr *httpx.ConfigError
	if !errors.As(err, &cfgErr) {
		t.Fatalf("err = %T (%v), want *httpx.ConfigError", err, err)
	}
	if cfgErr.Field != "routes[2].path" {
		t.Fatalf("ConfigError.Field = %q, want routes[2].path", cfgErr.Field)
	}
}

// --- Match ----------------------------------------------------------------

func TestMatchUsesSegmentBoundaries(t *testing.T) {
	r, err := New([]*Route{{Path: "/account", Service: "account"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	tests := []struct {
		path string
		want bool
	}{
		{"/account", true},
		{"/account/", true},
		{"/account/123", true},
		{"/accounting", false},
		{"/account-x", false},
		{"/", false},
		{"/other", false},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := r.Match(tt.path) != nil
			if got != tt.want {
				t.Fatalf("Match(%q) matched = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestMatchReturnsNilWhenNothingMatches(t *testing.T) {
	r, err := New([]*Route{{Path: "/account", Service: "account"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if match := r.Match("/nope"); match != nil {
		t.Fatalf("Match(/nope) = %+v, want nil", match)
	}
}

func TestRoutesReturnsACopy(t *testing.T) {
	r, err := New([]*Route{{Path: "/account", Service: "account"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got := r.Routes()
	got[0] = nil
	if r.Routes()[0] == nil {
		t.Fatalf("Routes() exposed the internal slice: mutating the result changed the router")
	}
}

// --- AllowsMethod ---------------------------------------------------------

func TestAllowsMethodWithNoMethodList(t *testing.T) {
	route := &Route{Path: "/a", Service: "s"}
	for _, method := range []string{"GET", "POST", "DELETE", "PATCH", "HEAD", ""} {
		if !route.AllowsMethod(method) {
			t.Fatalf("AllowsMethod(%q) = false, want true for a route with no method list", method)
		}
	}
}

func TestAllowsMethodHonoursTheDeclaredList(t *testing.T) {
	r, err := New([]*Route{{Path: "/a", Service: "s", Methods: []string{"POST"}}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	route := r.Routes()[0]
	if !route.AllowsMethod("POST") {
		t.Fatalf("AllowsMethod(POST) = false, want true")
	}
	if !route.AllowsMethod("post") {
		t.Fatalf("AllowsMethod(post) = false, want the comparison to be case-insensitive")
	}
	if route.AllowsMethod("GET") {
		t.Fatalf("AllowsMethod(GET) = true, want false")
	}
	// HEAD must NOT be allowed where GET was never declared: nothing will
	// serve it.
	if route.AllowsMethod("HEAD") {
		t.Fatalf("AllowsMethod(HEAD) = true for a POST-only route, want false")
	}
}

func TestAllowsMethodServesHeadFromGet(t *testing.T) {
	r, err := New([]*Route{{Path: "/a", Service: "s", Methods: []string{"GET"}}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	route := r.Routes()[0]
	if !route.AllowsMethod("HEAD") {
		t.Fatalf("AllowsMethod(HEAD) = false, want true when GET is declared")
	}
	if !route.AllowsMethod("GET") {
		t.Fatalf("AllowsMethod(GET) = false, want true")
	}
}

// --- AllowsIP -------------------------------------------------------------

func TestAllowsIPWithoutRules(t *testing.T) {
	r, err := New([]*Route{{Path: "/a", Service: "s"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !r.Routes()[0].AllowsIP(net.ParseIP("203.0.113.9")) {
		t.Fatalf("AllowsIP = false, want true when the route has no IP rules")
	}
}

func TestAllowsIPAllowListRejectsUnlisted(t *testing.T) {
	r, err := New([]*Route{{Path: "/a", Service: "s", AllowedIPs: []string{"10.0.0.0/8"}}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	route := r.Routes()[0]
	if !route.AllowsIP(net.ParseIP("10.1.2.3")) {
		t.Fatalf("AllowsIP(10.1.2.3) = false, want true")
	}
	if route.AllowsIP(net.ParseIP("192.168.1.1")) {
		t.Fatalf("AllowsIP(192.168.1.1) = true, want false: a non-empty allow list rejects unmatched addresses")
	}
}

func TestAllowsIPDenyWins(t *testing.T) {
	r, err := New([]*Route{{
		Path:       "/a",
		Service:    "s",
		AllowedIPs: []string{"10.0.0.0/8"},
		DeniedIPs:  []string{"10.0.0.7"},
	}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	route := r.Routes()[0]
	if route.AllowsIP(net.ParseIP("10.0.0.7")) {
		t.Fatalf("AllowsIP(10.0.0.7) = true, want false: deny wins")
	}
	if !route.AllowsIP(net.ParseIP("10.0.0.8")) {
		t.Fatalf("AllowsIP(10.0.0.8) = false, want true")
	}
}

func TestAllowsIPFoldsIPv4InIPv6(t *testing.T) {
	// A v4-mapped literal must still match a v4 network; without normalisation
	// the denylist would be trivially bypassed.
	r, err := New([]*Route{{Path: "/a", Service: "s", DeniedIPs: []string{"10.0.0.7"}}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if r.Routes()[0].AllowsIP(net.ParseIP("::ffff:10.0.0.7")) {
		t.Fatalf("AllowsIP(::ffff:10.0.0.7) = true, want false")
	}
}

// --- ForwardPath ----------------------------------------------------------

func TestForwardPathKeepsThePath(t *testing.T) {
	r, err := New([]*Route{{Path: "/account", Service: "s"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	route := r.Routes()[0]
	tests := []struct{ in, want string }{
		{"/account/123", "/account/123"},
		{"/account", "/account"},
		{"", "/"},
	}
	for _, tt := range tests {
		if got := route.ForwardPath(tt.in); got != tt.want {
			t.Fatalf("ForwardPath(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestForwardPathStripsPrefix(t *testing.T) {
	r, err := New([]*Route{{Path: "/api/account", Service: "s", StripPrefix: true}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	route := r.Routes()[0]
	tests := []struct{ in, want string }{
		{"/api/account", "/"},
		{"/api/account/", "/"},
		{"/api/account/123", "/123"},
		{"/api/accounting", "/ing"},
		{"/nothing", "/nothing"},
	}
	for _, tt := range tests {
		if got := route.ForwardPath(tt.in); got != tt.want {
			t.Fatalf("ForwardPath(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
