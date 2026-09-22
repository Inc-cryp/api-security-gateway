package httpx

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"net/http"
	"strings"
)

type ctxKey int

const (
	ctxRequestID ctxKey = iota
	ctxPrincipal
	ctxClientIP
)

// RequestIDHeader is the header the gateway reads and writes for correlation.
const RequestIDHeader = "X-Request-Id"

// WithRequestID stores id on ctx.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, ctxRequestID, id)
}

// RequestID returns the request id carried by ctx, or "" when absent.
func RequestID(ctx context.Context) string {
	id, _ := ctx.Value(ctxRequestID).(string)
	return id
}

// NewRequestID returns a random 128-bit hex id. It falls back to a fixed
// marker only if the system entropy source fails, which keeps the request
// path non-fatal while making the failure visible in logs.
func NewRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "unavailable"
	}
	return hex.EncodeToString(b[:])
}

// Identity is the authenticated caller as carried on the request context.
type Identity struct {
	ClientID string
	Scheme   string
}

// String renders the identity for logs.
func (i Identity) String() string {
	if i.ClientID == "" {
		return ""
	}
	return i.Scheme + ":" + i.ClientID
}

// WithPrincipal stores the authenticated identity on ctx so the access log
// can attribute the request without re-running authentication.
func WithPrincipal(ctx context.Context, identity Identity) context.Context {
	return context.WithValue(ctx, ctxPrincipal, identity)
}

// PrincipalFrom returns the authenticated identity carried by ctx.
func PrincipalFrom(ctx context.Context) (Identity, bool) {
	identity, ok := ctx.Value(ctxPrincipal).(Identity)
	return identity, ok && identity.ClientID != ""
}

// WithClientIP stores the resolved caller address on ctx so later stages and
// the access log agree on who the caller is.
func WithClientIP(ctx context.Context, ip net.IP) context.Context {
	return context.WithValue(ctx, ctxClientIP, ip)
}

// ClientIP returns the caller address resolved for req.
//
// It prefers the value stored on the context by the client-IP middleware, so
// that every consumer sees the same answer the IP filter and the rate limiter
// used. Outside a gateway request it falls back to the socket peer address.
func ClientIP(req *http.Request) net.IP {
	if req == nil {
		return nil
	}
	if ip, ok := req.Context().Value(ctxClientIP).(net.IP); ok && ip != nil {
		return ip
	}
	return peerIP(req.RemoteAddr)
}

// ClientIPResolver derives the caller's address, trusting forwarded headers
// only from explicitly configured proxies. Trusting X-Forwarded-For
// unconditionally would let any client spoof its address and walk straight
// past the IP filter and the per-IP rate limit.
type ClientIPResolver struct {
	trusted []*net.IPNet
	header  string
}

// NewClientIPResolver builds a resolver from CIDR strings. An empty list
// means "trust nothing": only the socket peer address is ever used.
func NewClientIPResolver(trustedCIDRs []string, header string) (*ClientIPResolver, error) {
	r := &ClientIPResolver{header: strings.TrimSpace(header)}
	for _, cidr := range trustedCIDRs {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		_, block, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, &ConfigError{Field: "client_ip.trusted_proxies", Value: cidr, Err: err}
		}
		r.trusted = append(r.trusted, block)
	}
	return r, nil
}

// ClientIP returns the address the gateway should attribute the request to.
func (r *ClientIPResolver) ClientIP(req *http.Request) net.IP {
	if req == nil {
		return nil
	}
	peer := peerIP(req.RemoteAddr)
	if r == nil || r.header == "" || !r.isTrusted(peer) {
		return peer
	}
	// Walk the forwarded chain right-to-left and take the first address that
	// is not itself a trusted proxy. Everything to its left was supplied by
	// an untrusted hop and must be ignored.
	var hops []string
	for _, value := range req.Header.Values(r.header) {
		for _, part := range strings.Split(value, ",") {
			if part = strings.TrimSpace(part); part != "" {
				hops = append(hops, part)
			}
		}
	}
	for i := len(hops) - 1; i >= 0; i-- {
		ip := net.ParseIP(hops[i])
		if ip == nil || r.isTrusted(ip) {
			continue
		}
		return ip
	}
	return peer
}

func (r *ClientIPResolver) isTrusted(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, block := range r.trusted {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

func peerIP(remoteAddr string) net.IP {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	return net.ParseIP(strings.TrimSpace(host))
}
