// Package auth authenticates gateway callers with one of three credential
// schemes: HS256 JSON Web Tokens, static API keys, and HMAC request
// signatures. All three are implemented on the standard library alone.
package auth

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/Inc-cryp/api-security-gateway/internal/httpx"
)

// Scheme names. These match the values accepted in a route's
// `authenticators` list.
const (
	SchemeJWT    = "jwt"
	SchemeAPIKey = "api_key"
	SchemeHMAC   = "hmac"
)

// Principal identifies the authenticated caller. It is an alias of
// httpx.Identity so that the middleware can place it on the request context
// without a conversion.
type Principal = httpx.Identity

// Verifier authenticates a single credential scheme.
type Verifier interface {
	// Scheme returns the scheme name this verifier handles.
	Scheme() string
	// Verify inspects r and returns the authenticated principal. A nil error
	// means the request presented a valid credential for this scheme.
	Verify(r *http.Request) (Principal, error)
}

// Authenticator dispatches to the configured verifiers.
type Authenticator struct {
	verifiers map[string]Verifier
	order     []string
}

// NewAuthenticator builds an Authenticator. Unknown scheme names are a
// configuration error rather than a silent no-op.
func NewAuthenticator(verifiers ...Verifier) (*Authenticator, error) {
	a := &Authenticator{verifiers: make(map[string]Verifier, len(verifiers))}
	for i, v := range verifiers {
		if v == nil {
			return nil, &httpx.ConfigError{Field: fmt.Sprintf("authenticators[%d]", i), Value: "nil", Err: errors.New("verifier must not be nil")}
		}
		scheme := strings.ToLower(strings.TrimSpace(v.Scheme()))
		if scheme == "" {
			return nil, &httpx.ConfigError{Field: fmt.Sprintf("authenticators[%d]", i), Value: "empty scheme name"}
		}
		if _, dup := a.verifiers[scheme]; dup {
			return nil, &httpx.ConfigError{Field: "authenticators", Value: scheme, Err: errors.New("duplicate scheme")}
		}
		a.verifiers[scheme] = v
		a.order = append(a.order, scheme)
	}
	if len(a.verifiers) == 0 {
		return nil, &httpx.ConfigError{Field: "authenticators", Value: "none configured"}
	}
	return a, nil
}

// Has reports whether a verifier for scheme is configured.
func (a *Authenticator) Has(scheme string) bool {
	if a == nil {
		return false
	}
	_, ok := a.verifiers[strings.ToLower(strings.TrimSpace(scheme))]
	return ok
}

// Schemes returns the configured scheme names in the order they are tried.
func (a *Authenticator) Schemes() []string {
	if a == nil {
		return nil
	}
	return append([]string(nil), a.order...)
}

// Authenticate tries the schemes named in allowed, in the order given. An
// empty allowed list means "try every configured verifier".
//
// The verifiers are attempted in sequence and the first success wins. When a
// verifier reports that the request carried no credential for its scheme at
// all, the next scheme is tried; a verifier that actively rejects a presented
// credential is treated as a hard failure so that a caller cannot bypass a
// scheme by supplying a malformed version of it alongside a valid one.
func (a *Authenticator) Authenticate(r *http.Request, allowed []string) (Principal, error) {
	if a == nil {
		return Principal{}, fmt.Errorf("%w: authenticator is not configured", httpx.ErrUnauthorized)
	}
	schemes := a.order
	if len(allowed) > 0 {
		schemes = make([]string, 0, len(allowed))
		for _, name := range allowed {
			name = strings.ToLower(strings.TrimSpace(name))
			if !a.Has(name) {
				return Principal{}, fmt.Errorf("%w: scheme %q is not configured", httpx.ErrUnauthorized, name)
			}
			schemes = append(schemes, name)
		}
	}

	var (
		lastErr error
		absent  = true
	)
	for _, scheme := range schemes {
		verifier := a.verifiers[scheme]
		if !presentsCredential(r, scheme) {
			continue
		}
		absent = false
		principal, err := verifier.Verify(r)
		if err == nil {
			return principal, nil
		}
		lastErr = err
	}
	if absent {
		return Principal{}, fmt.Errorf("%w: missing credentials", httpx.ErrUnauthorized)
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("%w: no acceptable credential was presented", httpx.ErrUnauthorized)
	}
	return Principal{}, lastErr
}

// presentsCredential reports whether r carries anything that looks like the
// named scheme's credential, so that "absent" and "rejected" stay distinct.
func presentsCredential(r *http.Request, scheme string) bool {
	switch scheme {
	case SchemeJWT:
		return strings.HasPrefix(strings.TrimSpace(r.Header.Get("Authorization")), "Bearer ")
	case SchemeAPIKey:
		return strings.TrimSpace(r.Header.Get("X-Api-Key")) != ""
	case SchemeHMAC:
		return strings.TrimSpace(r.Header.Get("X-Signature")) != "" || strings.TrimSpace(r.Header.Get("X-Client-Id")) != ""
	default:
		return false
	}
}
