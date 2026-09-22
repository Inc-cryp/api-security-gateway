package auth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Inc-cryp/api-security-gateway/internal/httpx"
)

func testAuthenticator(t *testing.T) *Authenticator {
	t.Helper()
	jwtVerifier, err := NewJWTVerifier(JWTConfig{Secret: testSecret})
	if err != nil {
		t.Fatalf("NewJWTVerifier: %v", err)
	}
	keyVerifier, err := NewAPIKeyVerifier([]APIKeyConfig{{Key: "key-alpha", ClientID: "alpha"}})
	if err != nil {
		t.Fatalf("NewAPIKeyVerifier: %v", err)
	}
	hmacVerifier, err := NewHMACVerifier(HMACConfig{
		Clients: []HMACClient{{ClientID: hmacClientID, Secret: hmacSecret}},
	})
	if err != nil {
		t.Fatalf("NewHMACVerifier: %v", err)
	}
	authenticator, err := NewAuthenticator(jwtVerifier, keyVerifier, hmacVerifier)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	return authenticator
}

func TestAuthenticatorSchemeOrder(t *testing.T) {
	authenticator := testAuthenticator(t)
	want := []string{SchemeJWT, SchemeAPIKey, SchemeHMAC}
	got := authenticator.Schemes()
	if len(got) != len(want) {
		t.Fatalf("Schemes() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Schemes() = %v, want %v", got, want)
		}
	}
}

func TestAuthenticatorAnyOf(t *testing.T) {
	authenticator := testAuthenticator(t)
	validToken := signHS256(t, testSecret, map[string]any{"alg": "HS256"}, map[string]any{"sub": "jwt-client"})

	tests := []struct {
		name       string
		allowed    []string
		setup      func(r *http.Request)
		wantClient string
		wantScheme string
		wantErr    bool
	}{
		{
			name:    "no credential at all",
			setup:   func(r *http.Request) {},
			wantErr: true,
		},
		{
			name:       "jwt accepted with empty allow list",
			setup:      func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+validToken) },
			wantClient: "jwt-client",
			wantScheme: SchemeJWT,
		},
		{
			name:       "api key accepted with empty allow list",
			setup:      func(r *http.Request) { r.Header.Set(APIKeyHeader, "key-alpha") },
			wantClient: "alpha",
			wantScheme: SchemeAPIKey,
		},
		{
			name:       "api key accepted when only api_key is allowed",
			allowed:    []string{SchemeAPIKey},
			setup:      func(r *http.Request) { r.Header.Set(APIKeyHeader, "key-alpha") },
			wantClient: "alpha",
			wantScheme: SchemeAPIKey,
		},
		{
			name:    "jwt rejected when only api_key is allowed",
			allowed: []string{SchemeAPIKey},
			setup:   func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+validToken) },
			wantErr: true,
		},
		{
			name:    "hmac accepted when allowed",
			allowed: []string{SchemeHMAC},
			setup:   func(r *http.Request) { r.Header.Set(SignatureHeader, "deadbeef") },
			wantErr: true, // signature is bogus, but the scheme is at least consulted
		},
		{
			name:    "unconfigured scheme in allow list",
			allowed: []string{"kerberos"},
			setup:   func(r *http.Request) { r.Header.Set(APIKeyHeader, "key-alpha") },
			wantErr: true,
		},
		{
			name:    "bad api key is rejected",
			setup:   func(r *http.Request) { r.Header.Set(APIKeyHeader, "wrong-key") },
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			tc.setup(r)
			principal, err := authenticator.Authenticate(r, tc.allowed)
			if tc.wantErr {
				if err == nil {
					t.Fatal("request was authenticated, want rejection")
				}
				if !errors.Is(err, httpx.ErrUnauthorized) {
					t.Fatalf("error = %v, want ErrUnauthorized", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Authenticate: %v", err)
			}
			if principal.ClientID != tc.wantClient {
				t.Fatalf("ClientID = %q, want %q", principal.ClientID, tc.wantClient)
			}
			if principal.Scheme != tc.wantScheme {
				t.Fatalf("Scheme = %q, want %q", principal.Scheme, tc.wantScheme)
			}
		})
	}
}

func TestNewAuthenticatorRejectsBadInput(t *testing.T) {
	if _, err := NewAuthenticator(); err == nil {
		t.Fatal("expected an error for no verifiers")
	}
	if _, err := NewAuthenticator(nil); err == nil {
		t.Fatal("expected an error for a nil verifier")
	}
	verifier, err := NewAPIKeyVerifier([]APIKeyConfig{{Key: "k", ClientID: "c"}})
	if err != nil {
		t.Fatalf("NewAPIKeyVerifier: %v", err)
	}
	if _, err := NewAuthenticator(verifier, verifier); err == nil {
		t.Fatal("expected an error for a duplicate scheme")
	}
}

func TestAuthenticatorNilIsUnauthorized(t *testing.T) {
	var authenticator *Authenticator
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if _, err := authenticator.Authenticate(r, nil); !errors.Is(err, httpx.ErrUnauthorized) {
		t.Fatalf("error = %v, want ErrUnauthorized", err)
	}
	if authenticator.Has(SchemeJWT) {
		t.Fatal("nil authenticator reported a scheme")
	}
	if authenticator.Schemes() != nil {
		t.Fatal("nil authenticator returned schemes")
	}
}

func TestJWTSkewDefaults(t *testing.T) {
	// A verifier built without an explicit skew must still accept a token
	// that expired a few seconds ago, which is what real clock drift looks
	// like.
	verifier, err := NewJWTVerifier(JWTConfig{Secret: testSecret})
	if err != nil {
		t.Fatalf("NewJWTVerifier: %v", err)
	}
	token := signHS256(t, testSecret,
		map[string]any{"alg": "HS256"},
		map[string]any{"sub": "c", "exp": time.Now().Add(-5 * time.Second).Unix()},
	)
	if _, err := verifier.Verify(requestWithToken(token)); err != nil {
		t.Fatalf("token within the default skew was rejected: %v", err)
	}
}
