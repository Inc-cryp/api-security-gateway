package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Inc-cryp/api-security-gateway/internal/httpx"
)

const testSecret = "test-secret-at-least-16-bytes"

// signHS256 builds a token with the given header and claims.
func signHS256(t *testing.T, secret string, header map[string]any, claims map[string]any) string {
	t.Helper()
	encode := func(v any) string {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshalling segment: %v", err)
		}
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	signingInput := encode(header) + "." + encode(claims)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func requestWithToken(token string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/account/1", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	return r
}

func TestJWTVerifierAcceptsValidToken(t *testing.T) {
	verifier, err := NewJWTVerifier(JWTConfig{Secret: testSecret})
	if err != nil {
		t.Fatalf("NewJWTVerifier: %v", err)
	}
	token := signHS256(t,
		testSecret,
		map[string]any{"alg": "HS256", "typ": "JWT"},
		map[string]any{"sub": "client-1", "exp": time.Now().Add(time.Hour).Unix()},
	)
	principal, err := verifier.Verify(requestWithToken(token))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if principal.ClientID != "client-1" {
		t.Fatalf("ClientID = %q, want client-1", principal.ClientID)
	}
	if principal.Scheme != SchemeJWT {
		t.Fatalf("Scheme = %q, want %q", principal.Scheme, SchemeJWT)
	}
}

// TestJWTVerifierRejectsAlgorithmSubstitution covers the classic JWT attack:
// a token that announces a different algorithm in its header. The verifier
// must decide the algorithm itself, so `none` and the asymmetric families are
// all rejected regardless of how plausible the token looks.
func TestJWTVerifierRejectsAlgorithmSubstitution(t *testing.T) {
	verifier, err := NewJWTVerifier(JWTConfig{Secret: testSecret})
	if err != nil {
		t.Fatalf("NewJWTVerifier: %v", err)
	}
	claims := map[string]any{"sub": "attacker", "exp": time.Now().Add(time.Hour).Unix()}
	for _, alg := range []string{"none", "None", "NONE", "RS256", "ES256", "HS384", "HS512"} {
		t.Run(alg, func(t *testing.T) {
			token := signHS256(t, testSecret, map[string]any{"alg": alg, "typ": "JWT"}, claims)
			if _, err := verifier.Verify(requestWithToken(token)); err == nil {
				t.Fatalf("token with alg=%q was accepted", alg)
			} else if !errors.Is(err, httpx.ErrUnauthorized) {
				t.Fatalf("error = %v, want ErrUnauthorized", err)
			}
		})
	}
}

// TestJWTVerifierRejectsUnsignedTokenWithNoneHeader is the `alg: none` token
// an attacker can mint without any secret at all.
func TestJWTVerifierRejectsUnsignedTokenWithNoneHeader(t *testing.T) {
	verifier, err := NewJWTVerifier(JWTConfig{Secret: testSecret})
	if err != nil {
		t.Fatalf("NewJWTVerifier: %v", err)
	}
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	claims := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"attacker"}`))
	token := header + "." + claims + "."
	if _, err := verifier.Verify(requestWithToken(token)); err == nil {
		t.Fatal("unsigned token was accepted")
	}
}

func TestJWTVerifierRejectsBadSignature(t *testing.T) {
	verifier, err := NewJWTVerifier(JWTConfig{Secret: testSecret})
	if err != nil {
		t.Fatalf("NewJWTVerifier: %v", err)
	}
	token := signHS256(t, "a-different-secret-entirely",
		map[string]any{"alg": "HS256"},
		map[string]any{"sub": "client-1"},
	)
	if _, err := verifier.Verify(requestWithToken(token)); !errors.Is(err, httpx.ErrUnauthorized) {
		t.Fatalf("error = %v, want ErrUnauthorized", err)
	}
}

func TestJWTVerifierClaimChecks(t *testing.T) {
	now := time.Now()
	verifier, err := NewJWTVerifier(JWTConfig{
		Secret:    testSecret,
		Issuer:    "issuer-a",
		Audience:  "audience-a",
		ClockSkew: time.Minute,
	})
	if err != nil {
		t.Fatalf("NewJWTVerifier: %v", err)
	}
	tests := []struct {
		name    string
		claims  map[string]any
		wantErr bool
	}{
		{
			name:   "all claims valid",
			claims: map[string]any{"sub": "c", "iss": "issuer-a", "aud": "audience-a", "exp": now.Add(time.Hour).Unix()},
		},
		{
			name:   "audience as array",
			claims: map[string]any{"sub": "c", "iss": "issuer-a", "aud": []string{"other", "audience-a"}, "exp": now.Add(time.Hour).Unix()},
		},
		{
			name:    "expired beyond skew",
			claims:  map[string]any{"sub": "c", "iss": "issuer-a", "aud": "audience-a", "exp": now.Add(-2 * time.Minute).Unix()},
			wantErr: true,
		},
		{
			name:   "expired within skew",
			claims: map[string]any{"sub": "c", "iss": "issuer-a", "aud": "audience-a", "exp": now.Add(-30 * time.Second).Unix()},
		},
		{
			name:    "not yet valid beyond skew",
			claims:  map[string]any{"sub": "c", "iss": "issuer-a", "aud": "audience-a", "nbf": now.Add(2 * time.Minute).Unix()},
			wantErr: true,
		},
		{
			name:    "wrong issuer",
			claims:  map[string]any{"sub": "c", "iss": "issuer-b", "aud": "audience-a"},
			wantErr: true,
		},
		{
			name:    "wrong audience",
			claims:  map[string]any{"sub": "c", "iss": "issuer-a", "aud": "audience-b"},
			wantErr: true,
		},
		{
			name:    "missing subject",
			claims:  map[string]any{"iss": "issuer-a", "aud": "audience-a"},
			wantErr: true,
		},
		{
			name:    "non-integer exp",
			claims:  map[string]any{"sub": "c", "exp": "soon"},
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			token := signHS256(t, testSecret, map[string]any{"alg": "HS256"}, tc.claims)
			_, err := verifier.Verify(requestWithToken(token))
			if tc.wantErr && err == nil {
				t.Fatal("token was accepted, want rejection")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("token was rejected: %v", err)
			}
		})
	}
}

func TestJWTVerifierMalformedInput(t *testing.T) {
	verifier, err := NewJWTVerifier(JWTConfig{Secret: testSecret})
	if err != nil {
		t.Fatalf("NewJWTVerifier: %v", err)
	}
	tests := []struct {
		name   string
		header string
	}{
		{"missing header", ""},
		{"wrong scheme", "Basic " + base64.StdEncoding.EncodeToString([]byte("user:pass"))},
		{"bearer with no token", "Bearer "},
		{"two segments", "Bearer aaa.bbb"},
		{"non-base64 header", "Bearer !!!.bbb.ccc"},
		{"valid signature over non-JSON header", "Bearer " + func() string {
			header := base64.RawURLEncoding.EncodeToString([]byte("not json"))
			payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"c"}`))
			mac := hmac.New(sha256.New, []byte(testSecret))
			mac.Write([]byte(header + "." + payload))
			return header + "." + payload + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
		}()},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.header != "" {
				r.Header.Set("Authorization", tc.header)
			}
			if _, err := verifier.Verify(r); !errors.Is(err, httpx.ErrUnauthorized) {
				t.Fatalf("error = %v, want ErrUnauthorized", err)
			}
		})
	}
}

func TestNewJWTVerifierRejectsWeakConfig(t *testing.T) {
	tests := []struct {
		name        string
		cfg         JWTConfig
		secretField bool
	}{
		{"empty secret", JWTConfig{}, true},
		{"short secret", JWTConfig{Secret: "tooshort"}, true},
		{"negative skew", JWTConfig{Secret: testSecret, ClockSkew: -time.Second}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewJWTVerifier(tc.cfg)
			if err == nil {
				t.Fatal("expected a configuration error")
			}
			var cfgErr *httpx.ConfigError
			if !errors.As(err, &cfgErr) {
				t.Fatalf("error = %T, want *httpx.ConfigError", err)
			}
			// A rejected secret must never be echoed back: the error text ends
			// up in logs and terminals.
			if tc.secretField {
				if tc.cfg.Secret != "" && strings.Contains(cfgErr.Error(), tc.cfg.Secret) {
					t.Fatalf("secret leaked in error message: %q", cfgErr.Error())
				}
				if !strings.Contains(cfgErr.Error(), "***") {
					t.Fatalf("error does not mark the secret as redacted: %q", cfgErr.Error())
				}
			}
		})
	}
}
