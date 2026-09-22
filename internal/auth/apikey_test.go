package auth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Inc-cryp/api-security-gateway/internal/httpx"
)

func TestAPIKeyVerifier(t *testing.T) {
	verifier, err := NewAPIKeyVerifier([]APIKeyConfig{
		{Key: "key-alpha", ClientID: "alpha"},
		{Key: "key-beta-value", ClientID: "beta"},
	})
	if err != nil {
		t.Fatalf("NewAPIKeyVerifier: %v", err)
	}
	tests := []struct {
		name    string
		key     string
		wantID  string
		wantErr bool
	}{
		{name: "first key", key: "key-alpha", wantID: "alpha"},
		{name: "second key", key: "key-beta-value", wantID: "beta"},
		{name: "unknown key", key: "key-gamma", wantErr: true},
		{name: "prefix of a valid key", key: "key-alph", wantErr: true},
		{name: "unknown key sharing a prefix", key: "key-alphax", wantErr: true},
		{name: "valid key plus trailing text", key: "key-alpha-extra", wantErr: true},
		{name: "empty", key: "", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.key != "" {
				r.Header.Set(APIKeyHeader, tc.key)
			}
			principal, err := verifier.Verify(r)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("key %q was accepted", tc.key)
				}
				if !errors.Is(err, httpx.ErrUnauthorized) {
					t.Fatalf("error = %v, want ErrUnauthorized", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if principal.ClientID != tc.wantID {
				t.Fatalf("ClientID = %q, want %q", principal.ClientID, tc.wantID)
			}
			if principal.Scheme != SchemeAPIKey {
				t.Fatalf("Scheme = %q, want %q", principal.Scheme, SchemeAPIKey)
			}
		})
	}
}

func TestNewAPIKeyVerifierRejectsEmptyConfig(t *testing.T) {
	if _, err := NewAPIKeyVerifier(nil); err == nil {
		t.Fatal("expected a configuration error for no keys")
	}
	for _, keys := range [][]APIKeyConfig{
		{{ClientID: "alpha"}},
		{{Key: "key"}},
	} {
		if _, err := NewAPIKeyVerifier(keys); err == nil {
			t.Fatalf("expected a configuration error for %+v", keys)
		}
	}
}
