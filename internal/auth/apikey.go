package auth

import (
	"crypto/subtle"
	"fmt"
	"net/http"
	"strings"

	"github.com/Inc-cryp/api-security-gateway/internal/httpx"
)

// APIKeyHeader is the header carrying a static API key.
const APIKeyHeader = "X-Api-Key"

// APIKeyConfig is one issued key and the client it identifies.
type APIKeyConfig struct {
	Key      string
	ClientID string
}

// APIKeyVerifier authenticates a static API key presented in X-Api-Key.
type APIKeyVerifier struct {
	keys []APIKeyConfig
}

// NewAPIKeyVerifier validates keys and returns a verifier. At least one key
// is required.
func NewAPIKeyVerifier(keys []APIKeyConfig) (*APIKeyVerifier, error) {
	if len(keys) == 0 {
		return nil, &httpx.ConfigError{Field: "security.api_keys", Value: "none configured"}
	}
	out := make([]APIKeyConfig, 0, len(keys))
	for i, key := range keys {
		if strings.TrimSpace(key.Key) == "" {
			return nil, &httpx.ConfigError{Field: fmt.Sprintf("security.api_keys[%d].key", i)}
		}
		if strings.TrimSpace(key.ClientID) == "" {
			return nil, &httpx.ConfigError{Field: fmt.Sprintf("security.api_keys[%d].client_id", i)}
		}
		out = append(out, key)
	}
	return &APIKeyVerifier{keys: out}, nil
}

// Scheme implements Verifier.
func (v *APIKeyVerifier) Scheme() string { return SchemeAPIKey }

// Verify implements Verifier.
//
// Every configured key is compared even after a match is found, and the
// comparison uses the constant-time primitive: a keyed map lookup would leak
// the position and length of the matching prefix through timing.
func (v *APIKeyVerifier) Verify(r *http.Request) (Principal, error) {
	presented := strings.TrimSpace(r.Header.Get(APIKeyHeader))
	if presented == "" {
		return Principal{}, fmt.Errorf("%w: missing %s header", httpx.ErrUnauthorized, APIKeyHeader)
	}
	clientID := ""
	match := 0
	for _, candidate := range v.keys {
		eq := subtle.ConstantTimeCompare([]byte(presented), []byte(candidate.Key))
		if eq == 1 {
			clientID = candidate.ClientID
		}
		match |= eq
	}
	if match != 1 {
		return Principal{}, fmt.Errorf("%w: unknown API key", httpx.ErrUnauthorized)
	}
	return Principal{ClientID: clientID, Scheme: SchemeAPIKey}, nil
}
