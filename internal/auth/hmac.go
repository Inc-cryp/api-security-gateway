package auth

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Inc-cryp/api-security-gateway/internal/httpx"
)

// Header names used by the request-signing scheme.
const (
	ClientIDHeader       = "X-Client-Id"
	TimestampHeader      = "X-Timestamp"
	SignatureHeader      = "X-Signature"
	defaultSignatureSkew = 5 * time.Minute
)

// HMACClient is one signing client's shared secret.
type HMACClient struct {
	ClientID string
	Secret   string
}

// HMACConfig configures request signing.
type HMACConfig struct {
	// Clients are the accepted shared secrets. Required.
	Clients []HMACClient
	// MaxSkew is how far the request timestamp may drift from now, in either
	// direction. Defaults to defaultSignatureSkew when zero.
	MaxSkew time.Duration
	// Header names, defaulting to the package constants.
	ClientHeader    string
	TimestampHeader string
	SignatureHeader string
}

// HMACVerifier authenticates requests signed with a shared secret.
//
// The caller signs a canonical description of the request:
//
//	METHOD \n PATH \n RAWQUERY \n TIMESTAMP \n CLIENTID \n SHA256(body)
//
// Binding the body hash into the signature is what stops a captured request
// from being replayed against a different payload, and binding the timestamp
// into it is what stops an old signature from outliving its window.
type HMACVerifier struct {
	cfg     HMACConfig
	secrets map[string][]byte
}

// NewHMACVerifier validates cfg and returns a verifier.
func NewHMACVerifier(cfg HMACConfig) (*HMACVerifier, error) {
	if len(cfg.Clients) == 0 {
		return nil, &httpx.ConfigError{Field: "security.hmac.clients", Value: "none configured"}
	}
	if cfg.MaxSkew < 0 {
		return nil, &httpx.ConfigError{Field: "security.hmac.max_skew", Value: cfg.MaxSkew.String(), Err: fmt.Errorf("must not be negative")}
	}
	if cfg.MaxSkew == 0 {
		cfg.MaxSkew = defaultSignatureSkew
	}
	cfg.ClientHeader = firstNonEmpty(cfg.ClientHeader, ClientIDHeader)
	cfg.TimestampHeader = firstNonEmpty(cfg.TimestampHeader, TimestampHeader)
	cfg.SignatureHeader = firstNonEmpty(cfg.SignatureHeader, SignatureHeader)

	secrets := make(map[string][]byte, len(cfg.Clients))
	for i, client := range cfg.Clients {
		if strings.TrimSpace(client.ClientID) == "" {
			return nil, &httpx.ConfigError{Field: fmt.Sprintf("security.hmac.clients[%d].client_id", i)}
		}
		if strings.TrimSpace(client.Secret) == "" {
			return nil, &httpx.ConfigError{Field: fmt.Sprintf("security.hmac.clients[%d].secret", i)}
		}
		if _, dup := secrets[client.ClientID]; dup {
			return nil, &httpx.ConfigError{Field: "security.hmac.clients", Value: client.ClientID, Err: fmt.Errorf("duplicate client id")}
		}
		secrets[client.ClientID] = []byte(client.Secret)
	}
	return &HMACVerifier{cfg: cfg, secrets: secrets}, nil
}

// Scheme implements Verifier.
func (v *HMACVerifier) Scheme() string { return SchemeHMAC }

// Verify implements Verifier. The request body is buffered and then restored,
// because the proxy downstream still has to forward it.
func (v *HMACVerifier) Verify(r *http.Request) (Principal, error) {
	clientID := strings.TrimSpace(r.Header.Get(v.cfg.ClientHeader))
	signature := strings.TrimSpace(r.Header.Get(v.cfg.SignatureHeader))
	timestamp := strings.TrimSpace(r.Header.Get(v.cfg.TimestampHeader))
	switch {
	case clientID == "":
		return Principal{}, fmt.Errorf("%w: missing %s header", httpx.ErrUnauthorized, v.cfg.ClientHeader)
	case signature == "":
		return Principal{}, fmt.Errorf("%w: missing %s header", httpx.ErrUnauthorized, v.cfg.SignatureHeader)
	case timestamp == "":
		return Principal{}, fmt.Errorf("%w: missing %s header", httpx.ErrUnauthorized, v.cfg.TimestampHeader)
	}

	secret, known := v.secrets[clientID]
	if !known {
		return Principal{}, fmt.Errorf("%w: unknown signing client %q", httpx.ErrUnauthorized, clientID)
	}

	sentAt, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return Principal{}, fmt.Errorf("%w: %s must be unix seconds", httpx.ErrUnauthorized, v.cfg.TimestampHeader)
	}
	drift := time.Since(time.Unix(sentAt, 0))
	if drift < 0 {
		drift = -drift
	}
	if drift > v.cfg.MaxSkew {
		direction := "old"
		if time.Since(time.Unix(sentAt, 0)) < 0 {
			direction = "in the future"
		}
		return Principal{}, fmt.Errorf("%w: request timestamp is %s (%s, allowed skew %s)", httpx.ErrUnauthorized, direction, drift.Round(time.Second), v.cfg.MaxSkew)
	}

	body, err := drainBody(r)
	if err != nil {
		return Principal{}, fmt.Errorf("%w: reading request body", httpx.ErrUnauthorized)
	}

	canonical := canonicalString(r, timestamp, clientID, body)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(canonical))
	presented, err := hex.DecodeString(signature)
	if err != nil {
		return Principal{}, fmt.Errorf("%w: %s must be lowercase hex", httpx.ErrUnauthorized, v.cfg.SignatureHeader)
	}
	if !hmac.Equal(mac.Sum(nil), presented) {
		return Principal{}, fmt.Errorf("%w: request signature does not verify", httpx.ErrUnauthorized)
	}
	return Principal{ClientID: clientID, Scheme: SchemeHMAC}, nil
}

// canonicalString builds the exact text the caller is expected to have signed.
func canonicalString(r *http.Request, timestamp, clientID string, body []byte) string {
	bodySum := sha256.Sum256(body)
	return strings.Join([]string{
		r.Method,
		r.URL.Path,
		r.URL.RawQuery,
		timestamp,
		clientID,
		hex.EncodeToString(bodySum[:]),
	}, "\n")
}

// drainBody reads the whole request body and puts it back, so verification is
// transparent to everything downstream.
func drainBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	_ = r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	r.ContentLength = int64(len(body))
	return body, nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
