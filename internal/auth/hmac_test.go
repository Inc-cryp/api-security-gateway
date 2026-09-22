package auth

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/Inc-cryp/api-security-gateway/internal/httpx"
)

const (
	hmacClientID = "signer-1"
	hmacSecret   = "shared-secret-value"
)

// signRequest reproduces the canonical string the verifier expects and
// attaches the resulting signature headers.
func signRequest(t *testing.T, r *http.Request, secret, clientID string, at time.Time, body []byte) {
	t.Helper()
	timestamp := strconv.FormatInt(at.Unix(), 10)
	sum := sha256.Sum256(body)
	canonical := r.Method + "\n" + r.URL.Path + "\n" + r.URL.RawQuery + "\n" +
		timestamp + "\n" + clientID + "\n" + hex.EncodeToString(sum[:])
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(canonical))
	r.Header.Set(ClientIDHeader, clientID)
	r.Header.Set(TimestampHeader, timestamp)
	r.Header.Set(SignatureHeader, hex.EncodeToString(mac.Sum(nil)))
}

func newHMACVerifier(t *testing.T) *HMACVerifier {
	t.Helper()
	verifier, err := NewHMACVerifier(HMACConfig{
		Clients: []HMACClient{{ClientID: hmacClientID, Secret: hmacSecret}},
		MaxSkew: 2 * time.Minute,
	})
	if err != nil {
		t.Fatalf("NewHMACVerifier: %v", err)
	}
	return verifier
}

func TestHMACVerifierAcceptsValidSignature(t *testing.T) {
	verifier := newHMACVerifier(t)
	body := []byte(`{"amount":100}`)
	r := httptest.NewRequest(http.MethodPost, "/transfer?ref=abc", bytes.NewReader(body))
	signRequest(t, r, hmacSecret, hmacClientID, time.Now(), body)

	principal, err := verifier.Verify(r)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if principal.ClientID != hmacClientID || principal.Scheme != SchemeHMAC {
		t.Fatalf("principal = %+v, want %s/%s", principal, hmacClientID, SchemeHMAC)
	}
}

// TestHMACVerifierRestoresBody is the property the proxy depends on: the body
// must still be readable, and re-readable, after verification.
func TestHMACVerifierRestoresBody(t *testing.T) {
	verifier := newHMACVerifier(t)
	body := []byte(`{"amount":100}`)
	r := httptest.NewRequest(http.MethodPost, "/transfer", bytes.NewReader(body))
	signRequest(t, r, hmacSecret, hmacClientID, time.Now(), body)

	if _, err := verifier.Verify(r); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	first, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("reading restored body: %v", err)
	}
	if !bytes.Equal(first, body) {
		t.Fatalf("body = %q, want %q", first, body)
	}
	if r.ContentLength != int64(len(body)) {
		t.Fatalf("ContentLength = %d, want %d", r.ContentLength, len(body))
	}
	if r.GetBody == nil {
		t.Fatal("GetBody was not restored")
	}
	reopened, err := r.GetBody()
	if err != nil {
		t.Fatalf("GetBody: %v", err)
	}
	defer reopened.Close()
	second, err := io.ReadAll(reopened)
	if err != nil {
		t.Fatalf("reading reopened body: %v", err)
	}
	if !bytes.Equal(second, body) {
		t.Fatalf("reopened body = %q, want %q", second, body)
	}
}

func TestHMACVerifierRejections(t *testing.T) {
	now := time.Now()
	body := []byte(`{"amount":100}`)
	tests := []struct {
		name   string
		mutate func(t *testing.T, r *http.Request)
	}{
		{
			name: "tampered body",
			mutate: func(t *testing.T, r *http.Request) {
				signRequest(t, r, hmacSecret, hmacClientID, now, body)
				r.Body = io.NopCloser(bytes.NewReader([]byte(`{"amount":999999}`)))
			},
		},
		{
			name: "tampered path",
			mutate: func(t *testing.T, r *http.Request) {
				signRequest(t, r, hmacSecret, hmacClientID, now, body)
				r.URL.Path = "/transfer/other"
			},
		},
		{
			name: "tampered query",
			mutate: func(t *testing.T, r *http.Request) {
				signRequest(t, r, hmacSecret, hmacClientID, now, body)
				r.URL.RawQuery = "ref=changed"
			},
		},
		{
			name: "tampered method",
			mutate: func(t *testing.T, r *http.Request) {
				signRequest(t, r, hmacSecret, hmacClientID, now, body)
				r.Method = http.MethodPut
			},
		},
		{
			name: "wrong secret",
			mutate: func(t *testing.T, r *http.Request) {
				signRequest(t, r, "a-different-secret", hmacClientID, now, body)
			},
		},
		{
			name: "unknown client",
			mutate: func(t *testing.T, r *http.Request) {
				signRequest(t, r, hmacSecret, "nobody", now, body)
			},
		},
		{
			name: "missing client header",
			mutate: func(t *testing.T, r *http.Request) {
				signRequest(t, r, hmacSecret, hmacClientID, now, body)
				r.Header.Del(ClientIDHeader)
			},
		},
		{
			name: "missing timestamp header",
			mutate: func(t *testing.T, r *http.Request) {
				signRequest(t, r, hmacSecret, hmacClientID, now, body)
				r.Header.Del(TimestampHeader)
			},
		},
		{
			name: "missing signature header",
			mutate: func(t *testing.T, r *http.Request) {
				signRequest(t, r, hmacSecret, hmacClientID, now, body)
				r.Header.Del(SignatureHeader)
			},
		},
		{
			name: "stale timestamp",
			mutate: func(t *testing.T, r *http.Request) {
				signRequest(t, r, hmacSecret, hmacClientID, now.Add(-10*time.Minute), body)
			},
		},
		{
			name: "future timestamp",
			mutate: func(t *testing.T, r *http.Request) {
				signRequest(t, r, hmacSecret, hmacClientID, now.Add(10*time.Minute), body)
			},
		},
		{
			name: "non-numeric timestamp",
			mutate: func(t *testing.T, r *http.Request) {
				signRequest(t, r, hmacSecret, hmacClientID, now, body)
				r.Header.Set(TimestampHeader, "yesterday")
			},
		},
		{
			name: "signature is not hex",
			mutate: func(t *testing.T, r *http.Request) {
				signRequest(t, r, hmacSecret, hmacClientID, now, body)
				r.Header.Set(SignatureHeader, "zzzz")
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/transfer?ref=abc", bytes.NewReader(body))
			tc.mutate(t, r)
			verifier := newHMACVerifier(t)
			if _, err := verifier.Verify(r); !errors.Is(err, httpx.ErrUnauthorized) {
				t.Fatalf("error = %v, want ErrUnauthorized", err)
			}
		})
	}
}

func TestNewHMACVerifierRejectsBadConfig(t *testing.T) {
	tests := []struct {
		name string
		cfg  HMACConfig
	}{
		{"no clients", HMACConfig{}},
		{"empty client id", HMACConfig{Clients: []HMACClient{{Secret: "s"}}}},
		{"empty secret", HMACConfig{Clients: []HMACClient{{ClientID: "c"}}}},
		{"duplicate client id", HMACConfig{Clients: []HMACClient{
			{ClientID: "c", Secret: "s1"},
			{ClientID: "c", Secret: "s2"},
		}}},
		{"negative skew", HMACConfig{
			Clients: []HMACClient{{ClientID: "c", Secret: "s"}},
			MaxSkew: -time.Second,
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewHMACVerifier(tc.cfg); err == nil {
				t.Fatal("expected a configuration error")
			}
		})
	}
}
