package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Inc-cryp/api-security-gateway/internal/httpx"
)

// defaultClockSkew is the leeway applied to exp/nbf when the configuration
// does not specify one.
const defaultClockSkew = 30 * time.Second

// JWTConfig configures the HS256 verifier.
type JWTConfig struct {
	// Secret is the HMAC signing key. Required, at least 16 bytes.
	Secret string
	// Issuer, when set, must match the token's `iss` claim.
	Issuer string
	// Audience, when set, must appear in the token's `aud` claim.
	Audience string
	// ClockSkew is the leeway for exp/nbf comparisons. Defaults to
	// defaultClockSkew when zero.
	ClockSkew time.Duration
}

// JWTVerifier validates HS256-signed JSON Web Tokens.
//
// Only HS256 is accepted. The `alg` header is chosen by whoever minted the
// token, so honouring it would let an attacker downgrade to `none` or swap in
// an asymmetric algorithm this verifier cannot check. The algorithm is fixed
// here and the header is merely compared against it.
type JWTVerifier struct {
	cfg JWTConfig
}

// NewJWTVerifier validates cfg and returns a verifier.
func NewJWTVerifier(cfg JWTConfig) (*JWTVerifier, error) {
	if strings.TrimSpace(cfg.Secret) == "" {
		return nil, &httpx.ConfigError{Field: "security.jwt.secret", Value: "***", Err: fmt.Errorf("required")}
	}
	if len(cfg.Secret) < 16 {
		return nil, &httpx.ConfigError{Field: "security.jwt.secret", Value: "***", Err: fmt.Errorf("must be at least 16 bytes")}
	}
	if cfg.ClockSkew < 0 {
		return nil, &httpx.ConfigError{Field: "security.jwt.clock_skew", Value: cfg.ClockSkew.String(), Err: fmt.Errorf("must not be negative")}
	}
	if cfg.ClockSkew == 0 {
		cfg.ClockSkew = defaultClockSkew
	}
	return &JWTVerifier{cfg: cfg}, nil
}

// Scheme implements Verifier.
func (v *JWTVerifier) Scheme() string { return SchemeJWT }

// Verify implements Verifier.
func (v *JWTVerifier) Verify(r *http.Request) (Principal, error) {
	header := strings.TrimSpace(r.Header.Get("Authorization"))
	if header == "" {
		return Principal{}, fmt.Errorf("%w: missing Authorization header", httpx.ErrUnauthorized)
	}
	scheme, token, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return Principal{}, fmt.Errorf("%w: expected an Authorization: Bearer token", httpx.ErrUnauthorized)
	}
	claims, err := v.verifyToken(strings.TrimSpace(token), time.Now())
	if err != nil {
		return Principal{}, err
	}
	return Principal{ClientID: claims.Subject, Scheme: SchemeJWT}, nil
}

type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

type jwtClaims struct {
	Subject   string          `json:"sub"`
	Issuer    string          `json:"iss"`
	Audience  json.RawMessage `json:"aud"`
	Expiry    *json.Number    `json:"exp"`
	NotBefore *json.Number    `json:"nbf"`
}

// verifyToken checks the signature and the registered claims. now is a
// parameter so tests can pin the clock.
func (v *JWTVerifier) verifyToken(token string, now time.Time) (jwtClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return jwtClaims{}, fmt.Errorf("%w: token must have three dot-separated parts", httpx.ErrUnauthorized)
	}
	rawHeader, err := decodeSegment(parts[0])
	if err != nil {
		return jwtClaims{}, fmt.Errorf("%w: malformed token header", httpx.ErrUnauthorized)
	}
	var header jwtHeader
	if err := json.Unmarshal(rawHeader, &header); err != nil {
		return jwtClaims{}, fmt.Errorf("%w: malformed token header", httpx.ErrUnauthorized)
	}
	if !strings.EqualFold(header.Alg, "HS256") {
		// Deliberately explicit: `none` and the asymmetric algorithms are the
		// two families an attacker reaches for here.
		return jwtClaims{}, fmt.Errorf("%w: token algorithm %q is not accepted, only HS256", httpx.ErrUnauthorized, header.Alg)
	}

	mac := hmac.New(sha256.New, []byte(v.cfg.Secret))
	mac.Write([]byte(parts[0] + "." + parts[1]))
	expected := mac.Sum(nil)
	presented, err := decodeSegment(parts[2])
	if err != nil {
		return jwtClaims{}, fmt.Errorf("%w: malformed token signature", httpx.ErrUnauthorized)
	}
	if !hmac.Equal(expected, presented) {
		return jwtClaims{}, fmt.Errorf("%w: token signature does not verify", httpx.ErrUnauthorized)
	}

	rawClaims, err := decodeSegment(parts[1])
	if err != nil {
		return jwtClaims{}, fmt.Errorf("%w: malformed token payload", httpx.ErrUnauthorized)
	}
	decoder := json.NewDecoder(strings.NewReader(string(rawClaims)))
	decoder.UseNumber()
	var claims jwtClaims
	if err := decoder.Decode(&claims); err != nil {
		return jwtClaims{}, fmt.Errorf("%w: malformed token payload", httpx.ErrUnauthorized)
	}
	if strings.TrimSpace(claims.Subject) == "" {
		return jwtClaims{}, fmt.Errorf("%w: token has no subject", httpx.ErrUnauthorized)
	}

	if claims.Expiry != nil {
		exp, err := claims.Expiry.Int64()
		if err != nil {
			return jwtClaims{}, fmt.Errorf("%w: token exp is not an integer", httpx.ErrUnauthorized)
		}
		if now.After(time.Unix(exp, 0).Add(v.cfg.ClockSkew)) {
			return jwtClaims{}, fmt.Errorf("%w: token expired at %s", httpx.ErrUnauthorized, time.Unix(exp, 0).UTC().Format(time.RFC3339))
		}
	}
	if claims.NotBefore != nil {
		nbf, err := claims.NotBefore.Int64()
		if err != nil {
			return jwtClaims{}, fmt.Errorf("%w: token nbf is not an integer", httpx.ErrUnauthorized)
		}
		if now.Add(v.cfg.ClockSkew).Before(time.Unix(nbf, 0)) {
			return jwtClaims{}, fmt.Errorf("%w: token is not valid before %s", httpx.ErrUnauthorized, time.Unix(nbf, 0).UTC().Format(time.RFC3339))
		}
	}
	if v.cfg.Issuer != "" && claims.Issuer != v.cfg.Issuer {
		return jwtClaims{}, fmt.Errorf("%w: token issuer %q is not accepted", httpx.ErrUnauthorized, claims.Issuer)
	}
	if v.cfg.Audience != "" && !audienceContains(claims.Audience, v.cfg.Audience) {
		return jwtClaims{}, fmt.Errorf("%w: token audience is not accepted", httpx.ErrUnauthorized)
	}
	return claims, nil
}

// audienceContains handles `aud` being either a single string or an array of
// strings, both of which RFC 7519 permits.
func audienceContains(raw json.RawMessage, want string) bool {
	if len(raw) == 0 {
		return false
	}
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		return single == want
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err == nil {
		for _, item := range list {
			if item == want {
				return true
			}
		}
	}
	return false
}

// decodeSegment base64url-decodes a JWS segment, accepting both the padded
// and the unpadded encoding since both appear in the wild.
func decodeSegment(segment string) ([]byte, error) {
	if segment == "" {
		return nil, fmt.Errorf("empty segment")
	}
	if decoded, err := base64.RawURLEncoding.DecodeString(segment); err == nil {
		return decoded, nil
	}
	return base64.URLEncoding.DecodeString(segment)
}
