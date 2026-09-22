// Package logging provides the gateway's structured access log.
package logging

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Inc-cryp/api-security-gateway/internal/httpx"
)

// errUnknownLevel is reported when logging.level names an unknown level.
var errUnknownLevel = errors.New("want debug, info, warn or error")

// Options configures the access logger.
type Options struct {
	// Level is one of debug, info, warn, error.
	Level string
	// RedactQuery replaces the query string with a marker, so credentials
	// passed as query parameters never reach the log.
	RedactQuery bool
	// RedactHeaders lists headers whose values are replaced by a marker.
	RedactHeaders []string
}

// Logger writes one structured line per request.
type Logger struct {
	log           *slog.Logger
	redactQuery   bool
	redactHeaders map[string]bool
}

// New builds a Logger writing JSON to stderr.
func New(opts Options) (*Logger, error) {
	level, err := parseLevel(opts.Level)
	if err != nil {
		return nil, err
	}
	handler := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	redact := make(map[string]bool, len(opts.RedactHeaders))
	for _, name := range opts.RedactHeaders {
		redact[http.CanonicalHeaderKey(strings.TrimSpace(name))] = true
	}
	// A caller's credentials must never be logged, whether or not the
	// operator remembered to list them.
	for _, name := range []string{
		"Authorization", httpx.RequestIDHeader, "X-Api-Key",
		"X-Signature", "X-Client-Id", "Cookie", "Set-Cookie", "Proxy-Authorization",
	} {
		redact[name] = true
	}
	return &Logger{log: slog.New(handler), redactQuery: opts.RedactQuery, redactHeaders: redact}, nil
}

// Slog exposes the underlying logger for start-up and error messages.
func (l *Logger) Slog() *slog.Logger { return l.log }

// Record describes one completed request.
type Record struct {
	Method    string
	Path      string
	Query     string
	ClientIP  string
	Principal string
	Route     string
	Service   string
	Status    int
	Bytes     int64
	Duration  time.Duration
	UserAgent string
	RequestID string
	Error     string
}

// Access writes the access-log line for a completed request.
func (l *Logger) Access(ctx context.Context, rec Record) {
	query := rec.Query
	if l.redactQuery && query != "" {
		query = "[redacted]"
	}
	attrs := []slog.Attr{
		slog.String("request_id", rec.RequestID),
		slog.String("method", rec.Method),
		slog.String("path", rec.Path),
		slog.String("client_ip", rec.ClientIP),
		slog.Int("status", rec.Status),
		slog.Int64("bytes", rec.Bytes),
		slog.Duration("duration", rec.Duration),
	}
	if query != "" {
		attrs = append(attrs, slog.String("query", query))
	}
	if rec.Principal != "" {
		attrs = append(attrs, slog.String("principal", rec.Principal))
	}
	if rec.Route != "" {
		attrs = append(attrs, slog.String("route", rec.Route))
	}
	if rec.Service != "" {
		attrs = append(attrs, slog.String("service", rec.Service))
	}
	if rec.UserAgent != "" {
		attrs = append(attrs, slog.String("user_agent", rec.UserAgent))
	}
	if rec.Error != "" {
		attrs = append(attrs, slog.String("error", rec.Error))
	}
	level := slog.LevelInfo
	switch {
	case rec.Status >= 500:
		level = slog.LevelError
	case rec.Status >= 400:
		level = slog.LevelWarn
	}
	l.log.LogAttrs(ctx, level, "request", attrs...)
}

func parseLevel(name string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, &httpx.ConfigError{Field: "logging.level", Value: name, Err: errUnknownLevel}
	}
}
