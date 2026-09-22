// Command gatewayd runs the API security gateway.
//
// It loads a YAML configuration file, wires the authentication verifiers, the
// rate limiters, the circuit breakers and the reverse proxy, and serves until
// it receives a termination signal.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Inc-cryp/api-security-gateway/internal/auth"
	"github.com/Inc-cryp/api-security-gateway/internal/breaker"
	"github.com/Inc-cryp/api-security-gateway/internal/config"
	"github.com/Inc-cryp/api-security-gateway/internal/httpx"
	"github.com/Inc-cryp/api-security-gateway/internal/logging"
	"github.com/Inc-cryp/api-security-gateway/internal/middleware"
	"github.com/Inc-cryp/api-security-gateway/internal/proxy"
	"github.com/Inc-cryp/api-security-gateway/internal/router"
)

// version is replaced at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "gatewayd:", err)
		os.Exit(1)
	}
}

func run() error {
	configPath := flag.String("config", "config.yaml", "path to the gateway configuration file")
	printVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()

	if *printVersion {
		fmt.Println("gatewayd", version)
		return nil
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	logger, err := logging.New(logging.Options{
		Level:       cfg.Logging.Level,
		RedactQuery: cfg.Logging.RedactQuery,
	})
	if err != nil {
		return err
	}
	handler, cleanup, err := build(cfg, logger)
	if cleanup != nil {
		defer cleanup()
	}
	if err != nil {
		return err
	}

	readTimeout, writeTimeout, readHeaderTimeout, idleTimeout, shutdownTimeout, err := cfg.Server.ServerTimeouts()
	if err != nil {
		return err
	}

	server := &http.Server{
		Addr:              cfg.Server.Addr,
		Handler:           handler,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       idleTimeout,
		ErrorLog:          slog.NewLogLogger(logger.Slog().Handler(), slog.LevelError),
	}

	shutdownSignals := make(chan os.Signal, 1)
	signal.Notify(shutdownSignals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(shutdownSignals)

	listenErr := make(chan error, 1)
	go func() {
		logger.Slog().Info("gateway listening",
			"addr", cfg.Server.Addr,
			"routes", len(cfg.Routes),
			"services", handler.Services(),
			"version", version,
		)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			listenErr <- err
			return
		}
		listenErr <- nil
	}()

	select {
	case err := <-listenErr:
		return err
	case signal := <-shutdownSignals:
		logger.Slog().Info("shutting down", "signal", signal.String(), "grace", shutdownTimeout.String())
	}

	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	// In-flight requests get the grace period; the idle connections do not
	// hold the process open past it.
	if err := server.Shutdown(ctx); err != nil {
		return fmt.Errorf("graceful shutdown did not complete within %s: %w", shutdownTimeout, err)
	}
	if err := <-listenErr; err != nil {
		return err
	}
	logger.Slog().Info("shutdown complete")
	return nil
}

// build assembles the gateway handler from cfg.
func build(cfg config.Config, logger *logging.Logger) (*middleware.Gateway, func(), error) {
	verifiers, err := newVerifiers(cfg)
	if err != nil {
		return nil, nil, err
	}
	authenticator, err := auth.NewAuthenticator(verifiers...)
	if err != nil {
		return nil, nil, err
	}
	for _, route := range cfg.Routes {
		for _, scheme := range route.Authenticators {
			if !authenticator.Has(scheme) {
				return nil, nil, &httpx.ConfigError{
					Field: "routes." + route.Path + ".authenticators",
					Value: scheme,
					Err:   fmt.Errorf("no verifier is configured for this scheme"),
				}
			}
		}
	}

	clientIP, err := httpx.NewClientIPResolver(cfg.Security.ClientIP.TrustedProxies, cfg.Security.ClientIP.ForwardedHeader)
	if err != nil {
		return nil, nil, err
	}

	routes, err := newRoutes(cfg)
	if err != nil {
		return nil, nil, err
	}
	table, err := router.New(routes)
	if err != nil {
		return nil, nil, err
	}

	upstreamTimeout, err := config.ParseDuration(cfg.Upstream.Timeout)
	if err != nil {
		return nil, nil, err
	}
	breakers, err := newBreakers(cfg)
	if err != nil {
		return nil, nil, err
	}
	forwarder, err := proxy.New(proxy.Config{
		Services:       cfg.Upstreams,
		DefaultTimeout: upstreamTimeout,
		Breaker:        breakers,
	})
	if err != nil {
		return nil, nil, err
	}

	gateway, err := middleware.New(middleware.Options{
		Config:        cfg,
		Router:        table,
		Proxy:         forwarder,
		Authenticator: authenticator,
		ClientIP:      clientIP,
		Logger:        logger,
	})
	if err != nil {
		return nil, nil, err
	}
	return gateway, func() {}, nil
}

func newVerifiers(cfg config.Config) ([]auth.Verifier, error) {
	var verifiers []auth.Verifier
	if cfg.Security.JWT.Secret != "" {
		skew, err := optionalDuration(cfg.Security.JWT.ClockSkew)
		if err != nil {
			return nil, err
		}
		verifier, err := auth.NewJWTVerifier(auth.JWTConfig{
			Secret:    cfg.Security.JWT.Secret,
			Issuer:    cfg.Security.JWT.Issuer,
			Audience:  cfg.Security.JWT.Audience,
			ClockSkew: skew,
		})
		if err != nil {
			return nil, err
		}
		verifiers = append(verifiers, verifier)
	}
	if len(cfg.Security.APIKeys) > 0 {
		keys := make([]auth.APIKeyConfig, 0, len(cfg.Security.APIKeys))
		for _, key := range cfg.Security.APIKeys {
			keys = append(keys, auth.APIKeyConfig{Key: key.Key, ClientID: key.ClientID})
		}
		verifier, err := auth.NewAPIKeyVerifier(keys)
		if err != nil {
			return nil, err
		}
		verifiers = append(verifiers, verifier)
	}
	if len(cfg.Security.HMAC.Clients) > 0 {
		skew, err := optionalDuration(cfg.Security.HMAC.MaxSkew)
		if err != nil {
			return nil, err
		}
		clients := make([]auth.HMACClient, 0, len(cfg.Security.HMAC.Clients))
		for _, client := range cfg.Security.HMAC.Clients {
			clients = append(clients, auth.HMACClient{ClientID: client.ClientID, Secret: client.Secret})
		}
		verifier, err := auth.NewHMACVerifier(auth.HMACConfig{
			Clients:         clients,
			MaxSkew:         skew,
			ClientHeader:    cfg.Security.HMAC.ClientHeader,
			TimestampHeader: cfg.Security.HMAC.TimestampHeader,
			SignatureHeader: cfg.Security.HMAC.SignatureHeader,
		})
		if err != nil {
			return nil, err
		}
		verifiers = append(verifiers, verifier)
	}
	if len(verifiers) == 0 {
		return nil, &httpx.ConfigError{Field: "security", Value: "no verifier configured"}
	}
	return verifiers, nil
}

func newRoutes(cfg config.Config) ([]*router.Route, error) {
	routes := make([]*router.Route, 0, len(cfg.Routes))
	for i, route := range cfg.Routes {
		timeout, err := optionalDuration(route.Timeout)
		if err != nil {
			return nil, &httpx.ConfigError{Field: fmt.Sprintf("routes[%d].timeout", i), Value: route.Timeout, Err: err}
		}
		routes = append(routes, &router.Route{
			Path:           route.Path,
			Service:        route.Service,
			Authenticators: route.Authenticators,
			Methods:        route.Methods,
			StripPrefix:    route.StripPrefix,
			Timeout:        timeout,
			// The rate-limit pair has to survive this copy: middleware.New
			// builds one limiter per route that sets rate_limit, so dropping
			// it here leaves every route unlimited no matter what the file
			// says.
			RateLimit:  route.RateLimit,
			RateBurst:  route.RateBurst,
			AllowedIPs: route.AllowedIPs,
			DeniedIPs:  route.DeniedIPs,
		})
	}
	return routes, nil
}

func newBreakers(cfg config.Config) (*breaker.Registry, error) {
	openTimeout, err := optionalDuration(cfg.Upstream.CircuitBreaker.OpenTimeout)
	if err != nil {
		return nil, err
	}
	return breaker.NewRegistry(breaker.Config{
		FailureThreshold:  cfg.Upstream.CircuitBreaker.FailureThreshold,
		OpenTimeout:       openTimeout,
		HalfOpenSuccesses: cfg.Upstream.CircuitBreaker.HalfOpenSuccesses,
	}), nil
}

func optionalDuration(value string) (time.Duration, error) {
	if value == "" {
		return 0, nil
	}
	return config.ParseDuration(value)
}
