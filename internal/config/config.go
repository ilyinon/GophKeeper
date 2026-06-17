// Package config contains environment-backed application configuration.
package config

import (
	"os"
	"path/filepath"
	"time"
)

const (
	// DefaultServerAddress is the default gRPC listen and dial address.
	DefaultServerAddress = "127.0.0.1:3200"
	// DefaultTokenTTL is the default access token lifetime.
	DefaultTokenTTL = 24 * time.Hour
)

// ServerConfig contains GophKeeper server settings.
type ServerConfig struct {
	ListenAddr  string
	DatabaseURL string
	JWTSecret   string
	TokenTTL    time.Duration
	TLSCertFile string
	TLSKeyFile  string
}

// ClientConfig contains GophKeeper CLI settings.
type ClientConfig struct {
	ServerAddr string
	CachePath  string
	TLSCAFile  string
	Insecure   bool
}

// LoadServer returns server configuration from environment variables.
func LoadServer() ServerConfig {
	return ServerConfig{
		ListenAddr:  env("GOPHKEEPER_LISTEN_ADDR", DefaultServerAddress),
		DatabaseURL: os.Getenv("GOPHKEEPER_DATABASE_URL"),
		JWTSecret:   env("GOPHKEEPER_JWT_SECRET", "dev-secret-change-me-dev-secret-32-bytes"),
		TokenTTL:    envDuration("GOPHKEEPER_TOKEN_TTL", DefaultTokenTTL),
		TLSCertFile: os.Getenv("GOPHKEEPER_TLS_CERT_FILE"),
		TLSKeyFile:  os.Getenv("GOPHKEEPER_TLS_KEY_FILE"),
	}
}

// LoadClient returns CLI configuration from environment variables.
func LoadClient() ClientConfig {
	return ClientConfig{
		ServerAddr: env("GOPHKEEPER_SERVER_ADDR", DefaultServerAddress),
		CachePath:  env("GOPHKEEPER_CACHE_PATH", defaultCachePath()),
		TLSCAFile:  os.Getenv("GOPHKEEPER_TLS_CA_FILE"),
		Insecure:   env("GOPHKEEPER_INSECURE", "true") == "true",
	}
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func envDuration(key string, fallback time.Duration) time.Duration {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	duration, err := time.ParseDuration(value)
	if err != nil {
		return fallback
	}
	return duration
}

func defaultCachePath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return filepath.Join(".", "gophkeeper.db")
	}
	return filepath.Join(dir, "gophkeeper", "cache.db")
}
