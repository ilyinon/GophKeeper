package config

import (
	"strings"
	"testing"
	"time"
)

func TestLoadServerFromEnv(t *testing.T) {
	t.Setenv("GOPHKEEPER_LISTEN_ADDR", "127.0.0.1:1")
	t.Setenv("GOPHKEEPER_DATABASE_URL", "postgres://test")
	t.Setenv("GOPHKEEPER_JWT_SECRET", strings.Repeat("x", 32))
	t.Setenv("GOPHKEEPER_TOKEN_TTL", "2h")
	t.Setenv("GOPHKEEPER_TLS_CERT_FILE", "cert.pem")
	t.Setenv("GOPHKEEPER_TLS_KEY_FILE", "key.pem")

	cfg := LoadServer()
	if cfg.ListenAddr != "127.0.0.1:1" || cfg.DatabaseURL != "postgres://test" || cfg.TokenTTL != 2*time.Hour {
		t.Fatalf("server config = %+v", cfg)
	}
	if cfg.TLSCertFile != "cert.pem" || cfg.TLSKeyFile != "key.pem" {
		t.Fatalf("tls config = %+v", cfg)
	}
}

func TestLoadClientFromEnv(t *testing.T) {
	t.Setenv("GOPHKEEPER_SERVER_ADDR", "example:3200")
	t.Setenv("GOPHKEEPER_CACHE_PATH", "/tmp/cache.db")
	t.Setenv("GOPHKEEPER_TLS_CA_FILE", "ca.pem")
	t.Setenv("GOPHKEEPER_INSECURE", "false")

	cfg := LoadClient()
	if cfg.ServerAddr != "example:3200" || cfg.CachePath != "/tmp/cache.db" || cfg.TLSCAFile != "ca.pem" || cfg.Insecure {
		t.Fatalf("client config = %+v", cfg)
	}
}

func TestEnvDurationFallback(t *testing.T) {
	t.Setenv("BAD_DURATION", "not-a-duration")
	if got := envDuration("BAD_DURATION", time.Minute); got != time.Minute {
		t.Fatalf("duration = %s, want 1m", got)
	}
}
