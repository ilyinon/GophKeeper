// Command gophkeeper-server runs the GophKeeper gRPC server.
package main

import (
	"context"
	"flag"
	"log"
	"net"
	"os/signal"
	"syscall"

	gogrpc "google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/oilyin/gophkeeper/internal/auth"
	"github.com/oilyin/gophkeeper/internal/config"
	"github.com/oilyin/gophkeeper/internal/migrations"
	"github.com/oilyin/gophkeeper/internal/repository/postgres"
	grpctransport "github.com/oilyin/gophkeeper/internal/transport/grpc"
	"github.com/oilyin/gophkeeper/internal/usecase"
)

var (
	buildVersion = "dev"
	buildDate    = "unknown"
)

func main() {
	cfg := config.LoadServer()
	flag.StringVar(&cfg.ListenAddr, "listen", cfg.ListenAddr, "gRPC listen address")
	flag.StringVar(&cfg.DatabaseURL, "database-url", cfg.DatabaseURL, "PostgreSQL connection URL")
	flag.StringVar(&cfg.JWTSecret, "jwt-secret", cfg.JWTSecret, "JWT HMAC secret")
	flag.DurationVar(&cfg.TokenTTL, "token-ttl", cfg.TokenTTL, "JWT token TTL")
	flag.StringVar(&cfg.TLSCertFile, "tls-cert", cfg.TLSCertFile, "TLS certificate file")
	flag.StringVar(&cfg.TLSKeyFile, "tls-key", cfg.TLSKeyFile, "TLS private key file")
	flag.Parse()

	if cfg.DatabaseURL == "" {
		log.Fatal("database-url or GOPHKEEPER_DATABASE_URL is required")
	}
	log.Printf("gophkeeper-server version=%s build_date=%s", buildVersion, buildDate)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pool, err := postgres.OpenPool(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("open postgres: %v", err)
	}
	defer pool.Close()
	if err := migrations.Up(ctx, pool); err != nil {
		log.Fatalf("migrate database: %v", err)
	}

	tokenManager, err := auth.NewTokenManager(cfg.JWTSecret, cfg.TokenTTL, "gophkeeper")
	if err != nil {
		log.Fatalf("create token manager: %v", err)
	}

	userRepository := postgres.NewUserRepository(pool)
	vaultRepository := postgres.NewVaultRepository(pool)
	authUseCase := usecase.NewAuthUseCase(userRepository, auth.NewPasswordHasher(), tokenManager)
	vaultUseCase := usecase.NewVaultUseCase(vaultRepository)

	var serverOptions []gogrpc.ServerOption
	if cfg.TLSCertFile != "" || cfg.TLSKeyFile != "" {
		creds, err := credentials.NewServerTLSFromFile(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			log.Fatalf("load tls credentials: %v", err)
		}
		serverOptions = append(serverOptions, gogrpc.Creds(creds))
	}
	grpcServer := gogrpc.NewServer(serverOptions...)
	grpctransport.RegisterServices(grpcServer, grpctransport.NewServer(authUseCase, vaultUseCase, tokenManager))

	listener, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	go func() {
		<-ctx.Done()
		grpcServer.GracefulStop()
	}()
	log.Printf("listening on %s", cfg.ListenAddr)
	if err := grpcServer.Serve(listener); err != nil {
		log.Fatalf("serve grpc: %v", err)
	}
}
