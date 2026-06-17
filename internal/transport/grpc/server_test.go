package grpctransport

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	gogrpc "google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"

	"github.com/oilyin/gophkeeper/internal/auth"
	"github.com/oilyin/gophkeeper/internal/entity"
	apperrors "github.com/oilyin/gophkeeper/internal/errors"
	gophkeeperv1 "github.com/oilyin/gophkeeper/internal/transport/grpc/pb/gophkeeper/v1"
	"github.com/oilyin/gophkeeper/internal/usecase"
)

func TestServerAuthAndVaultFlow(t *testing.T) {
	ctx := context.Background()
	client, cleanup := newTestClient(t)
	defer cleanup()

	authResp, err := client.auth.Register(ctx, &gophkeeperv1.RegisterRequest{
		Login:    "alice",
		Password: "password-1",
		KdfSalt:  []byte("1234567890123456"),
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	authCtx := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+authResp.GetAccessToken())

	header, err := client.vault.CreateItem(authCtx, &gophkeeperv1.CreateItemRequest{
		Nonce:      []byte("123456789012"),
		Ciphertext: []byte("cipher"),
	})
	if err != nil {
		t.Fatalf("CreateItem: %v", err)
	}
	if header.GetRevision() != 1 || header.GetSyncVersion() != 1 {
		t.Fatalf("header = %+v", header)
	}

	got, err := client.vault.GetItem(authCtx, &gophkeeperv1.GetItemRequest{Id: header.GetId()})
	if err != nil {
		t.Fatalf("GetItem: %v", err)
	}
	if string(got.GetCiphertext()) != "cipher" {
		t.Fatalf("ciphertext = %q", got.GetCiphertext())
	}

	updated, err := client.vault.UpdateItem(authCtx, &gophkeeperv1.UpdateItemRequest{
		Id:               header.GetId(),
		ExpectedRevision: 1,
		Nonce:            []byte("abcdefghijkl"),
		Ciphertext:       []byte("new"),
	})
	if err != nil {
		t.Fatalf("UpdateItem: %v", err)
	}
	if updated.GetRevision() != 2 {
		t.Fatalf("updated revision = %d, want 2", updated.GetRevision())
	}

	syncResp, err := client.vault.Sync(authCtx, &gophkeeperv1.SyncRequest{AfterSyncVersion: 1})
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(syncResp.GetItems()) != 1 || syncResp.GetCurrentSyncVersion() != 2 {
		t.Fatalf("sync response = %+v", syncResp)
	}

	if _, err := client.vault.DeleteItem(authCtx, &gophkeeperv1.DeleteItemRequest{Id: header.GetId(), ExpectedRevision: 1}); err == nil {
		t.Fatal("DeleteItem accepted stale revision")
	}
	deleted, err := client.vault.DeleteItem(authCtx, &gophkeeperv1.DeleteItemRequest{Id: header.GetId(), ExpectedRevision: 2})
	if err != nil {
		t.Fatalf("DeleteItem: %v", err)
	}
	if deleted.GetHeader().GetDeletedAt() == nil {
		t.Fatal("delete response has no tombstone")
	}
}

func TestServerRejectsMissingAuth(t *testing.T) {
	ctx := context.Background()
	client, cleanup := newTestClient(t)
	defer cleanup()

	if _, err := client.vault.ListItems(ctx, &gophkeeperv1.ListItemsRequest{}); err == nil {
		t.Fatal("ListItems accepted missing auth")
	}
}

func TestServerValidationErrors(t *testing.T) {
	ctx := context.Background()
	client, cleanup := newTestClient(t)
	defer cleanup()

	if _, err := client.auth.Register(ctx, &gophkeeperv1.RegisterRequest{Login: "a", Password: "short"}); err == nil {
		t.Fatal("Register accepted invalid input")
	}
	authResp, err := client.auth.Register(ctx, &gophkeeperv1.RegisterRequest{
		Login:    "alice",
		Password: "password-1",
		KdfSalt:  []byte("1234567890123456"),
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	authCtx := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+authResp.GetAccessToken())
	if _, err := client.vault.GetItem(authCtx, &gophkeeperv1.GetItemRequest{Id: "bad"}); err == nil {
		t.Fatal("GetItem accepted bad uuid")
	}
	if _, err := client.vault.CreateItem(authCtx, &gophkeeperv1.CreateItemRequest{Nonce: []byte("short"), Ciphertext: []byte("cipher")}); err == nil {
		t.Fatal("CreateItem accepted bad nonce")
	}
}

type testClient struct {
	auth  gophkeeperv1.AuthServiceClient
	vault gophkeeperv1.VaultServiceClient
}

func newTestClient(t *testing.T) (testClient, func()) {
	t.Helper()
	listener := bufconn.Listen(1024 * 1024)
	tokenManager, err := auth.NewTokenManager(strings.Repeat("a", 32), time.Hour, "gophkeeper")
	if err != nil {
		t.Fatalf("NewTokenManager: %v", err)
	}
	userRepo := newTransportMemoryUsers()
	vaultRepo := newTransportMemoryVault()
	authUseCase := usecase.NewAuthUseCase(userRepo, transportPasswordService{}, tokenManager)
	vaultUseCase := usecase.NewVaultUseCase(vaultRepo)
	server := gogrpc.NewServer()
	RegisterServices(server, NewServer(authUseCase, vaultUseCase, tokenManager))
	go func() {
		_ = server.Serve(listener)
	}()

	ctx := context.Background()
	conn, err := gogrpc.DialContext(ctx, "bufnet",
		gogrpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return listener.Dial()
		}),
		gogrpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	cleanup := func() {
		conn.Close()
		server.Stop()
		listener.Close()
	}
	return testClient{
		auth:  gophkeeperv1.NewAuthServiceClient(conn),
		vault: gophkeeperv1.NewVaultServiceClient(conn),
	}, cleanup
}

type transportMemoryUsers struct {
	byID    map[uuid.UUID]entity.User
	byLogin map[string]entity.User
}

func newTransportMemoryUsers() *transportMemoryUsers {
	return &transportMemoryUsers{byID: map[uuid.UUID]entity.User{}, byLogin: map[string]entity.User{}}
}

func (m *transportMemoryUsers) Create(_ context.Context, user entity.User) error {
	if _, ok := m.byLogin[user.Login]; ok {
		return apperrors.ErrAlreadyExists
	}
	m.byID[user.ID] = user
	m.byLogin[user.Login] = user
	return nil
}

func (m *transportMemoryUsers) GetByLogin(_ context.Context, login string) (entity.User, error) {
	user, ok := m.byLogin[login]
	if !ok {
		return entity.User{}, apperrors.ErrNotFound
	}
	return user, nil
}

func (m *transportMemoryUsers) GetByID(_ context.Context, id uuid.UUID) (entity.User, error) {
	user, ok := m.byID[id]
	if !ok {
		return entity.User{}, apperrors.ErrNotFound
	}
	return user, nil
}

type transportPasswordService struct{}

func (transportPasswordService) Hash(password string) (string, error) {
	return "hash:" + password, nil
}

func (transportPasswordService) Verify(password, encodedHash string) (bool, error) {
	return encodedHash == "hash:"+password, nil
}

type transportMemoryVault struct {
	items map[uuid.UUID]entity.VaultItem
	sync  uint64
}

func newTransportMemoryVault() *transportMemoryVault {
	return &transportMemoryVault{items: map[uuid.UUID]entity.VaultItem{}}
}

func (m *transportMemoryVault) Create(_ context.Context, item entity.VaultItem) (entity.VaultItem, error) {
	m.sync++
	item.Revision = 1
	item.SyncVersion = m.sync
	m.items[item.ID] = item
	return item, nil
}

func (m *transportMemoryVault) Update(_ context.Context, item entity.VaultItem, expectedRevision int64) (entity.VaultItem, error) {
	current, ok := m.items[item.ID]
	if !ok {
		return entity.VaultItem{}, apperrors.ErrNotFound
	}
	if current.Revision != expectedRevision || current.IsDeleted() {
		return entity.VaultItem{}, apperrors.ErrConflict
	}
	m.sync++
	current.Revision++
	current.SyncVersion = m.sync
	current.Payload = item.Payload
	current.UpdatedAt = item.UpdatedAt
	m.items[item.ID] = current
	return current, nil
}

func (m *transportMemoryVault) Delete(_ context.Context, userID, itemID uuid.UUID, expectedRevision int64) (entity.VaultItem, error) {
	current, ok := m.items[itemID]
	if !ok || current.UserID != userID {
		return entity.VaultItem{}, apperrors.ErrNotFound
	}
	if current.Revision != expectedRevision || current.IsDeleted() {
		return entity.VaultItem{}, apperrors.ErrConflict
	}
	m.sync++
	current.Revision++
	current.SyncVersion = m.sync
	now := time.Now().UTC()
	current.UpdatedAt = now
	current.DeletedAt = &now
	current.Payload = entity.EncryptedPayload{}
	m.items[itemID] = current
	return current, nil
}

func (m *transportMemoryVault) Get(_ context.Context, userID, itemID uuid.UUID) (entity.VaultItem, error) {
	item, ok := m.items[itemID]
	if !ok || item.UserID != userID || item.IsDeleted() {
		return entity.VaultItem{}, apperrors.ErrNotFound
	}
	return item, nil
}

func (m *transportMemoryVault) List(_ context.Context, userID uuid.UUID, includeDeleted bool) ([]entity.VaultItem, error) {
	var out []entity.VaultItem
	for _, item := range m.items {
		if item.UserID == userID && (includeDeleted || !item.IsDeleted()) {
			out = append(out, item)
		}
	}
	return out, nil
}

func (m *transportMemoryVault) Sync(_ context.Context, userID uuid.UUID, afterSyncVersion uint64) ([]entity.VaultItem, uint64, error) {
	var out []entity.VaultItem
	for _, item := range m.items {
		if item.UserID == userID && item.SyncVersion > afterSyncVersion {
			out = append(out, item)
		}
	}
	return out, m.sync, nil
}
