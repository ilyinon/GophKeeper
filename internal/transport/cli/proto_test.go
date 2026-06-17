package cli

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/timestamppb"

	localsqlite "github.com/oilyin/gophkeeper/internal/repository/sqlite"
	gophkeeperv1 "github.com/oilyin/gophkeeper/internal/transport/grpc/pb/gophkeeper/v1"
)

func TestItemFromParts(t *testing.T) {
	id := uuid.New()
	now := time.Now().UTC()
	item, err := itemFromParts(&gophkeeperv1.ItemHeader{
		Id:          id.String(),
		Revision:    3,
		SyncVersion: 7,
		CreatedAt:   timestamppb.New(now),
		UpdatedAt:   timestamppb.New(now),
	}, []byte("123456789012"), []byte("cipher"))
	if err != nil {
		t.Fatalf("itemFromParts: %v", err)
	}
	if item.ID != id || item.Revision != 3 || item.SyncVersion != 7 {
		t.Fatalf("item = %+v", item)
	}
}

func TestProtoItemsToEntityAndAuthContext(t *testing.T) {
	id := uuid.New()
	items, err := protoItemsToEntity([]*gophkeeperv1.EncryptedItem{{
		Header: &gophkeeperv1.ItemHeader{
			Id:          id.String(),
			Revision:    1,
			SyncVersion: 2,
			CreatedAt:   timestamppb.Now(),
			UpdatedAt:   timestamppb.Now(),
		},
		Nonce:      []byte("123456789012"),
		Ciphertext: []byte("cipher"),
	}})
	if err != nil {
		t.Fatalf("protoItemsToEntity: %v", err)
	}
	if len(items) != 1 || items[0].ID != id {
		t.Fatalf("items = %+v", items)
	}

	ctx := authContext(context.Background(), localsqlite.Session{AccessToken: "token"})
	md, ok := metadata.FromOutgoingContext(ctx)
	if !ok || len(md.Get("authorization")) != 1 {
		t.Fatalf("metadata = %+v", md)
	}
}
