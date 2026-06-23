// Package grpctransport adapts GophKeeper use cases to gRPC services.
package grpctransport

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"strings"

	"github.com/google/uuid"
	gogrpc "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/oilyin/gophkeeper/internal/auth"
	"github.com/oilyin/gophkeeper/internal/entity"
	apperrors "github.com/oilyin/gophkeeper/internal/errors"
	gophkeeperv1 "github.com/oilyin/gophkeeper/internal/transport/grpc/pb/gophkeeper/v1"
	"github.com/oilyin/gophkeeper/internal/usecase"
)

// Server implements GophKeeper gRPC services.
type Server struct {
	gophkeeperv1.UnimplementedAuthServiceServer
	gophkeeperv1.UnimplementedVaultServiceServer

	authUseCase  *usecase.AuthUseCase
	vaultUseCase *usecase.VaultUseCase
	tokens       *auth.TokenManager
}

// NewServer creates a gRPC transport server.
func NewServer(authUseCase *usecase.AuthUseCase, vaultUseCase *usecase.VaultUseCase, tokens *auth.TokenManager) *Server {
	return &Server{authUseCase: authUseCase, vaultUseCase: vaultUseCase, tokens: tokens}
}

// RegisterServices registers GophKeeper services on registrar.
func RegisterServices(registrar gogrpc.ServiceRegistrar, server *Server) {
	gophkeeperv1.RegisterAuthServiceServer(registrar, server)
	gophkeeperv1.RegisterVaultServiceServer(registrar, server)
}

// Register creates a new account.
func (s *Server) Register(ctx context.Context, req *gophkeeperv1.RegisterRequest) (*gophkeeperv1.AuthResponse, error) {
	result, err := s.authUseCase.Register(ctx, usecase.RegisterInput{
		Login:    req.GetLogin(),
		Password: req.GetPassword(),
		KDFSalt:  req.GetKdfSalt(),
	})
	if err != nil {
		return nil, toStatusError(err)
	}
	return authResultToProto(result), nil
}

// Login authenticates an existing account.
func (s *Server) Login(ctx context.Context, req *gophkeeperv1.LoginRequest) (*gophkeeperv1.AuthResponse, error) {
	result, err := s.authUseCase.Login(ctx, usecase.LoginInput{
		Login:    req.GetLogin(),
		Password: req.GetPassword(),
	})
	if err != nil {
		return nil, toStatusError(err)
	}
	return authResultToProto(result), nil
}

// CreateItem stores a new opaque encrypted vault item.
func (s *Server) CreateItem(ctx context.Context, req *gophkeeperv1.CreateItemRequest) (*gophkeeperv1.ItemHeader, error) {
	userID, err := s.authenticate(ctx)
	if err != nil {
		return nil, toStatusError(err)
	}
	itemID, err := parseOptionalUUID(req.GetId())
	if err != nil {
		return nil, toStatusError(err)
	}
	item, err := s.vaultUseCase.Create(ctx, usecase.CreateItemInput{
		ID:     itemID,
		UserID: userID,
		Payload: usecase.ItemPayloadInput{
			Nonce:      req.GetNonce(),
			Ciphertext: req.GetCiphertext(),
		},
	})
	if err != nil {
		return nil, toStatusError(err)
	}
	return itemHeaderToProto(item), nil
}

// UpdateItem replaces an opaque encrypted vault item.
func (s *Server) UpdateItem(ctx context.Context, req *gophkeeperv1.UpdateItemRequest) (*gophkeeperv1.ItemHeader, error) {
	userID, err := s.authenticate(ctx)
	if err != nil {
		return nil, toStatusError(err)
	}
	itemID, err := parseRequiredUUID(req.GetId())
	if err != nil {
		return nil, toStatusError(err)
	}
	item, err := s.vaultUseCase.Update(ctx, usecase.UpdateItemInput{
		ID:               itemID,
		UserID:           userID,
		ExpectedRevision: req.GetExpectedRevision(),
		Payload: usecase.ItemPayloadInput{
			Nonce:      req.GetNonce(),
			Ciphertext: req.GetCiphertext(),
		},
	})
	if err != nil {
		return nil, toStatusError(err)
	}
	return itemHeaderToProto(item), nil
}

// DeleteItem tombstones an opaque encrypted vault item.
func (s *Server) DeleteItem(ctx context.Context, req *gophkeeperv1.DeleteItemRequest) (*gophkeeperv1.DeleteItemResponse, error) {
	userID, err := s.authenticate(ctx)
	if err != nil {
		return nil, toStatusError(err)
	}
	itemID, err := parseRequiredUUID(req.GetId())
	if err != nil {
		return nil, toStatusError(err)
	}
	item, err := s.vaultUseCase.Delete(ctx, usecase.DeleteItemInput{
		ID:               itemID,
		UserID:           userID,
		ExpectedRevision: req.GetExpectedRevision(),
	})
	if err != nil {
		return nil, toStatusError(err)
	}
	return &gophkeeperv1.DeleteItemResponse{Header: itemHeaderToProto(item)}, nil
}

// GetItem returns one opaque encrypted vault item.
func (s *Server) GetItem(ctx context.Context, req *gophkeeperv1.GetItemRequest) (*gophkeeperv1.EncryptedItem, error) {
	userID, err := s.authenticate(ctx)
	if err != nil {
		return nil, toStatusError(err)
	}
	itemID, err := parseRequiredUUID(req.GetId())
	if err != nil {
		return nil, toStatusError(err)
	}
	item, err := s.vaultUseCase.Get(ctx, userID, itemID)
	if err != nil {
		return nil, toStatusError(err)
	}
	return itemToProto(item), nil
}

// ListItems returns opaque encrypted vault items.
func (s *Server) ListItems(ctx context.Context, req *gophkeeperv1.ListItemsRequest) (*gophkeeperv1.ListItemsResponse, error) {
	userID, err := s.authenticate(ctx)
	if err != nil {
		return nil, toStatusError(err)
	}
	itemsSeq, err := s.vaultUseCase.List(ctx, userID, req.GetIncludeDeleted())
	if err != nil {
		return nil, toStatusError(err)
	}
	items, err := itemsToProto(itemsSeq)
	if err != nil {
		return nil, toStatusError(err)
	}
	return &gophkeeperv1.ListItemsResponse{Items: items}, nil
}

// Sync returns opaque encrypted changes after a client cursor.
func (s *Server) Sync(ctx context.Context, req *gophkeeperv1.SyncRequest) (*gophkeeperv1.SyncResponse, error) {
	userID, err := s.authenticate(ctx)
	if err != nil {
		return nil, toStatusError(err)
	}
	itemsSeq, current, err := s.vaultUseCase.Sync(ctx, userID, req.GetAfterSyncVersion())
	if err != nil {
		return nil, toStatusError(err)
	}
	items, err := itemsToProto(itemsSeq)
	if err != nil {
		return nil, toStatusError(err)
	}
	return &gophkeeperv1.SyncResponse{
		Items:              items,
		CurrentSyncVersion: current,
	}, nil
}

func (s *Server) authenticate(ctx context.Context) (uuid.UUID, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return uuid.Nil, apperrors.ErrUnauthorized
	}
	values := md.Get("authorization")
	if len(values) == 0 {
		return uuid.Nil, apperrors.ErrUnauthorized
	}
	scheme, tokenValue, ok := strings.Cut(values[0], " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || tokenValue == "" {
		return uuid.Nil, apperrors.ErrUnauthorized
	}
	return s.tokens.Verify(tokenValue)
}

func parseOptionalUUID(value string) (uuid.UUID, error) {
	if value == "" {
		return uuid.Nil, nil
	}
	return parseRequiredUUID(value)
}

func parseRequiredUUID(value string) (uuid.UUID, error) {
	parsed, err := uuid.Parse(value)
	if err != nil {
		return uuid.Nil, fmt.Errorf("%w: invalid uuid", apperrors.ErrInvalidInput)
	}
	return parsed, nil
}

func authResultToProto(result usecase.AuthResult) *gophkeeperv1.AuthResponse {
	return &gophkeeperv1.AuthResponse{
		UserId:      result.UserID.String(),
		AccessToken: result.AccessToken,
		ExpiresAt:   timestamppb.New(result.ExpiresAt),
		KdfSalt:     result.KDFSalt,
	}
}

func itemsToProto(items iter.Seq2[entity.VaultItem, error]) ([]*gophkeeperv1.EncryptedItem, error) {
	var out []*gophkeeperv1.EncryptedItem
	for item, err := range items {
		if err != nil {
			return nil, err
		}
		out = append(out, itemToProto(item))
	}
	return out, nil
}

func itemToProto(item entity.VaultItem) *gophkeeperv1.EncryptedItem {
	return &gophkeeperv1.EncryptedItem{
		Header:     itemHeaderToProto(item),
		Nonce:      item.Payload.Nonce,
		Ciphertext: item.Payload.Ciphertext,
	}
}

func itemHeaderToProto(item entity.VaultItem) *gophkeeperv1.ItemHeader {
	header := &gophkeeperv1.ItemHeader{
		Id:          item.ID.String(),
		Revision:    item.Revision,
		SyncVersion: item.SyncVersion,
		CreatedAt:   timestamppb.New(item.CreatedAt),
		UpdatedAt:   timestamppb.New(item.UpdatedAt),
	}
	if item.DeletedAt != nil {
		header.DeletedAt = timestamppb.New(*item.DeletedAt)
	}
	return header
}

func toStatusError(err error) error {
	switch {
	case errors.Is(err, apperrors.ErrInvalidInput):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, apperrors.ErrAlreadyExists):
		return status.Error(codes.AlreadyExists, err.Error())
	case errors.Is(err, apperrors.ErrNotFound):
		return status.Error(codes.NotFound, err.Error())
	case errors.Is(err, apperrors.ErrUnauthorized):
		return status.Error(codes.Unauthenticated, err.Error())
	case errors.Is(err, apperrors.ErrForbidden):
		return status.Error(codes.PermissionDenied, err.Error())
	case errors.Is(err, apperrors.ErrConflict):
		return status.Error(codes.Aborted, err.Error())
	default:
		return status.Error(codes.Internal, "internal error")
	}
}
