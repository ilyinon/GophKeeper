// Package cli adapts GophKeeper client workflows to a Cobra CLI.
package cli

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	gogrpc "google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	"github.com/oilyin/gophkeeper/internal/config"
	vaultcrypto "github.com/oilyin/gophkeeper/internal/crypto"
	"github.com/oilyin/gophkeeper/internal/entity"
	apperrors "github.com/oilyin/gophkeeper/internal/errors"
	localsqlite "github.com/oilyin/gophkeeper/internal/repository/sqlite"
	gophkeeperv1 "github.com/oilyin/gophkeeper/internal/transport/grpc/pb/gophkeeper/v1"
)

// VersionInfo contains CLI build metadata.
type VersionInfo struct {
	Version string
	Date    string
}

type app struct {
	cfg     config.ClientConfig
	version VersionInfo
}

type authFlags struct {
	login    string
	password string
}

type itemFlags struct {
	login       string
	password    string
	itemType    string
	name        string
	metadata    []string
	text        string
	file        string
	username    string
	secret      string
	cardNumber  string
	cardHolder  string
	cardExpiry  string
	cardCVV     string
	revision    int64
	offline     bool
	includeGone bool
}

// NewRootCommand creates the gophkeeper-client root command.
func NewRootCommand(version VersionInfo) *cobra.Command {
	a := &app{cfg: config.LoadClient(), version: version}
	root := &cobra.Command{
		Use:   "gophkeeper-client",
		Short: "GophKeeper CLI client",
	}
	root.PersistentFlags().StringVar(&a.cfg.ServerAddr, "server", a.cfg.ServerAddr, "gRPC server address")
	root.PersistentFlags().StringVar(&a.cfg.CachePath, "cache", a.cfg.CachePath, "SQLite cache path")
	root.PersistentFlags().StringVar(&a.cfg.TLSCAFile, "tls-ca", a.cfg.TLSCAFile, "TLS CA certificate file")
	root.PersistentFlags().BoolVar(&a.cfg.Insecure, "insecure", a.cfg.Insecure, "use plaintext gRPC transport")

	root.AddCommand(a.versionCommand())
	root.AddCommand(a.registerCommand())
	root.AddCommand(a.loginCommand())
	root.AddCommand(a.syncCommand())
	root.AddCommand(a.addCommand())
	root.AddCommand(a.listCommand())
	root.AddCommand(a.getCommand())
	root.AddCommand(a.updateCommand())
	root.AddCommand(a.deleteCommand())
	return root
}

func (a *app) versionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print client version",
		Run: func(cmd *cobra.Command, _ []string) {
			cmd.Printf("version=%s build_date=%s\n", a.version.Version, a.version.Date)
		},
	}
}

func (a *app) registerCommand() *cobra.Command {
	var flags authFlags
	cmd := &cobra.Command{
		Use:   "register",
		Short: "Register a new user",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			password, err := readPassword(flags.password)
			if err != nil {
				return err
			}
			kdfSalt, err := vaultcrypto.RandomBytes(vaultcrypto.SaltSize)
			if err != nil {
				return err
			}
			conn, err := a.dial(ctx)
			if err != nil {
				return err
			}
			defer conn.Close()
			resp, err := gophkeeperv1.NewAuthServiceClient(conn).Register(ctx, &gophkeeperv1.RegisterRequest{
				Login:    flags.login,
				Password: password,
				KdfSalt:  kdfSalt,
			})
			if err != nil {
				return err
			}
			session, err := sessionFromAuth(a.cfg.ServerAddr, flags.login, resp)
			if err != nil {
				return err
			}
			if err := a.saveSession(ctx, session); err != nil {
				return err
			}
			cmd.Printf("registered user %s\n", flags.login)
			return nil
		},
	}
	cmd.Flags().StringVar(&flags.login, "login", "", "user login")
	cmd.Flags().StringVar(&flags.password, "password", "", "user password")
	_ = cmd.MarkFlagRequired("login")
	return cmd
}

func (a *app) loginCommand() *cobra.Command {
	var flags authFlags
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Login and store a local session",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			password, err := readPassword(flags.password)
			if err != nil {
				return err
			}
			conn, err := a.dial(ctx)
			if err != nil {
				return err
			}
			defer conn.Close()
			resp, err := gophkeeperv1.NewAuthServiceClient(conn).Login(ctx, &gophkeeperv1.LoginRequest{
				Login:    flags.login,
				Password: password,
			})
			if err != nil {
				return err
			}
			session, err := sessionFromAuth(a.cfg.ServerAddr, flags.login, resp)
			if err != nil {
				return err
			}
			if err := a.saveSession(ctx, session); err != nil {
				return err
			}
			cmd.Printf("logged in as %s\n", flags.login)
			return nil
		},
	}
	cmd.Flags().StringVar(&flags.login, "login", "", "user login")
	cmd.Flags().StringVar(&flags.password, "password", "", "user password")
	_ = cmd.MarkFlagRequired("login")
	return cmd
}

func (a *app) syncCommand() *cobra.Command {
	var flags itemFlags
	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Synchronize encrypted items into local cache",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			store, session, err := a.loadSession(ctx, flags.login)
			if err != nil {
				return err
			}
			defer store.Close()
			session, changed, err := a.sync(ctx, store, session)
			if err != nil {
				return err
			}
			cmd.Printf("synced %d changes, cursor=%d\n", changed, session.LastSyncVersion)
			return nil
		},
	}
	cmd.Flags().StringVar(&flags.login, "login", "", "session login")
	return cmd
}

func (a *app) addCommand() *cobra.Command {
	var flags itemFlags
	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add an encrypted vault item",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			store, session, err := a.loadSession(ctx, flags.login)
			if err != nil {
				return err
			}
			defer store.Close()
			cipher, err := unlock(session, flags.password, a.cfg.VaultKeyParams)
			if err != nil {
				return err
			}
			plaintext, err := buildPayload(flags)
			if err != nil {
				return err
			}
			nonce, ciphertext, err := cipher.Encrypt(plaintext)
			if err != nil {
				return err
			}
			conn, err := a.dial(ctx)
			if err != nil {
				return err
			}
			defer conn.Close()
			header, err := gophkeeperv1.NewVaultServiceClient(conn).CreateItem(authContext(ctx, session), &gophkeeperv1.CreateItemRequest{
				Nonce:      nonce,
				Ciphertext: ciphertext,
			})
			if err != nil {
				return err
			}
			item, err := itemFromParts(header, nonce, ciphertext)
			if err != nil {
				return err
			}
			if err := store.UpsertItems(ctx, session.UserID, []entity.VaultItem{item}); err != nil {
				return err
			}
			cmd.Printf("created item %s revision=%d\n", header.GetId(), header.GetRevision())
			return nil
		},
	}
	addItemFlags(cmd, &flags, true)
	return cmd
}

func (a *app) listCommand() *cobra.Command {
	var flags itemFlags
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List encrypted vault items",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			store, session, err := a.loadSession(ctx, flags.login)
			if err != nil {
				return err
			}
			defer store.Close()
			if !flags.offline {
				session, _, err = a.sync(ctx, store, session)
				if err != nil {
					return err
				}
			}
			cipher, err := unlock(session, flags.password, a.cfg.VaultKeyParams)
			if err != nil {
				return err
			}
			items, err := store.ListItems(ctx, session.UserID, flags.includeGone)
			if err != nil {
				return err
			}
			for _, item := range items {
				if item.IsDeleted() {
					cmd.Printf("%s\tdeleted\trevision=%d\tsync=%d\n", item.ID, item.Revision, item.SyncVersion)
					continue
				}
				payload, err := decryptPayload(cipher, item)
				if err != nil {
					return err
				}
				cmd.Printf("%s\t%s\t%s\trevision=%d\tsync=%d\n", item.ID, payload.Type, payload.Name, item.Revision, item.SyncVersion)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&flags.login, "login", "", "session login")
	cmd.Flags().StringVar(&flags.password, "password", "", "master password")
	cmd.Flags().BoolVar(&flags.offline, "offline", false, "read only local cache")
	cmd.Flags().BoolVar(&flags.includeGone, "include-deleted", false, "include deletion tombstones")
	return cmd
}

func (a *app) getCommand() *cobra.Command {
	var flags itemFlags
	cmd := &cobra.Command{
		Use:   "get ITEM_ID",
		Short: "Decrypt and print a vault item",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			store, session, err := a.loadSession(ctx, flags.login)
			if err != nil {
				return err
			}
			defer store.Close()
			itemID, err := uuid.Parse(args[0])
			if err != nil {
				return fmt.Errorf("%w: invalid item id", apperrors.ErrInvalidInput)
			}
			item, err := a.getItem(ctx, store, session, itemID, flags.offline)
			if err != nil {
				return err
			}
			cipher, err := unlock(session, flags.password, a.cfg.VaultKeyParams)
			if err != nil {
				return err
			}
			payload, err := decryptPayload(cipher, item)
			if err != nil {
				return err
			}
			encoded, err := json.MarshalIndent(payload, "", "  ")
			if err != nil {
				return err
			}
			cmd.Println(string(encoded))
			return nil
		},
	}
	cmd.Flags().StringVar(&flags.login, "login", "", "session login")
	cmd.Flags().StringVar(&flags.password, "password", "", "master password")
	cmd.Flags().BoolVar(&flags.offline, "offline", false, "read only local cache")
	return cmd
}

func (a *app) updateCommand() *cobra.Command {
	var flags itemFlags
	cmd := &cobra.Command{
		Use:   "update ITEM_ID",
		Short: "Replace an encrypted vault item",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			store, session, err := a.loadSession(ctx, flags.login)
			if err != nil {
				return err
			}
			defer store.Close()
			itemID, err := uuid.Parse(args[0])
			if err != nil {
				return fmt.Errorf("%w: invalid item id", apperrors.ErrInvalidInput)
			}
			current, err := a.getItem(ctx, store, session, itemID, false)
			if err != nil {
				return err
			}
			expectedRevision := current.Revision
			if flags.revision > 0 {
				expectedRevision = flags.revision
			}
			cipher, err := unlock(session, flags.password, a.cfg.VaultKeyParams)
			if err != nil {
				return err
			}
			plaintext, err := buildPayload(flags)
			if err != nil {
				return err
			}
			nonce, ciphertext, err := cipher.Encrypt(plaintext)
			if err != nil {
				return err
			}
			conn, err := a.dial(ctx)
			if err != nil {
				return err
			}
			defer conn.Close()
			header, err := gophkeeperv1.NewVaultServiceClient(conn).UpdateItem(authContext(ctx, session), &gophkeeperv1.UpdateItemRequest{
				Id:               itemID.String(),
				ExpectedRevision: expectedRevision,
				Nonce:            nonce,
				Ciphertext:       ciphertext,
			})
			if err != nil {
				return err
			}
			item, err := itemFromParts(header, nonce, ciphertext)
			if err != nil {
				return err
			}
			if err := store.UpsertItems(ctx, session.UserID, []entity.VaultItem{item}); err != nil {
				return err
			}
			cmd.Printf("updated item %s revision=%d\n", header.GetId(), header.GetRevision())
			return nil
		},
	}
	addItemFlags(cmd, &flags, true)
	cmd.Flags().Int64Var(&flags.revision, "revision", 0, "expected revision override")
	return cmd
}

func (a *app) deleteCommand() *cobra.Command {
	var flags itemFlags
	cmd := &cobra.Command{
		Use:   "delete ITEM_ID",
		Short: "Delete a vault item",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			store, session, err := a.loadSession(ctx, flags.login)
			if err != nil {
				return err
			}
			defer store.Close()
			itemID, err := uuid.Parse(args[0])
			if err != nil {
				return fmt.Errorf("%w: invalid item id", apperrors.ErrInvalidInput)
			}
			current, err := a.getItem(ctx, store, session, itemID, false)
			if err != nil {
				return err
			}
			expectedRevision := current.Revision
			if flags.revision > 0 {
				expectedRevision = flags.revision
			}
			conn, err := a.dial(ctx)
			if err != nil {
				return err
			}
			defer conn.Close()
			resp, err := gophkeeperv1.NewVaultServiceClient(conn).DeleteItem(authContext(ctx, session), &gophkeeperv1.DeleteItemRequest{
				Id:               itemID.String(),
				ExpectedRevision: expectedRevision,
			})
			if err != nil {
				return err
			}
			item, err := itemFromParts(resp.GetHeader(), nil, nil)
			if err != nil {
				return err
			}
			if err := store.UpsertItems(ctx, session.UserID, []entity.VaultItem{item}); err != nil {
				return err
			}
			cmd.Printf("deleted item %s revision=%d\n", itemID, resp.GetHeader().GetRevision())
			return nil
		},
	}
	cmd.Flags().StringVar(&flags.login, "login", "", "session login")
	cmd.Flags().Int64Var(&flags.revision, "revision", 0, "expected revision override")
	return cmd
}

func addItemFlags(cmd *cobra.Command, flags *itemFlags, requireName bool) {
	cmd.Flags().StringVar(&flags.login, "login", "", "session login")
	cmd.Flags().StringVar(&flags.password, "password", "", "master password")
	cmd.Flags().StringVar(&flags.itemType, "type", "", "item type: login_password, text, binary, card")
	cmd.Flags().StringVar(&flags.name, "name", "", "item name")
	cmd.Flags().StringArrayVar(&flags.metadata, "metadata", nil, "metadata key=value, repeatable")
	cmd.Flags().StringVar(&flags.text, "text", "", "text data")
	cmd.Flags().StringVar(&flags.file, "file", "", "file path for text or binary data")
	cmd.Flags().StringVar(&flags.username, "username", "", "login for login_password item")
	cmd.Flags().StringVar(&flags.secret, "secret", "", "password or secret for login_password item")
	cmd.Flags().StringVar(&flags.cardNumber, "card-number", "", "bank card number")
	cmd.Flags().StringVar(&flags.cardHolder, "card-holder", "", "bank card holder")
	cmd.Flags().StringVar(&flags.cardExpiry, "card-expiry", "", "bank card expiry")
	cmd.Flags().StringVar(&flags.cardCVV, "card-cvv", "", "bank card CVV")
	_ = cmd.MarkFlagRequired("type")
	if requireName {
		_ = cmd.MarkFlagRequired("name")
	}
}

func (a *app) dial(ctx context.Context) (*gogrpc.ClientConn, error) {
	var creds credentials.TransportCredentials
	if a.cfg.Insecure {
		creds = insecure.NewCredentials()
	} else if a.cfg.TLSCAFile != "" {
		loaded, err := credentials.NewClientTLSFromFile(a.cfg.TLSCAFile, "")
		if err != nil {
			return nil, fmt.Errorf("load tls ca: %w", err)
		}
		creds = loaded
	} else {
		creds = credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12})
	}
	conn, err := gogrpc.DialContext(ctx, a.cfg.ServerAddr, gogrpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("dial gophkeeper server: %w", err)
	}
	return conn, nil
}

func (a *app) saveSession(ctx context.Context, session localsqlite.Session) error {
	store, err := localsqlite.Open(a.cfg.CachePath)
	if err != nil {
		return err
	}
	defer store.Close()
	return store.SaveSession(ctx, session)
}

func (a *app) loadSession(ctx context.Context, login string) (*localsqlite.Store, localsqlite.Session, error) {
	store, err := localsqlite.Open(a.cfg.CachePath)
	if err != nil {
		return nil, localsqlite.Session{}, err
	}
	session, err := store.LoadSession(ctx, a.cfg.ServerAddr, login)
	if err != nil {
		_ = store.Close()
		return nil, localsqlite.Session{}, err
	}
	return store, session, nil
}

func (a *app) sync(ctx context.Context, store *localsqlite.Store, session localsqlite.Session) (localsqlite.Session, int, error) {
	conn, err := a.dial(ctx)
	if err != nil {
		return session, 0, err
	}
	defer conn.Close()
	resp, err := gophkeeperv1.NewVaultServiceClient(conn).Sync(authContext(ctx, session), &gophkeeperv1.SyncRequest{
		AfterSyncVersion: session.LastSyncVersion,
	})
	if err != nil {
		return session, 0, err
	}
	items, err := protoItemsToEntity(resp.GetItems())
	if err != nil {
		return session, 0, err
	}
	if err := store.UpsertItems(ctx, session.UserID, items); err != nil {
		return session, 0, err
	}
	session.LastSyncVersion = resp.GetCurrentSyncVersion()
	if err := store.SetLastSyncVersion(ctx, session.UserID, a.cfg.ServerAddr, session.LastSyncVersion); err != nil {
		return session, 0, err
	}
	return session, len(items), nil
}

func (a *app) getItem(ctx context.Context, store *localsqlite.Store, session localsqlite.Session, itemID uuid.UUID, offline bool) (entity.VaultItem, error) {
	if offline {
		return store.GetItem(ctx, session.UserID, itemID, false)
	}
	conn, err := a.dial(ctx)
	if err != nil {
		return entity.VaultItem{}, err
	}
	defer conn.Close()
	resp, err := gophkeeperv1.NewVaultServiceClient(conn).GetItem(authContext(ctx, session), &gophkeeperv1.GetItemRequest{
		Id: itemID.String(),
	})
	if err != nil {
		return entity.VaultItem{}, err
	}
	item, err := protoItemToEntity(resp)
	if err != nil {
		return entity.VaultItem{}, err
	}
	if err := store.UpsertItems(ctx, session.UserID, []entity.VaultItem{item}); err != nil {
		return entity.VaultItem{}, err
	}
	return item, nil
}

func sessionFromAuth(serverAddr, login string, resp *gophkeeperv1.AuthResponse) (localsqlite.Session, error) {
	userID, err := uuid.Parse(resp.GetUserId())
	if err != nil {
		return localsqlite.Session{}, fmt.Errorf("parse auth user id: %w", err)
	}
	return localsqlite.Session{
		UserID:         userID,
		Login:          strings.ToLower(strings.TrimSpace(login)),
		ServerAddr:     serverAddr,
		AccessToken:    resp.GetAccessToken(),
		TokenExpiresAt: resp.GetExpiresAt().AsTime(),
		KDFSalt:        resp.GetKdfSalt(),
	}, nil
}

func authContext(ctx context.Context, session localsqlite.Session) context.Context {
	return metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+session.AccessToken)
}

func readPassword(value string) (string, error) {
	if value != "" {
		return value, nil
	}
	fmt.Fprint(os.Stderr, "Password: ")
	password, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	return strings.TrimRight(password, "\r\n"), nil
}

func unlock(session localsqlite.Session, password string, params vaultcrypto.VaultKeyParams) (*vaultcrypto.Cipher, error) {
	actualPassword, err := readPassword(password)
	if err != nil {
		return nil, err
	}
	key := vaultcrypto.DeriveVaultKey(actualPassword, session.KDFSalt, params)
	return vaultcrypto.NewAESGCM(key)
}
