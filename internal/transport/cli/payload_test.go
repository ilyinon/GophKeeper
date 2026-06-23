package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	vaultcrypto "github.com/oilyin/gophkeeper/internal/crypto"
	"github.com/oilyin/gophkeeper/internal/entity"
)

func TestBuildPayloadLoginPassword(t *testing.T) {
	encoded, err := buildPayload(itemFlags{
		itemType: string(entity.VaultItemTypeLoginPassword),
		name:     "example",
		metadata: []string{"site=example.com"},
		username: "alice",
		secret:   "secret",
	})
	if err != nil {
		t.Fatalf("buildPayload: %v", err)
	}
	var payload entity.VaultPayload
	if err := json.Unmarshal(encoded, &payload); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if payload.SchemaVersion != entity.PayloadSchemaVersion || payload.Type != entity.VaultItemTypeLoginPassword || payload.Metadata["site"] != "example.com" {
		t.Fatalf("payload = %+v", payload)
	}
}

func TestBuildPayloadBinary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret.bin")
	if err := os.WriteFile(path, []byte{1, 2, 3}, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	encoded, err := buildPayload(itemFlags{
		itemType: string(entity.VaultItemTypeBinary),
		name:     "file",
		file:     path,
	})
	if err != nil {
		t.Fatalf("buildPayload: %v", err)
	}
	var payload entity.VaultPayload
	if err := json.Unmarshal(encoded, &payload); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if payload.Type != entity.VaultItemTypeBinary {
		t.Fatalf("type = %s", payload.Type)
	}
}

func TestBuildPayloadRejectsUnsupportedType(t *testing.T) {
	if _, err := buildPayload(itemFlags{itemType: "unknown", name: "bad"}); err == nil {
		t.Fatal("buildPayload accepted unsupported type")
	}
}

func TestDecryptPayload(t *testing.T) {
	key := vaultcrypto.DeriveVaultKey("password", bytes.Repeat([]byte{1}, vaultcrypto.SaltSize), vaultcrypto.NewVaultKeyParams())
	cipher, err := vaultcrypto.NewAESGCM(key)
	if err != nil {
		t.Fatalf("NewAESGCM: %v", err)
	}
	encoded, err := buildPayload(itemFlags{itemType: string(entity.VaultItemTypeText), name: "note", text: "hello"})
	if err != nil {
		t.Fatalf("buildPayload: %v", err)
	}
	nonce, ciphertext, err := cipher.Encrypt(encoded)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	payload, err := decryptPayload(cipher, entity.VaultItem{Payload: entity.EncryptedPayload{Nonce: nonce, Ciphertext: ciphertext}})
	if err != nil {
		t.Fatalf("decryptPayload: %v", err)
	}
	if payload.Name != "note" || payload.Type != entity.VaultItemTypeText {
		t.Fatalf("payload = %+v", payload)
	}
}
