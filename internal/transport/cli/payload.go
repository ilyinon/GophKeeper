package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	vaultcrypto "github.com/oilyin/gophkeeper/internal/crypto"
	"github.com/oilyin/gophkeeper/internal/entity"
	apperrors "github.com/oilyin/gophkeeper/internal/errors"
)

type loginPasswordData struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

type textData struct {
	Text string `json:"text"`
}

type binaryData struct {
	Filename string `json:"filename"`
	Content  []byte `json:"content"`
}

type cardData struct {
	Number string `json:"number"`
	Holder string `json:"holder"`
	Expiry string `json:"expiry"`
	CVV    string `json:"cvv"`
}

func buildPayload(flags itemFlags) ([]byte, error) {
	itemType := entity.VaultItemType(flags.itemType)
	var data any
	switch itemType {
	case entity.VaultItemTypeLoginPassword:
		if flags.username == "" || flags.secret == "" {
			return nil, fmt.Errorf("%w: username and secret are required", apperrors.ErrInvalidInput)
		}
		data = loginPasswordData{Login: flags.username, Password: flags.secret}
	case entity.VaultItemTypeText:
		text := flags.text
		if text == "" && flags.file != "" {
			content, err := os.ReadFile(flags.file)
			if err != nil {
				return nil, fmt.Errorf("read text file: %w", err)
			}
			text = string(content)
		}
		if text == "" {
			return nil, fmt.Errorf("%w: text or file is required", apperrors.ErrInvalidInput)
		}
		data = textData{Text: text}
	case entity.VaultItemTypeBinary:
		if flags.file == "" {
			return nil, fmt.Errorf("%w: file is required for binary item", apperrors.ErrInvalidInput)
		}
		content, err := os.ReadFile(flags.file)
		if err != nil {
			return nil, fmt.Errorf("read binary file: %w", err)
		}
		data = binaryData{Filename: flags.file, Content: content}
	case entity.VaultItemTypeCard:
		if flags.cardNumber == "" || flags.cardHolder == "" || flags.cardExpiry == "" {
			return nil, fmt.Errorf("%w: card-number, card-holder and card-expiry are required", apperrors.ErrInvalidInput)
		}
		data = cardData{Number: flags.cardNumber, Holder: flags.cardHolder, Expiry: flags.cardExpiry, CVV: flags.cardCVV}
	default:
		return nil, fmt.Errorf("%w: unsupported item type", apperrors.ErrInvalidInput)
	}
	encodedData, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("encode payload data: %w", err)
	}
	payload := entity.VaultPayload{
		SchemaVersion: entity.PayloadSchemaVersion,
		Type:          itemType,
		Name:          flags.name,
		Metadata:      parseMetadata(flags.metadata),
		Data:          encodedData,
	}
	encodedPayload, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("encode vault payload: %w", err)
	}
	return encodedPayload, nil
}

func decryptPayload(cipher *vaultcrypto.Cipher, item entity.VaultItem) (entity.VaultPayload, error) {
	plaintext, err := cipher.Decrypt(item.Payload.Nonce, item.Payload.Ciphertext)
	if err != nil {
		return entity.VaultPayload{}, err
	}
	var payload entity.VaultPayload
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return entity.VaultPayload{}, fmt.Errorf("decode vault payload: %w", err)
	}
	return payload, nil
}

func parseMetadata(values []string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]string, len(values))
	for _, value := range values {
		key, raw, ok := strings.Cut(value, "=")
		if !ok {
			out[value] = ""
			continue
		}
		out[strings.TrimSpace(key)] = strings.TrimSpace(raw)
	}
	return out
}
