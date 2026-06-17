package entity

import "encoding/json"

// PayloadSchemaVersion is the current client-side encrypted payload schema.
const PayloadSchemaVersion = 1

// VaultPayload is the plaintext JSON envelope encrypted by the CLI client.
type VaultPayload struct {
	SchemaVersion int               `json:"schema_version"`
	Type          VaultItemType     `json:"type"`
	Name          string            `json:"name"`
	Metadata      map[string]string `json:"metadata,omitempty"`
	Data          json.RawMessage   `json:"data"`
}
