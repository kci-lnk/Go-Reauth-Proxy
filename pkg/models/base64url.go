package models

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// Base64URLBytes keeps compiled range blobs compact and deterministic in the
// persisted JSON config while still mapping directly to protobuf bytes.
type Base64URLBytes []byte

func (value Base64URLBytes) MarshalJSON() ([]byte, error) {
	return json.Marshal(base64.RawURLEncoding.EncodeToString(value))
}

func (value *Base64URLBytes) UnmarshalJSON(data []byte) error {
	if value == nil {
		return fmt.Errorf("cannot unmarshal base64url bytes into nil receiver")
	}
	if bytes.Equal(data, []byte("null")) {
		*value = nil
		return nil
	}
	var encoded string
	if err := json.Unmarshal(data, &encoded); err != nil {
		return err
	}
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		// Accept the standard padded representation written by early
		// development builds, then always write canonical base64url.
		decoded, err = base64.StdEncoding.DecodeString(encoded)
	}
	if err != nil {
		return fmt.Errorf("decode base64url bytes: %w", err)
	}
	*value = decoded
	return nil
}
