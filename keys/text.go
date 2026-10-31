package keys

import (
	"encoding/hex"
	"fmt"
)

func marshalHex(b []byte) ([]byte, error) {
	out := make([]byte, hex.EncodedLen(len(b)))
	hex.Encode(out, b)
	return out, nil
}

func unmarshalHex(dst []byte, text []byte) error {
	if len(text) != hex.EncodedLen(len(dst)) {
		return fmt.Errorf("keys: want %d hex characters, got %d", hex.EncodedLen(len(dst)), len(text))
	}
	_, err := hex.Decode(dst, text)
	return err
}

// MarshalText encodes the key as lowercase hex.
func (k PublicKey) MarshalText() ([]byte, error) { return marshalHex(k[:]) }

// UnmarshalText decodes 64 hex characters.
func (k *PublicKey) UnmarshalText(b []byte) error { return unmarshalHex(k[:], b) }

func (k PublicKey) String() string { return hex.EncodeToString(k[:]) }

// MarshalText encodes the key as lowercase hex.
func (k SecretKey) MarshalText() ([]byte, error) { return marshalHex(k[:]) }

// UnmarshalText decodes 64 hex characters.
func (k *SecretKey) UnmarshalText(b []byte) error { return unmarshalHex(k[:], b) }

// String never prints the secret.
func (k SecretKey) String() string { return "SecretKey(redacted)" }

// GoString never prints the secret.
func (k SecretKey) GoString() string { return k.String() }

// MarshalText encodes the key image as lowercase hex.
func (k KeyImage) MarshalText() ([]byte, error) { return marshalHex(k[:]) }

// UnmarshalText decodes 64 hex characters.
func (k *KeyImage) UnmarshalText(b []byte) error { return unmarshalHex(k[:], b) }

func (k KeyImage) String() string { return hex.EncodeToString(k[:]) }
