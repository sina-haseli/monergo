// Copyright (c) 2014-2026, The Monero Project
// Copyright (c) 2026, The monergo Authors
// SPDX-License-Identifier: BSD-3-Clause

package tx

import (
	"fmt"
)

// tx_extra tags (src/cryptonote_basic/tx_extra.h).
const (
	ExtraTagPadding           = 0x00
	ExtraTagPubKey            = 0x01
	ExtraTagNonce             = 0x02
	ExtraTagMergeMining       = 0x03
	ExtraTagAdditionalPubKeys = 0x04
	ExtraTagMinergate         = 0xde

	ExtraNoncePaymentID          = 0x00
	ExtraNonceEncryptedPaymentID = 0x01

	extraPaddingMaxCount = 255
	extraNonceMaxCount   = 255
)

// ExtraField is one parsed tx_extra field. Only the members for Tag are set.
type ExtraField struct {
	Tag               byte
	PaddingSize       int        // padding: total size including the tag byte
	PubKey            [32]byte   // pubkey
	Nonce             []byte     // nonce
	MergeMiningDepth  uint64     // merge mining
	MergeMiningRoot   [32]byte   // merge mining
	AdditionalPubKeys [][32]byte // additional pubkeys
	Data              []byte     // minergate
}

// ParseExtra parses tx_extra into fields. On error it returns the fields parsed
// before the bad one, as wallets do when they tolerate partial extra.
//
// Ported from monero src/cryptonote_basic/cryptonote_format_utils.cpp:
// parse_tx_extra, with the field serializers in tx_extra.h.
func ParseExtra(extra []byte) ([]ExtraField, error) {
	var fields []ExtraField
	r := &reader{b: extra}
	for r.remaining() > 0 {
		tag, _ := r.byte()
		f := ExtraField{Tag: tag}
		switch tag {
		case ExtraTagPadding:
			// tx_extra_padding: zeros to the end of extra, at most 255 bytes in all.
			size := 1
			for ; size <= extraPaddingMaxCount; size++ {
				if r.remaining() == 0 {
					break
				}
				c, _ := r.byte()
				if c != 0 {
					return fields, fmt.Errorf("%w: non-zero padding", ErrMalformed)
				}
			}
			if size > extraPaddingMaxCount {
				return fields, fmt.Errorf("%w: padding too long", ErrMalformed)
			}
			f.PaddingSize = size
		case ExtraTagPubKey:
			k, err := r.key()
			if err != nil {
				return fields, err
			}
			f.PubKey = k
		case ExtraTagNonce:
			n, err := r.count(1)
			if err != nil {
				return fields, err
			}
			if n > extraNonceMaxCount {
				return fields, fmt.Errorf("%w: nonce too long", ErrMalformed)
			}
			if f.Nonce, err = r.bytes(n); err != nil {
				return fields, err
			}
		case ExtraTagMergeMining:
			n, err := r.count(1)
			if err != nil {
				return fields, err
			}
			inner, err := r.bytes(n)
			if err != nil {
				return fields, err
			}
			ir := &reader{b: inner}
			if f.MergeMiningDepth, err = ir.varint(); err != nil {
				return fields, err
			}
			if f.MergeMiningRoot, err = ir.key(); err != nil {
				return fields, err
			}
			if ir.remaining() != 0 {
				return fields, fmt.Errorf("%w: merge mining tag size", ErrMalformed)
			}
		case ExtraTagAdditionalPubKeys:
			keys, err := r.keyVector()
			if err != nil {
				return fields, err
			}
			f.AdditionalPubKeys = keys
		case ExtraTagMinergate:
			n, err := r.count(1)
			if err != nil {
				return fields, err
			}
			if f.Data, err = r.bytes(n); err != nil {
				return fields, err
			}
		default:
			return fields, fmt.Errorf("%w: unknown extra tag %#x", ErrMalformed, tag)
		}
		fields = append(fields, f)
	}
	return fields, nil
}

// SerializeExtra encodes fields in the given order.
func SerializeExtra(fields []ExtraField) ([]byte, error) {
	w := &writer{}
	for _, f := range fields {
		if err := appendExtraField(w, f); err != nil {
			return nil, err
		}
	}
	return w.b, nil
}

func appendExtraField(w *writer, f ExtraField) error {
	w.byte(f.Tag)
	switch f.Tag {
	case ExtraTagPadding:
		if f.PaddingSize < 1 || f.PaddingSize > extraPaddingMaxCount {
			return fmt.Errorf("%w: padding size %d", ErrMalformed, f.PaddingSize)
		}
		w.bytes(make([]byte, f.PaddingSize-1))
	case ExtraTagPubKey:
		w.key(f.PubKey)
	case ExtraTagNonce:
		if len(f.Nonce) > extraNonceMaxCount {
			return fmt.Errorf("%w: nonce too long", ErrMalformed)
		}
		w.varint(uint64(len(f.Nonce)))
		w.bytes(f.Nonce)
	case ExtraTagMergeMining:
		inner := &writer{}
		inner.varint(f.MergeMiningDepth)
		inner.key(f.MergeMiningRoot)
		w.varint(uint64(len(inner.b)))
		w.bytes(inner.b)
	case ExtraTagAdditionalPubKeys:
		w.keyVector(f.AdditionalPubKeys)
	case ExtraTagMinergate:
		w.varint(uint64(len(f.Data)))
		w.bytes(f.Data)
	default:
		return fmt.Errorf("%w: unknown extra tag %#x", ErrMalformed, f.Tag)
	}
	return nil
}

// TxPubKey returns the first tx public key in extra.
//
// Ported from monero src/cryptonote_basic/cryptonote_format_utils.cpp:
// get_tx_pub_key_from_extra (index 0).
func TxPubKey(fields []ExtraField) ([32]byte, bool) {
	for _, f := range fields {
		if f.Tag == ExtraTagPubKey {
			return f.PubKey, true
		}
	}
	return [32]byte{}, false
}

// AdditionalPubKeys returns the additional tx public keys, if any.
//
// Ported from monero src/cryptonote_basic/cryptonote_format_utils.cpp:
// get_additional_tx_pub_keys_from_extra.
func AdditionalPubKeys(fields []ExtraField) [][32]byte {
	for _, f := range fields {
		if f.Tag == ExtraTagAdditionalPubKeys {
			return f.AdditionalPubKeys
		}
	}
	return nil
}

// EncryptedPaymentID returns the 8-byte encrypted payment ID from the extra nonce.
//
// Ported from monero src/cryptonote_basic/cryptonote_format_utils.cpp:
// get_encrypted_payment_id_from_tx_extra_nonce.
func EncryptedPaymentID(fields []ExtraField) ([8]byte, bool) {
	for _, f := range fields {
		if f.Tag == ExtraTagNonce && len(f.Nonce) == 9 && f.Nonce[0] == ExtraNonceEncryptedPaymentID {
			return [8]byte(f.Nonce[1:]), true
		}
	}
	return [8]byte{}, false
}
