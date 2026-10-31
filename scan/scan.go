// Copyright (c) 2014-2026, The Monero Project
// Copyright (c) 2026, The monergo Authors
// SPDX-License-Identifier: BSD-3-Clause

// Package scan decides output ownership and derives the one-time keys, key images,
// amounts and commitment masks of owned outputs.
//
// Ported from monero src/cryptonote_basic/cryptonote_format_utils.cpp
// @3fd0f88c20f559839cafb20911cb13cb45eba7bd: is_out_to_acc_precomp,
// generate_key_image_helper and generate_key_image_helper_precomp.
package scan

import (
	"errors"

	"filippo.io/edwards25519"
	"github.com/sina-haseli/monergo/keys"
	"github.com/sina-haseli/monergo/primitives"
	"github.com/sina-haseli/monergo/ringct"
)

// ErrNotOwned is returned when an output does not belong to the account.
var ErrNotOwned = errors.New("scan: output does not belong to this account")

// Output identifies one transaction output.
type Output struct {
	TxPubKey            keys.PublicKey
	AdditionalTxPubKeys []keys.PublicKey
	OutputIndex         uint64 // index of the output inside its transaction
	OutputKey           keys.PublicKey
	ViewTag             *keys.ViewTag // optional; skips derivation work when it does not match
}

// SubaddressTable maps subaddress spend keys to their index.
type SubaddressTable map[keys.PublicKey]keys.SubaddressIndex

// NewSubaddressTable returns the table for accounts 0..majors-1 and addresses
// 0..minors-1 of each.
//
// Ported from monero src/device/device_default.cpp: get_subaddress_spend_public_keys.
func NewSubaddressTable(acct keys.AccountKeys, majors, minors uint32) (SubaddressTable, error) {
	spendPub, err := acct.Spend.PublicKey()
	if err != nil {
		return nil, err
	}
	t := SubaddressTable{}
	for major := uint32(0); major < majors; major++ {
		for minor := uint32(0); minor < minors; minor++ {
			idx := keys.SubaddressIndex{Major: major, Minor: minor}
			D, err := keys.SubaddressSpendPublicKey(spendPub, acct.View, idx)
			if err != nil {
				return nil, err
			}
			t[D] = idx
		}
	}
	return t, nil
}

// Received is the result of matching an output to the account.
type Received struct {
	Subaddress keys.SubaddressIndex
	Derivation keys.KeyDerivation
}

// identityDerivation is what upstream substitutes when a derivation fails.
var identityDerivation = keys.KeyDerivation(ringct.IdentityBytes)

func derivation(pub keys.PublicKey, view keys.SecretKey) keys.KeyDerivation {
	d, err := keys.GenerateKeyDerivation(pub, view)
	if err != nil {
		return identityDerivation // upstream: memcpy(&recv_derivation, rct::identity())
	}
	return d
}

func canBeToAccount(tag *keys.ViewTag, d keys.KeyDerivation, i uint64) bool {
	return tag == nil || keys.DeriveViewTag(d, i) == *tag
}

// Find returns which subaddress in table received out, trying the shared tx public
// key first and then the output's additional tx public key.
//
// Ported from monero src/cryptonote_basic/cryptonote_format_utils.cpp:
// is_out_to_acc_precomp, with the derivations of generate_key_image_helper.
func Find(table SubaddressTable, view keys.SecretKey, out Output) (Received, error) {
	d := derivation(out.TxPubKey, view)
	if canBeToAccount(out.ViewTag, d, out.OutputIndex) {
		D, err := keys.DeriveSubaddressPublicKey(out.OutputKey, d, out.OutputIndex)
		if err != nil {
			return Received{}, err
		}
		if idx, ok := table[D]; ok {
			return Received{Subaddress: idx, Derivation: d}, nil
		}
	}
	if len(out.AdditionalTxPubKeys) > 0 {
		if out.OutputIndex >= uint64(len(out.AdditionalTxPubKeys)) {
			return Received{}, errors.New("scan: wrong number of additional derivations")
		}
		ad := derivation(out.AdditionalTxPubKeys[out.OutputIndex], view)
		if canBeToAccount(out.ViewTag, ad, out.OutputIndex) {
			D, err := keys.DeriveSubaddressPublicKey(out.OutputKey, ad, out.OutputIndex)
			if err != nil {
				return Received{}, err
			}
			if idx, ok := table[D]; ok {
				return Received{Subaddress: idx, Derivation: ad}, nil
			}
		}
	}
	return Received{}, ErrNotOwned
}

// Opened is an owned output's private data.
type Opened struct {
	Received
	OneTimeSecret keys.SecretKey
	KeyImage      keys.KeyImage
	AmountKey     ringct.Key // Hs(derivation ‖ output index)
}

// Wipe zeroes the secret parts.
func (o *Opened) Wipe() {
	o.OneTimeSecret.Wipe()
	clear(o.AmountKey[:])
}

// Open finds the receiving subaddress of out, derives its one-time secret key and
// checks that it opens the output key, and computes the key image.
//
// Ported from monero src/cryptonote_basic/cryptonote_format_utils.cpp:
// generate_key_image_helper and generate_key_image_helper_precomp.
func Open(acct keys.AccountKeys, table SubaddressTable, out Output) (Opened, error) {
	rec, err := Find(table, acct.View, out)
	if err != nil {
		return Opened{}, err
	}
	x, err := acct.OneTimeSecretKey(rec.Derivation, out.OutputIndex, rec.Subaddress)
	if err != nil {
		return Opened{}, err
	}
	pub, err := x.PublicKey()
	if err != nil || pub != out.OutputKey {
		x.Wipe()
		return Opened{}, errors.New("scan: derived public key does not match the output key")
	}
	ki, err := keys.GenerateKeyImage(out.OutputKey, x)
	if err != nil {
		x.Wipe()
		return Opened{}, err
	}
	s := keys.DerivationToScalar(rec.Derivation, out.OutputIndex)
	ak := ringct.Key(s.Bytes())
	primitives.WipeScalar(s)
	return Opened{Received: rec, OneTimeSecret: x, KeyImage: ki, AmountKey: ak}, nil
}

// Mask returns the commitment mask of an opened RingCT (type 4+) output.
func (o *Opened) Mask() *edwards25519.Scalar { return ringct.GenCommitmentMask(o.AmountKey) }

// OwnedOutput is an output together with the subaddress it was received at, as a
// stateless signer is told by its caller.
type OwnedOutput struct {
	Output
	Subaddress keys.SubaddressIndex
}

// KeyImages returns the key image of each output, failing if any output does not
// belong to acct at its stated subaddress.
func KeyImages(acct keys.AccountKeys, outputs []OwnedOutput) ([]keys.KeyImage, error) {
	spendPub, err := acct.Spend.PublicKey()
	if err != nil {
		return nil, err
	}
	out := make([]keys.KeyImage, len(outputs))
	for i, o := range outputs {
		D, err := keys.SubaddressSpendPublicKey(spendPub, acct.View, o.Subaddress)
		if err != nil {
			return nil, err
		}
		opened, err := Open(acct, SubaddressTable{D: o.Subaddress}, o.Output)
		if err != nil {
			return nil, err
		}
		out[i] = opened.KeyImage
		opened.Wipe()
	}
	return out, nil
}
