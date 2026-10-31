// Copyright (c) 2014-2026, The Monero Project
// Copyright (c) 2026, The monergo Authors
// SPDX-License-Identifier: BSD-3-Clause
//
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers.

// Package keys implements Monero key types and the CryptoNote key derivations:
// public keys, the shared derivation 8·a·R, one-time output keys, key images and
// view tags.
//
// Ported from monero src/crypto/crypto.cpp @3fd0f88c20f559839cafb20911cb13cb45eba7bd.
package keys

import (
	"errors"

	"filippo.io/edwards25519"
	"github.com/sina-haseli/monergo/internal/varint"
	"github.com/sina-haseli/monergo/primitives"
)

// PublicKey is a compressed Edwards point.
type PublicKey [32]byte

// SecretKey is a canonical scalar, little-endian. Call Wipe when done with it.
type SecretKey [32]byte

// KeyDerivation is the shared secret 8·a·R between a tx key and a view key.
type KeyDerivation [32]byte

// KeyImage is x·Hp(P) for a one-time key pair (x, P).
type KeyImage [32]byte

// ViewTag is the first byte of the view-tag hash (HF v15+).
type ViewTag byte

var (
	// ErrInvalidPublicKey is returned for keys that check_key rejects.
	ErrInvalidPublicKey = errors.New("keys: invalid public key")
	// ErrInvalidSecretKey is returned for secret keys that sc_check rejects.
	ErrInvalidSecretKey = errors.New("keys: non-canonical secret key")
)

// Wipe overwrites the secret key with zeros.
func (s *SecretKey) Wipe() { clear(s[:]) }

func (s *SecretKey) scalar() (*edwards25519.Scalar, error) {
	x, err := primitives.ScalarFromCanonical(*s)
	if err != nil {
		return nil, ErrInvalidSecretKey
	}
	return x, nil
}

func (p PublicKey) point() (*edwards25519.Point, error) {
	pt, err := primitives.DecodePoint(p)
	if err != nil {
		return nil, ErrInvalidPublicKey
	}
	return pt, nil
}

// PublicKey returns s·G.
//
// Ported from monero src/crypto/crypto.cpp: crypto_ops::secret_key_to_public_key.
func (s SecretKey) PublicKey() (PublicKey, error) {
	x, err := s.scalar()
	if err != nil {
		return PublicKey{}, err
	}
	defer primitives.WipeScalar(x)
	return PublicKey(new(edwards25519.Point).ScalarBaseMult(x).Bytes()), nil
}

// GenerateKeyDerivation returns 8·sec·pub. Upstream only asserts that sec is
// canonical; here a non-canonical sec is an error.
//
// Ported from monero src/crypto/crypto.cpp: crypto_ops::generate_key_derivation.
func GenerateKeyDerivation(pub PublicKey, sec SecretKey) (KeyDerivation, error) {
	pt, err := pub.point()
	if err != nil {
		return KeyDerivation{}, err
	}
	x, err := sec.scalar()
	if err != nil {
		return KeyDerivation{}, err
	}
	defer primitives.WipeScalar(x)
	r := new(edwards25519.Point).ScalarMult(x, pt)
	r.MultByCofactor(r)
	return KeyDerivation(r.Bytes()), nil
}

// DerivationToScalar returns Hs(derivation ‖ varint(outputIndex)).
//
// Ported from monero src/crypto/crypto.cpp: crypto_ops::derivation_to_scalar.
func DerivationToScalar(d KeyDerivation, outputIndex uint64) *edwards25519.Scalar {
	buf := make([]byte, 0, 32+10)
	buf = append(buf, d[:]...)
	buf = varint.Append(buf, outputIndex)
	s := primitives.HashToScalar(buf)
	clear(buf)
	return s
}

// DerivePublicKey returns Hs(d ‖ i)·G + base, the one-time output key.
//
// Ported from monero src/crypto/crypto.cpp: crypto_ops::derive_public_key.
func DerivePublicKey(d KeyDerivation, outputIndex uint64, base PublicKey) (PublicKey, error) {
	b, err := base.point()
	if err != nil {
		return PublicKey{}, err
	}
	s := DerivationToScalar(d, outputIndex)
	defer primitives.WipeScalar(s)
	p := new(edwards25519.Point).ScalarBaseMult(s)
	p.Add(b, p)
	return PublicKey(p.Bytes()), nil
}

// DeriveSubaddressPublicKey returns outKey - Hs(d ‖ i)·G, the spend key the output
// was sent to. Used to look outputs up in the subaddress table.
//
// Ported from monero src/crypto/crypto.cpp: crypto_ops::derive_subaddress_public_key.
func DeriveSubaddressPublicKey(outKey PublicKey, d KeyDerivation, outputIndex uint64) (PublicKey, error) {
	o, err := outKey.point()
	if err != nil {
		return PublicKey{}, err
	}
	s := DerivationToScalar(d, outputIndex)
	defer primitives.WipeScalar(s)
	p := new(edwards25519.Point).ScalarBaseMult(s)
	p.Subtract(o, p)
	return PublicKey(p.Bytes()), nil
}

// DeriveSecretKey returns Hs(d ‖ i) + base, the one-time output secret key.
// Upstream only asserts that base is canonical; here it is an error.
//
// Ported from monero src/crypto/crypto.cpp: crypto_ops::derive_secret_key.
func DeriveSecretKey(d KeyDerivation, outputIndex uint64, base SecretKey) (SecretKey, error) {
	b, err := base.scalar()
	if err != nil {
		return SecretKey{}, err
	}
	defer primitives.WipeScalar(b)
	s := DerivationToScalar(d, outputIndex)
	defer primitives.WipeScalar(s)
	s.Add(b, s)
	return SecretKey(s.Bytes()), nil
}

// DeriveKeyImageGenerator returns Hp(pub), the biased key-image generator used
// before FCMP++. The unbiased (FCMP++) generator is not implemented yet.
//
// Ported from monero src/crypto/crypto.cpp: biased_derive_key_image_generator.
func DeriveKeyImageGenerator(pub PublicKey) [32]byte {
	return [32]byte(primitives.BiasedHashToEC(pub).Bytes())
}

// GenerateKeyImage returns sec·Hp(pub).
//
// Ported from monero src/crypto/crypto.cpp: crypto_ops::generate_key_image
// ("key image derivation used before FCMP++/Carrot").
func GenerateKeyImage(pub PublicKey, sec SecretKey) (KeyImage, error) {
	x, err := sec.scalar()
	if err != nil {
		return KeyImage{}, err
	}
	defer primitives.WipeScalar(x)
	hp := primitives.BiasedHashToEC(pub)
	return KeyImage(new(edwards25519.Point).ScalarMult(x, hp).Bytes()), nil
}

// DeriveViewTag returns the first byte of Keccak("view_tag" ‖ d ‖ varint(i)).
//
// Ported from monero src/crypto/crypto.cpp: crypto_ops::derive_view_tag.
func DeriveViewTag(d KeyDerivation, outputIndex uint64) ViewTag {
	buf := make([]byte, 0, 8+32+10)
	buf = append(buf, "view_tag"...) // no null terminator
	buf = append(buf, d[:]...)
	buf = varint.Append(buf, outputIndex)
	h := primitives.Keccak256(buf)
	clear(buf)
	return ViewTag(h[0])
}
