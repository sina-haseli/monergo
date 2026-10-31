// Copyright (c) 2014-2026, The Monero Project
// Copyright (c) 2026, The monergo Authors
// SPDX-License-Identifier: BSD-3-Clause
//
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers.

// Package primitives implements the low-level Monero hash and curve operations:
// Keccak-256, scalar reduction, Hs (hash-to-scalar), Hp (hash-to-point) and point
// decoding with Monero's exact acceptance rules.
//
// Ported from monero-project/monero @3fd0f88c20f559839cafb20911cb13cb45eba7bd.
// Where filippo.io/edwards25519 provides an operation identical to an upstream
// ref10 function, it is used directly; the comment names the upstream function and
// the vectors in tests/crypto/tests.txt check the equivalence.
package primitives

import (
	"crypto/subtle"
	"errors"
	"io"

	"filippo.io/edwards25519"
	"filippo.io/edwards25519/field"
	"golang.org/x/crypto/sha3"
)

// ErrInvalidPoint is returned for bytes that ge_frombytes_vartime rejects.
var ErrInvalidPoint = errors.New("primitives: invalid point encoding")

// ErrInvalidScalar is returned for bytes that sc_check rejects (not reduced mod l).
var ErrInvalidScalar = errors.New("primitives: non-canonical scalar")

// Keccak256 returns the original Keccak-256 (cn_fast_hash) of the concatenation of
// its arguments. This is not SHA3-256.
//
// Ported from monero src/crypto/hash.c: cn_fast_hash.
func Keccak256(data ...[]byte) [32]byte {
	h := sha3.NewLegacyKeccak256()
	for _, d := range data {
		h.Write(d)
	}
	var out [32]byte
	h.Sum(out[:0])
	return out
}

// ScCheck reports whether s is a canonical scalar, i.e. s < l.
//
// Ported from monero src/crypto/crypto-ops.c: sc_check, via
// edwards25519.Scalar.SetCanonicalBytes.
func ScCheck(s [32]byte) bool {
	_, err := new(edwards25519.Scalar).SetCanonicalBytes(s[:])
	return err == nil
}

// ScReduce32 reduces a 256-bit little-endian integer modulo l.
//
// Ported from monero src/crypto/crypto-ops.c: sc_reduce32, via
// edwards25519.Scalar.SetUniformBytes on the zero-extended 64-byte value.
func ScReduce32(s [32]byte) [32]byte {
	return [32]byte(reduce32(s).Bytes())
}

func reduce32(s [32]byte) *edwards25519.Scalar {
	var wide [64]byte
	copy(wide[:], s[:])
	r, err := new(edwards25519.Scalar).SetUniformBytes(wide[:])
	if err != nil {
		panic("primitives: SetUniformBytes rejected 64 bytes: " + err.Error())
	}
	clear(wide[:])
	return r
}

// ScalarFromCanonical decodes a canonical scalar, rejecting values >= l.
func ScalarFromCanonical(s [32]byte) (*edwards25519.Scalar, error) {
	r, err := new(edwards25519.Scalar).SetCanonicalBytes(s[:])
	if err != nil {
		return nil, ErrInvalidScalar
	}
	return r, nil
}

// HashToScalar is Hs: Keccak-256 of the concatenated data, reduced mod l.
//
// Ported from monero src/crypto/crypto.cpp: crypto::hash_to_scalar.
func HashToScalar(data ...[]byte) *edwards25519.Scalar {
	h := Keccak256(data...)
	return reduce32(h)
}

// p is the field prime 2^255 - 19, little-endian.
var fieldPrime = [32]byte{
	0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
}

// isCanonicalFieldEncoding reports whether b, with bit 255 ignored, is < p. This is
// the canonicity check in fe_frombytes_vartime. b is public data (vartime is fine).
func isCanonicalFieldEncoding(b [32]byte) bool {
	b[31] &= 0x7f
	for i := 31; i >= 0; i-- {
		if b[i] != fieldPrime[i] {
			return b[i] < fieldPrime[i]
		}
	}
	return false // b == p
}

// DecodePoint decodes a compressed Edwards point with the same acceptance rules as
// Monero: the y coordinate must be fully reduced, the point must be on the curve,
// and x = 0 must not have the sign bit set. Unlike ge_frombytes_vartime it does not
// reject or clear torsion; neither does upstream.
//
// Ported from monero src/crypto/crypto-ops.c: ge_frombytes_vartime (with
// fe_frombytes_vartime). edwards25519.Point.SetBytes accepts the two non-canonical
// forms that upstream rejects, so those are checked explicitly here.
func DecodePoint(b [32]byte) (*edwards25519.Point, error) {
	if !isCanonicalFieldEncoding(b) {
		return nil, ErrInvalidPoint
	}
	p, err := new(edwards25519.Point).SetBytes(b[:])
	if err != nil {
		return nil, ErrInvalidPoint
	}
	// Upstream: "If x = 0, the sign must be positive". SetBytes leaves Z = 1, so
	// the X coordinate is the affine x.
	if b[31]>>7 == 1 {
		x, _, _, _ := p.ExtendedCoordinates()
		if x.Equal(new(field.Element).Zero()) == 1 {
			return nil, ErrInvalidPoint
		}
	}
	return p, nil
}

// CheckKey reports whether b is a valid point encoding.
//
// Ported from monero src/crypto/crypto.cpp: crypto_ops::check_key.
func CheckKey(b [32]byte) bool {
	_, err := DecodePoint(b)
	return err == nil
}

// IsIdentity reports whether p is the identity element, regardless of its internal
// projective representation.
//
// Counterpart of monero src/crypto/crypto-ops.c: ge_p3_is_point_at_infinity_vartime.
func IsIdentity(p *edwards25519.Point) bool {
	return p.Equal(edwards25519.NewIdentityPoint()) == 1
}

// ConstantTimeEqual32 compares two 32-byte values (for example secret keys or
// scalars) in constant time.
func ConstantTimeEqual32(a, b *[32]byte) bool {
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

// WipeScalar overwrites a secret scalar with zero.
func WipeScalar(s *edwards25519.Scalar) {
	if s != nil {
		s.Set(edwards25519.NewScalar())
	}
}

// lMinusOne is l - 1, the largest canonical scalar.
var lMinusOne = func() *edwards25519.Scalar {
	b := [32]byte{
		0xec, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
	}
	s, err := new(edwards25519.Scalar).SetCanonicalBytes(b[:])
	if err != nil {
		panic(err)
	}
	return s
}()

// IsInMainSubgroup reports whether l·p is the identity, i.e. p has no torsion
// component. l·p is computed as (l-1)·p + p because l itself is not a canonical
// scalar.
//
// Ported from monero src/ringct/rctOps.cpp: isInMainSubgroup / toPointCheckOrder.
func IsInMainSubgroup(p *edwards25519.Point) bool {
	q := new(edwards25519.Point).ScalarMult(lMinusOne, p)
	q.Add(q, p)
	return IsIdentity(q)
}

// randomLimit is 15·l, the largest multiple of l below 2^256.
var randomLimit = [32]byte{
	0xe3, 0x6a, 0x67, 0x72, 0x8b, 0xce, 0x13, 0x29, 0x8f, 0x30, 0x82, 0x8c, 0x0b, 0xa4, 0x10, 0x39,
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0,
}

func less32(k0, k1 *[32]byte) bool {
	for n := 31; n >= 0; n-- {
		if k0[n] < k1[n] {
			return true
		}
		if k0[n] > k1[n] {
			return false
		}
	}
	return false
}

// RandomScalar returns a uniformly random non-zero scalar read from rand: 32-byte
// samples below 15·l are kept and reduced, and zero is rejected.
//
// Ported from monero src/crypto/crypto.cpp: random32_unbiased (used by skGen and
// random_scalar).
func RandomScalar(rand io.Reader) (*edwards25519.Scalar, error) {
	var b [32]byte
	defer clear(b[:])
	for {
		if _, err := io.ReadFull(rand, b[:]); err != nil {
			return nil, err
		}
		if !less32(&b, &randomLimit) {
			continue
		}
		s := reduce32(b)
		if s.Equal(edwards25519.NewScalar()) == 0 {
			return s, nil
		}
	}
}
