// Copyright (c) 2014-2026, The Monero Project
// Copyright (c) 2026, The monergo Authors
// SPDX-License-Identifier: BSD-3-Clause

package ringct

import (
	"encoding/binary"

	"filippo.io/edwards25519"
	"github.com/sina-haseli/monergo/primitives"
)

// HBytes is the second Pedersen generator H.
//
// From monero src/ringct/rctTypes.h: rct::H.
var HBytes = Key{
	0x8b, 0x65, 0x59, 0x70, 0x15, 0x37, 0x99, 0xaf, 0x2a, 0xea, 0xdc, 0x9f, 0xf1, 0xad, 0xd0, 0xea,
	0x6c, 0x72, 0x51, 0xd5, 0x41, 0x54, 0xcf, 0xa9, 0x2c, 0x17, 0x3a, 0x0d, 0xd3, 0x9c, 0x1f, 0x94,
}

// InvEightBytes is 8^-1 mod l.
//
// From monero src/ringct/rctTypes.h: rct::INV_EIGHT.
var InvEightBytes = Key{
	0x79, 0x2f, 0xdc, 0xe2, 0x29, 0xe5, 0x06, 0x61, 0xd0, 0xda, 0x1c, 0x7d, 0xb3, 0x9d, 0xd3, 0x07,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06,
}

// IdentityBytes is the encoding of the identity point (rct::identity()).
var IdentityBytes = Key{1}

var (
	hPoint   = mustPoint(HBytes)
	invEight = mustScalar(InvEightBytes)
)

func mustPoint(k Key) *edwards25519.Point {
	p, err := primitives.DecodePoint(k)
	if err != nil {
		panic(err)
	}
	return p
}

func mustScalar(k Key) *edwards25519.Scalar {
	s, err := primitives.ScalarFromCanonical(k)
	if err != nil {
		panic(err)
	}
	return s
}

// H returns a copy of the generator H.
func H() *edwards25519.Point { return new(edwards25519.Point).Set(hPoint) }

// InvEight returns a copy of 8^-1 mod l.
func InvEight() *edwards25519.Scalar { return new(edwards25519.Scalar).Set(invEight) }

// AmountScalar returns the amount as a scalar (little-endian, zero-padded).
//
// Ported from monero src/ringct/rctOps.cpp: d2h.
func AmountScalar(amount uint64) *edwards25519.Scalar {
	var b [32]byte
	binary.LittleEndian.PutUint64(b[:], amount)
	s, err := new(edwards25519.Scalar).SetCanonicalBytes(b[:])
	if err != nil {
		panic(err) // a 64-bit value is always < l
	}
	return s
}

// Commit returns mask·G + amount·H. Both scalar multiplications are constant
// time, since amount and mask are secret when building a transaction.
//
// Ported from monero src/ringct/rctOps.cpp: genC / commit.
func Commit(amount uint64, mask *edwards25519.Scalar) *edwards25519.Point {
	a := AmountScalar(amount)
	defer primitives.WipeScalar(a)
	aH := new(edwards25519.Point).ScalarMult(a, hPoint)
	mG := new(edwards25519.Point).ScalarBaseMult(mask)
	return mG.Add(mG, aH)
}

// ZeroCommit returns G + amount·H, the commitment of a cleartext amount (coinbase
// and pre-RingCT outputs).
//
// Ported from monero src/ringct/rctOps.cpp: zeroCommitVartime.
func ZeroCommit(amount uint64) Key {
	p := new(edwards25519.Point).VarTimeDoubleScalarBaseMult(AmountScalar(amount), hPoint, scalarOne())
	return Key(p.Bytes())
}

func scalarOne() *edwards25519.Scalar {
	var b [32]byte
	b[0] = 1
	s, _ := new(edwards25519.Scalar).SetCanonicalBytes(b[:])
	return s
}

// HashToScalarKeys is Hs over the concatenation of keys (rct::hash_to_scalar(keyV)).
func HashToScalarKeys(keys ...Key) *edwards25519.Scalar {
	buf := make([]byte, 0, 32*len(keys))
	for _, k := range keys {
		buf = append(buf, k[:]...)
	}
	return primitives.HashToScalar(buf)
}
