// Copyright (c) 2014-2026, The Monero Project
// Copyright (c) 2026, The monergo Authors
// SPDX-License-Identifier: BSD-3-Clause

// Package clsag implements CLSAG ring signatures as used by RingCT types 5 and 6.
//
// Ported from monero src/ringct/rctSigs.cpp @3fd0f88c20f559839cafb20911cb13cb45eba7bd.
package clsag

import (
	"errors"

	"filippo.io/edwards25519"
	"github.com/sina-haseli/monergo/primitives"
	"github.com/sina-haseli/monergo/ringct"
)

// ErrInvalid is returned for any signature that does not verify.
var ErrInvalid = errors.New("clsag: invalid signature")

// Domain separators from monero src/cryptonote_config.h, each zero-padded to 32
// bytes as upstream copies them into an rct::key.
var (
	hashKeyAgg0  = domain("CLSAG_agg_0")
	hashKeyAgg1  = domain("CLSAG_agg_1")
	hashKeyRound = domain("CLSAG_round")
)

func domain(s string) ringct.Key {
	var k ringct.Key
	copy(k[:], s)
	return k
}

// Member is one ring member: the output key (dest) and its commitment (mask).
type Member struct {
	Dest ringct.Key
	Mask ringct.Key
}

// aggregationScalars returns (mu_P, mu_C).
func aggregationScalars(ring []Member, I, D, cOffset ringct.Key) (*edwards25519.Scalar, *edwards25519.Scalar) {
	n := len(ring)
	toHash := make([]ringct.Key, 2*n+4)
	for i, m := range ring {
		toHash[1+i] = m.Dest
		toHash[1+n+i] = m.Mask
	}
	toHash[2*n+1] = I
	toHash[2*n+2] = D
	toHash[2*n+3] = cOffset
	toHash[0] = hashKeyAgg0
	muP := ringct.HashToScalarKeys(toHash...)
	toHash[0] = hashKeyAgg1
	muC := ringct.HashToScalarKeys(toHash...)
	return muP, muC
}

// roundHashPrefix returns domain ‖ P ‖ C ‖ C_offset ‖ message with two trailing
// slots for L and R.
func roundHashPrefix(ring []Member, cOffset, message ringct.Key) []ringct.Key {
	n := len(ring)
	c := make([]ringct.Key, 2*n+5)
	c[0] = hashKeyRound
	for i, m := range ring {
		c[1+i] = m.Dest
		c[1+n+i] = m.Mask
	}
	c[2*n+1] = cOffset
	c[2*n+2] = message
	return c
}

// Verify checks a CLSAG over ring for message, with key image I and pseudo-output
// commitment cOffset.
//
// Ported from monero src/ringct/rctSigs.cpp: verRctCLSAGSimple. All inputs are
// public, so variable-time arithmetic is used throughout.
func Verify(message ringct.Key, sig ringct.CLSAG, I ringct.Key, ring []Member, cOffset ringct.Key) error {
	n := len(ring)
	if n < 1 || n != len(sig.S) {
		return ErrInvalid
	}
	s := make([]*edwards25519.Scalar, n)
	for i := range sig.S {
		var err error
		if s[i], err = primitives.ScalarFromCanonical(sig.S[i]); err != nil {
			return ErrInvalid // "Bad signature scalar!"
		}
	}
	c1, err := primitives.ScalarFromCanonical(sig.C1)
	if err != nil {
		return ErrInvalid // "Bad signature commitment!"
	}
	if I == ringct.IdentityBytes {
		return ErrInvalid // "Bad key image!"
	}
	cOffsetPt, err := primitives.DecodePoint(cOffset)
	if err != nil {
		return ErrInvalid
	}
	iPt, err := primitives.DecodePoint(I)
	if err != nil {
		return ErrInvalid
	}
	dPt, err := primitives.DecodePoint(sig.D)
	if err != nil {
		return ErrInvalid
	}
	d8 := new(edwards25519.Point).MultByCofactor(dPt)
	if primitives.IsIdentity(d8) {
		return ErrInvalid // "Bad auxiliary key image!"
	}

	muP, muC := aggregationScalars(ring, I, sig.D, cOffset)
	toHash := roundHashPrefix(ring, cOffset, message)

	c := new(edwards25519.Scalar).Set(c1)
	cP := new(edwards25519.Scalar)
	cC := new(edwards25519.Scalar)
	g := edwards25519.NewGeneratorPoint()
	for i := 0; i < n; i++ {
		cP.Multiply(muP, c)
		cC.Multiply(muC, c)

		P, err := primitives.DecodePoint(ring[i].Dest)
		if err != nil {
			return ErrInvalid
		}
		C, err := primitives.DecodePoint(ring[i].Mask)
		if err != nil {
			return ErrInvalid
		}
		C.Subtract(C, cOffsetPt)

		// L = s_i·G + c_p·P_i + c_c·(C_i - C_offset)
		L := new(edwards25519.Point).VarTimeMultiScalarMult(
			[]*edwards25519.Scalar{s[i], cP, cC}, []*edwards25519.Point{g, P, C})
		// R = s_i·Hp(P_i) + c_p·I + c_c·8D
		hp := primitives.BiasedHashToEC(ring[i].Dest)
		R := new(edwards25519.Point).VarTimeMultiScalarMult(
			[]*edwards25519.Scalar{s[i], cP, cC}, []*edwards25519.Point{hp, iPt, d8})

		toHash[2*n+3] = ringct.Key(L.Bytes())
		toHash[2*n+4] = ringct.Key(R.Bytes())
		c = ringct.HashToScalarKeys(toHash...)
		if c.Equal(edwards25519.NewScalar()) == 1 {
			return ErrInvalid // "Bad signature hash"
		}
	}
	if c.Equal(c1) != 1 {
		return ErrInvalid
	}
	return nil
}
