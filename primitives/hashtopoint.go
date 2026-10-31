// Copyright (c) 2014-2026, The Monero Project
// Copyright (c) 2026, The monergo Authors
// SPDX-License-Identifier: BSD-3-Clause
//
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers.

package primitives

import (
	"math/big"

	"filippo.io/edwards25519"
	"filippo.io/edwards25519/field"
)

type fieldElement = field.Element

// Field constants, transcribed verbatim from monero src/crypto/crypto-ops-data.c
// (ref10 radix-2^25.5 limbs) and converted with feFromLimbs. TestFieldConstants
// checks the documented identities.
var (
	feSqrtM1 = feFromLimbs([10]int64{-32595792, -7943725, 9377950, 3500415, 12389472, -272473, -25146209, -2005654, 326686, 11406482})        // sqrt(-1)
	feMA2    = feFromLimbs([10]int64{-12721188, -3529, 0, 0, 0, 0, 0, 0, 0, 0})                                                               // -A^2
	feMA     = feFromLimbs([10]int64{-486662, 0, 0, 0, 0, 0, 0, 0, 0, 0})                                                                     // -A
	feFFFB1  = feFromLimbs([10]int64{-31702527, -2466483, -26106795, -12203692, -12169197, -321052, 14850977, -10296299, -16929438, -407568}) // sqrt(-2 * A * (A + 2))
	feFFFB2  = feFromLimbs([10]int64{8166131, -6741800, -17040804, 3154616, 21461005, 1466302, -30876704, -6368709, 10503587, -13363080})     // sqrt(2 * A * (A + 2))
	feFFFB3  = feFromLimbs([10]int64{-13620103, 14639558, 4532995, 7679154, 16815101, -15883539, -22863840, -14813421, 13716513, -6477756})   // sqrt(-sqrt(-1) * A * (A + 2))
	feFFFB4  = feFromLimbs([10]int64{-21786234, -12173074, 21573800, 4524538, -4645904, 16204591, 8012863, -8444712, 3212926, 6885324})       // sqrt(sqrt(-1) * A * (A + 2))

	feOne      = new(fieldElement).One()
	feNineteen = feFromInt(19)
)

// feFromLimbs converts a ref10 fe (limb i has weight 2^ceil(25.5*i)) to a field
// element. Only used at init for public constants.
func feFromLimbs(l [10]int64) *fieldElement {
	weights := [10]uint{0, 26, 51, 77, 102, 128, 153, 179, 204, 230}
	p := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	v := new(big.Int)
	for i, limb := range l {
		v.Add(v, new(big.Int).Lsh(big.NewInt(limb), weights[i]))
	}
	v.Mod(v, p)
	be := v.FillBytes(make([]byte, 32))
	le := make([]byte, 32)
	for i := range be {
		le[i] = be[31-i]
	}
	fe, err := new(fieldElement).SetBytes(le)
	if err != nil {
		panic(err)
	}
	return fe
}

func feFromInt(n uint64) *fieldElement {
	var b [32]byte
	for i := 0; i < 8; i++ {
		b[i] = byte(n >> (8 * i))
	}
	fe, _ := new(fieldElement).SetBytes(b[:])
	return fe
}

func feIsNonZero(f *fieldElement) bool {
	return f.Equal(new(fieldElement).Zero()) == 0
}

// feDivPowM1 returns u * v^3 * (u * v^7)^((p-5)/8).
//
// Ported from monero src/crypto/crypto-ops.c: fe_divpowm1 (its inlined
// fe_pow22523 is field.Element.Pow22523).
func feDivPowM1(u, v *fieldElement) *fieldElement {
	v3 := new(fieldElement).Square(v)
	v3.Multiply(v3, v)
	uv7 := new(fieldElement).Square(v3)
	uv7.Multiply(uv7, v)
	uv7.Multiply(uv7, u)
	t0 := new(fieldElement).Pow22523(uv7)
	t0.Multiply(t0, v3)
	return t0.Multiply(t0, u)
}

// geFromfeFrombytesVartime maps 32 bytes to a curve point in projective (X:Y:Z)
// coordinates. All 256 input bits are used: unlike fe_frombytes, the upstream
// loader does not mask bit 255, so the input is read as an integer mod p.
//
// Ported from monero src/crypto/crypto-ops.c: ge_fromfe_frombytes_vartime.
// Inputs are public (hashes of public keys), so variable time is acceptable.
func geFromfeFrombytesVartime(s [32]byte) (X, Y, Z *fieldElement) {
	top := s[31] >> 7
	s[31] &= 0x7f
	u, err := new(fieldElement).SetBytes(s[:])
	if err != nil {
		panic(err)
	}
	if top == 1 {
		u.Add(u, feNineteen) // 2^255 = 19 (mod p)
	}

	v := new(fieldElement).Square(u)
	v.Add(v, v)                          // fe_sq2: v = 2 * u^2
	w := new(fieldElement).Add(v, feOne) // w = 2 * u^2 + 1
	x := new(fieldElement).Square(w)     // w^2
	y := new(fieldElement).Multiply(feMA2, v)
	x.Add(x, y)            // x = w^2 - 2 * A^2 * u^2
	rX := feDivPowM1(w, x) // (w / x)^(m + 1)
	y.Square(rX)
	x.Multiply(y, x)
	y.Subtract(w, x)
	z := new(fieldElement).Set(feMA)

	negative := false
	if feIsNonZero(y) {
		y.Add(w, x)
		if feIsNonZero(y) {
			negative = true
		} else {
			rX.Multiply(rX, feFFFB1)
		}
	} else {
		rX.Multiply(rX, feFFFB2)
	}

	var sign int
	if !negative {
		rX.Multiply(rX, u) // u * sqrt(2 * A * (A + 2) * w / x)
		z.Multiply(z, v)   // -2 * A * u^2
		sign = 0
	} else {
		x.Multiply(x, feSqrtM1)
		y.Subtract(w, x)
		if feIsNonZero(y) {
			// Upstream asserts w + x == 0 here.
			rX.Multiply(rX, feFFFB3)
		} else {
			rX.Multiply(rX, feFFFB4)
		}
		// rX = sqrt(A * (A + 2) * w / x), z = -A
		sign = 1
	}

	if rX.IsNegative() != sign {
		rX.Negate(rX)
	}
	Z = new(fieldElement).Add(z, w)
	Y = new(fieldElement).Subtract(z, w)
	X = rX.Multiply(rX, Z)
	return X, Y, Z
}

// p2ToPoint converts projective (X:Y:Z) coordinates to an edwards25519.Point.
func p2ToPoint(X, Y, Z *fieldElement) *edwards25519.Point {
	zInv := new(fieldElement).Invert(Z)
	x := new(fieldElement).Multiply(X, zInv)
	y := new(fieldElement).Multiply(Y, zInv)
	t := new(fieldElement).Multiply(x, y)
	p, err := new(edwards25519.Point).SetExtendedCoordinates(x, y, feOne, t)
	if err != nil {
		panic("primitives: ge_fromfe_frombytes_vartime produced a point off the curve")
	}
	return p
}

// HashToPoint applies ge_fromfe_frombytes_vartime to h directly (no hashing, no
// cofactor clearing) and returns the encoded point. This is the "hash_to_point"
// vector type; protocol code wants BiasedHashToEC.
//
// Ported from monero tests/crypto/crypto.cpp: hash_to_point (ge_fromfe_frombytes_vartime
// followed by ge_tobytes).
func HashToPoint(h [32]byte) [32]byte {
	return [32]byte(p2ToPoint(geFromfeFrombytesVartime(h)).Bytes())
}

// BiasedHashToEC is Monero's Hp as used for key images and CLSAG before FCMP++:
// 8 * ge_fromfe_frombytes_vartime(Keccak256(key)).
//
// Ported from monero src/crypto/crypto.cpp: biased_hash_to_ec (formerly hash_to_ec).
func BiasedHashToEC(key [32]byte) *edwards25519.Point {
	h := Keccak256(key[:])
	p := p2ToPoint(geFromfeFrombytesVartime(h))
	return p.MultByCofactor(p)
}
