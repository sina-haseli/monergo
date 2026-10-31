// Copyright (c) 2014-2026, The Monero Project
// Copyright (c) 2026, The monergo Authors
// SPDX-License-Identifier: BSD-3-Clause

// Package bpplus implements Bulletproofs+ aggregated range proofs (RingCT type 6).
//
// Ported from monero src/ringct/bulletproofs_plus.cc
// @3fd0f88c20f559839cafb20911cb13cb45eba7bd.
package bpplus

import (
	"sync"

	"filippo.io/edwards25519"
	"github.com/sina-haseli/monergo/internal/varint"
	"github.com/sina-haseli/monergo/primitives"
	"github.com/sina-haseli/monergo/ringct"
)

const (
	logN = 6
	maxN = 1 << logN // maximum number of bits in range
	maxM = 16        // BULLETPROOF_PLUS_MAX_OUTPUTS
)

// Domain separators from monero src/cryptonote_config.h.
const (
	hashKeyExponent   = "bulletproof_plus"            // HASH_KEY_BULLETPROOF_PLUS_EXPONENT
	hashKeyTranscript = "bulletproof_plus_transcript" // HASH_KEY_BULLETPROOF_PLUS_TRANSCRIPT
)

type generators struct {
	Gi, Hi             [maxN * maxM]*edwards25519.Point
	initialTranscript  ringct.Key
	twoSixtyFourMinus1 *edwards25519.Scalar
}

var (
	gensOnce sync.Once
	gens     *generators
)

// getExponent returns Hp(Keccak(base ‖ "bulletproof_plus" ‖ varint(idx))).
//
// Ported from monero src/ringct/bulletproofs_plus.cc: get_exponent (hash_to_p3 is
// biased_hash_to_ec, which hashes once more).
func getExponent(base ringct.Key, idx uint64) *edwards25519.Point {
	buf := append([]byte{}, base[:]...)
	buf = append(buf, hashKeyExponent...)
	buf = varint.Append(buf, idx)
	p := primitives.BiasedHashToEC(primitives.Keccak256(buf))
	if primitives.IsIdentity(p) {
		panic("bpplus: exponent is point at infinity")
	}
	return p
}

// initGenerators ports init_exponents.
func initGenerators() *generators {
	gensOnce.Do(func() {
		g := &generators{}
		for i := 0; i < maxN*maxM; i++ {
			g.Hi[i] = getExponent(ringct.HBytes, uint64(i*2))
			g.Gi[i] = getExponent(ringct.HBytes, uint64(i*2+1))
		}
		// 2**64 - 1
		t := scalarFromUint(2)
		for i := 0; i < 6; i++ {
			t.Multiply(t, t)
		}
		g.twoSixtyFourMinus1 = t.Subtract(t, scalarFromUint(1))
		g.initialTranscript = ringct.Key(primitives.BiasedHashToEC(primitives.Keccak256([]byte(hashKeyTranscript))).Bytes())
		gens = g
	})
	return gens
}

func scalarFromUint(v uint64) *edwards25519.Scalar { return ringct.AmountScalar(v) }

func scalarZero() *edwards25519.Scalar { return edwards25519.NewScalar() }

func isZero(s *edwards25519.Scalar) bool { return s.Equal(edwards25519.NewScalar()) == 1 }

func key(s *edwards25519.Scalar) ringct.Key { return ringct.Key(s.Bytes()) }

// transcriptUpdate sets transcript = Hs(transcript ‖ updates...) and returns it.
//
// Ported from monero src/ringct/bulletproofs_plus.cc: transcript_update.
func transcriptUpdate(transcript *ringct.Key, updates ...ringct.Key) *edwards25519.Scalar {
	s := ringct.HashToScalarKeys(append([]ringct.Key{*transcript}, updates...)...)
	*transcript = key(s)
	return s
}

// sumOfEvenPowers returns x^2 + x^4 + ... + x^n, n a power of 2.
//
// Ported from monero src/ringct/bulletproofs_plus.cc: sum_of_even_powers.
func sumOfEvenPowers(x *edwards25519.Scalar, n int) *edwards25519.Scalar {
	if n == 0 || n&(n-1) != 0 {
		panic("bpplus: need n a power of 2")
	}
	x1 := new(edwards25519.Scalar).Multiply(x, x)
	res := new(edwards25519.Scalar).Set(x1)
	for n > 2 {
		res.MultiplyAdd(x1, res, res)
		x1.Multiply(x1, x1)
		n /= 2
	}
	return res
}

// sumOfScalarPowers returns x^1 + x^2 + ... + x^n.
//
// Ported from monero src/ringct/bulletproofs_plus.cc: sum_of_scalar_powers.
func sumOfScalarPowers(x *edwards25519.Scalar, n int) *edwards25519.Scalar {
	if n == 0 {
		panic("bpplus: need n > 0")
	}
	if n == 1 {
		return new(edwards25519.Scalar).Set(x)
	}
	one := scalarFromUint(1)
	res := new(edwards25519.Scalar).Set(one)
	n++
	x1 := new(edwards25519.Scalar).Set(x)
	if n&(n-1) == 0 {
		res.Add(res, x1)
		for n > 2 {
			x1.Multiply(x1, x1)
			res.MultiplyAdd(x1, res, res)
			n /= 2
		}
	} else {
		prev := new(edwards25519.Scalar).Set(x1)
		for i := 1; i < n; i++ {
			if i > 1 {
				prev.Multiply(prev, x1)
			}
			res.Add(res, prev)
		}
	}
	return res.Subtract(res, one)
}
