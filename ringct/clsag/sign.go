// Copyright (c) 2014-2026, The Monero Project
// Copyright (c) 2026, The monergo Authors
// SPDX-License-Identifier: BSD-3-Clause

package clsag

import (
	"errors"
	"io"

	"filippo.io/edwards25519"
	"github.com/sina-haseli/monergo/primitives"
	"github.com/sina-haseli/monergo/ringct"
)

// ErrBadInput is returned for inconsistent signing inputs.
var ErrBadInput = errors.New("clsag: bad signing input")

// SignSimple signs message for the ring member at index l, whose one-time secret
// key is p and whose commitment mask is inMask, against a pseudo-output
// commitment cOut = outMask·G + amount·H. It returns the signature and the key
// image p·Hp(P_l).
//
// Ported from monero src/ringct/rctSigs.cpp: proveRctCLSAGSimple.
func SignSimple(rand io.Reader, message ringct.Key, ring []Member, l int, p, inMask, outMask *edwards25519.Scalar, cOut ringct.Key) (ringct.CLSAG, ringct.Key, error) {
	cOutPt, err := primitives.DecodePoint(cOut)
	if err != nil {
		return ringct.CLSAG{}, ringct.Key{}, ErrBadInput
	}
	// C: commitments to zero C_a - Cout; C_nonzero: unmodified commitments C_a
	C := make([]*edwards25519.Point, len(ring))
	for i, m := range ring {
		c, err := primitives.DecodePoint(m.Mask)
		if err != nil {
			return ringct.CLSAG{}, ringct.Key{}, ErrBadInput
		}
		C[i] = c.Subtract(c, cOutPt)
	}
	// z = c_a - c_out, the private key of C[l] = z·G
	z := new(edwards25519.Scalar).Subtract(inMask, outMask)
	defer primitives.WipeScalar(z)
	return sign(rand, message, ring, C, l, p, z, cOut)
}

// sign ports CLSAG_Gen with the default device (clsag_prepare, clsag_hash,
// clsag_sign). P is ring[i].Dest and C_nonzero is ring[i].Mask.
//
// Ported from monero src/ringct/rctSigs.cpp: CLSAG_Gen, and
// src/device/device_default.cpp: clsag_prepare, clsag_sign.
func sign(rand io.Reader, message ringct.Key, ring []Member, C []*edwards25519.Point, l int, p, z *edwards25519.Scalar, cOffset ringct.Key) (ringct.CLSAG, ringct.Key, error) {
	n := len(ring)
	if n == 0 || n != len(C) || l < 0 || l >= n {
		return ringct.CLSAG{}, ringct.Key{}, ErrBadInput
	}
	// The signer must own ring member l: P_l = p·G and C[l] = z·G. Upstream
	// leaves this to its callers; checking here turns a caller bug into an error
	// instead of an invalid signature.
	if ringct.Key(new(edwards25519.Point).ScalarBaseMult(p).Bytes()) != ring[l].Dest {
		return ringct.CLSAG{}, ringct.Key{}, ErrBadInput
	}
	if new(edwards25519.Point).ScalarBaseMult(z).Equal(C[l]) != 1 {
		return ringct.CLSAG{}, ringct.Key{}, ErrBadInput
	}

	// Key images: H = Hp(P_l)
	hPt := primitives.BiasedHashToEC(ring[l].Dest)

	// clsag_prepare: a random, aG = a·G, aH = a·H, I = p·H, D = z·H
	a, err := primitives.RandomScalar(rand)
	if err != nil {
		return ringct.CLSAG{}, ringct.Key{}, err
	}
	defer primitives.WipeScalar(a)
	aG := ringct.Key(new(edwards25519.Point).ScalarBaseMult(a).Bytes())
	aH := ringct.Key(new(edwards25519.Point).ScalarMult(a, hPt).Bytes())
	iPt := new(edwards25519.Point).ScalarMult(p, hPt)
	dPt := new(edwards25519.Point).ScalarMult(z, hPt)
	var sig ringct.CLSAG
	I := ringct.Key(iPt.Bytes())

	// Offset key image: sig.D = D·8^-1
	sig.D = ringct.Key(new(edwards25519.Point).ScalarMult(ringct.InvEight(), dPt).Bytes())

	muP, muC := aggregationScalars(ring, I, sig.D, cOffset)

	// Initial commitment
	toHash := roundHashPrefix(ring, cOffset, message)
	toHash[2*n+3] = aG
	toHash[2*n+4] = aH
	c := ringct.HashToScalarKeys(toHash...)

	i := (l + 1) % n
	if i == 0 {
		sig.C1 = ringct.Key(c.Bytes())
	}

	// Decoy indices
	sig.S = make([]ringct.Key, n)
	cP := new(edwards25519.Scalar)
	cC := new(edwards25519.Scalar)
	g := edwards25519.NewGeneratorPoint()
	for i != l {
		si, err := primitives.RandomScalar(rand)
		if err != nil {
			return ringct.CLSAG{}, ringct.Key{}, err
		}
		sig.S[i] = ringct.Key(si.Bytes())
		cP.Multiply(muP, c)
		cC.Multiply(muC, c)

		P, err := primitives.DecodePoint(ring[i].Dest)
		if err != nil {
			return ringct.CLSAG{}, ringct.Key{}, ErrBadInput
		}
		// L = s_i·G + c_p·P_i + c_c·C_i
		L := new(edwards25519.Point).VarTimeMultiScalarMult(
			[]*edwards25519.Scalar{si, cP, cC}, []*edwards25519.Point{g, P, C[i]})
		// R = s_i·Hp(P_i) + c_p·I + c_c·D
		hi := primitives.BiasedHashToEC(ring[i].Dest)
		R := new(edwards25519.Point).VarTimeMultiScalarMult(
			[]*edwards25519.Scalar{si, cP, cC}, []*edwards25519.Point{hi, iPt, dPt})

		toHash[2*n+3] = ringct.Key(L.Bytes())
		toHash[2*n+4] = ringct.Key(R.Bytes())
		c = ringct.HashToScalarKeys(toHash...)

		i = (i + 1) % n
		if i == 0 {
			sig.C1 = ringct.Key(c.Bytes())
		}
	}

	// clsag_sign: s_l = a - c·(mu_P·p + mu_C·z)
	x := new(edwards25519.Scalar).Multiply(muP, p)
	x.MultiplyAdd(muC, z, x)
	defer primitives.WipeScalar(x)
	sl := new(edwards25519.Scalar).Multiply(c, x)
	sl.Subtract(a, sl)
	sig.S[l] = ringct.Key(sl.Bytes())
	return sig, I, nil
}
