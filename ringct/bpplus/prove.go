// Copyright (c) 2014-2026, The Monero Project
// Copyright (c) 2026, The monergo Authors
// SPDX-License-Identifier: BSD-3-Clause

package bpplus

import (
	"errors"
	"io"

	"filippo.io/edwards25519"
	"github.com/sina-haseli/monergo/primitives"
	"github.com/sina-haseli/monergo/ringct"
)

// ErrBadInput is returned for invalid prover inputs.
var ErrBadInput = errors.New("bpplus: bad prover input")

type scalar = edwards25519.Scalar
type point = edwards25519.Point

func sMul(a, b *scalar) *scalar { return new(scalar).Multiply(a, b) }
func sAdd(a, b *scalar) *scalar { return new(scalar).Add(a, b) }
func sCopy(a *scalar) *scalar   { return new(scalar).Set(a) }
func pCopy(a *point) *point     { return new(point).Set(a) }

// ctMultiexp computes Σ s_i·P_i in constant time; used whenever a scalar depends
// on the amounts or blinding factors. (Upstream uses a variable-time multiexp.)
func ctMultiexp(s []*scalar, p []*point) *point {
	return new(point).MultiScalarMult(s, p)
}

// weightedInnerProduct returns Σ a_i·b_i·y^(i+1).
//
// Ported from monero src/ringct/bulletproofs_plus.cc: weighted_inner_product.
func weightedInnerProduct(a, b []*scalar, y *scalar) *scalar {
	res := scalarZero()
	yPower := scalarFromUint(1)
	temp := new(scalar)
	for i := range a {
		temp.Multiply(a[i], b[i])
		yPower.Multiply(yPower, y)
		res.MultiplyAdd(temp, yPower, res)
	}
	return res
}

// computeLR returns Σ (a[a0+i]·y/8)·G[G0+i] + (b[b0+i]/8)·H[H0+i] + (c/8)·H + (d/8)·G.
//
// Ported from monero src/ringct/bulletproofs_plus.cc: compute_LR.
func computeLR(size int, y *scalar, G []*point, g0 int, H []*point, h0 int, a []*scalar, a0 int, b []*scalar, b0 int, c, d *scalar) ringct.Key {
	inv8 := ringct.InvEight()
	ss := make([]*scalar, 0, 2*size+2)
	ps := make([]*point, 0, 2*size+2)
	for i := 0; i < size; i++ {
		ss = append(ss, sMul(sMul(a[a0+i], y), inv8))
		ps = append(ps, G[g0+i])
		ss = append(ss, sMul(b[b0+i], inv8))
		ps = append(ps, H[h0+i])
	}
	ss = append(ss, sMul(c, inv8), sMul(d, inv8))
	ps = append(ps, ringct.H(), edwards25519.NewGeneratorPoint())
	return ringct.Key(ctMultiexp(ss, ps).Bytes())
}

// hadamardFold sets v[n] = a·v[n] + b·v[sz+n] and halves v. a and b are public
// challenges, so variable time is fine.
//
// Ported from monero src/ringct/bulletproofs_plus.cc: hadamard_fold.
func hadamardFold(v []*point, a, b *scalar) []*point {
	sz := len(v) / 2
	for n := 0; n < sz; n++ {
		v[n] = new(point).VarTimeMultiScalarMult([]*scalar{a, b}, []*point{v[n], v[sz+n]})
	}
	return v[:sz]
}

// Prove builds an aggregated range proof that each amount is in [0, 2^64), for the
// commitments gamma_i·G + amount_i·H. The returned proof's V are those
// commitments divided by 8, as upstream stores them.
//
// Ported from monero src/ringct/bulletproofs_plus.cc: bulletproof_plus_PROVE (the
// uint64 and keyV overloads).
func Prove(rand io.Reader, amounts []uint64, gammas []*scalar) (*ringct.BulletproofPlus, error) {
	if len(amounts) != len(gammas) || len(amounts) == 0 {
		return nil, ErrBadInput
	}
	g := initGenerators()
	inv8 := ringct.InvEight()
	one := scalarFromUint(1)

	// M: first power of 2 >= the number of amounts
	logM := 0
	for 1<<logM <= maxM && 1<<logM < len(amounts) {
		logM++
	}
	M := 1 << logM
	if M > maxM {
		return nil, ErrBadInput // "sv/gamma are too large"
	}
	MN := M * maxN
	logMN := logM + logN

	// Output commitments offset by 8^-1: V_i = (gamma_i/8)·G + (v_i/8)·H
	V := make([]ringct.Key, len(amounts))
	for i := range amounts {
		gamma8 := sMul(gammas[i], inv8)
		sv8 := sMul(ringct.AmountScalar(amounts[i]), inv8)
		p := new(point).ScalarBaseMult(gamma8)
		p.Add(p, new(point).ScalarMult(sv8, ringct.H()))
		V[i] = ringct.Key(p.Bytes())
		primitives.WipeScalar(gamma8)
		primitives.WipeScalar(sv8)
	}

	// Decompose values (pads to M amounts with zeros)
	aL := make([]*scalar, MN)
	aR := make([]*scalar, MN)
	aL8 := make([]*scalar, MN)
	aR8 := make([]*scalar, MN)
	// Upstream branches on each bit: aL = 1, aR = 0 if set, else aL = 0, aR = -1.
	// The same values are computed arithmetically here (aL = b, aR = b - 1) so the
	// secret amount bits never select a branch.
	for j := 0; j < M; j++ {
		var v uint64
		if j < len(amounts) { // public: number of outputs
			v = amounts[j]
		}
		for i := maxN - 1; i >= 0; i-- {
			k := j*maxN + i
			b := scalarFromUint((v >> uint(i)) & 1)
			aL[k] = b
			aR[k] = new(scalar).Subtract(b, one)
			aL8[k] = sMul(b, inv8)
			aR8[k] = sMul(aR[k], inv8)
		}
	}

tryAgain:
	transcript := g.initialTranscript
	transcriptUpdate(&transcript, key(ringct.HashToScalarKeys(V...)))

	// A = Σ aL8·Gi + aR8·Hi + (alpha/8)·G
	alpha, err := primitives.RandomScalar(rand)
	if err != nil {
		return nil, err
	}
	ss := make([]*scalar, 0, 2*MN+1)
	ps := make([]*point, 0, 2*MN+1)
	for i := 0; i < MN; i++ {
		ss = append(ss, aL8[i], aR8[i])
		ps = append(ps, g.Gi[i], g.Hi[i])
	}
	ss = append(ss, sMul(alpha, inv8))
	ps = append(ps, edwards25519.NewGeneratorPoint())
	A := ringct.Key(ctMultiexp(ss, ps).Bytes())

	// Challenges
	y := transcriptUpdate(&transcript, A)
	if isZero(y) {
		goto tryAgain
	}
	z := ringct.HashToScalarKeys(key(y))
	transcript = key(z)
	if isZero(z) {
		goto tryAgain
	}
	zSquared := sMul(z, z)

	// d[j*N+i] = z**(2*(j+1)) * 2**i
	two := scalarFromUint(2)
	d := make([]*scalar, MN)
	d[0] = sCopy(zSquared)
	for i := 1; i < maxN; i++ {
		d[i] = sMul(d[i-1], two)
	}
	for j := 1; j < M; j++ {
		for i := 0; i < maxN; i++ {
			d[j*maxN+i] = sMul(d[(j-1)*maxN+i], zSquared)
		}
	}

	// y_powers = (1, y, ..., y^(MN+1))
	yPowers := make([]*scalar, MN+2)
	yPowers[0] = scalarFromUint(1)
	yPowers[1] = sCopy(y)
	for i := 2; i < MN+2; i++ {
		yPowers[i] = sMul(yPowers[i-1], y)
	}

	// aL1 = aL - z, aR1 = aR + z + d∘y^(MN-i)
	aprime := make([]*scalar, MN)
	bprime := make([]*scalar, MN)
	for i := 0; i < MN; i++ {
		aprime[i] = new(scalar).Subtract(aL[i], z)
		bprime[i] = sAdd(sAdd(aR[i], z), sMul(d[i], yPowers[MN-i]))
	}

	// alpha1 = alpha + Σ_j z^(2(j+1)) · y^(MN+1) · gamma_j
	alpha1 := sCopy(alpha)
	temp := scalarFromUint(1)
	for j := range amounts {
		temp.Multiply(temp, zSquared)
		alpha1.MultiplyAdd(sMul(yPowers[MN+1], temp), gammas[j], alpha1)
	}

	// Inner-product rounds
	nprime := MN
	Gprime := make([]*point, MN)
	Hprime := make([]*point, MN)
	yinv := new(scalar).Invert(y)
	yinvpow := make([]*scalar, MN)
	yinvpow[0] = scalarFromUint(1)
	for i := 0; i < MN; i++ {
		Gprime[i] = pCopy(g.Gi[i])
		Hprime[i] = pCopy(g.Hi[i])
		if i > 0 {
			yinvpow[i] = sMul(yinvpow[i-1], yinv)
		}
	}
	L := make([]ringct.Key, logMN)
	R := make([]ringct.Key, logMN)
	for round := 0; nprime > 1; round++ {
		nprime /= 2
		cL := weightedInnerProduct(aprime[:nprime], bprime[nprime:], y)
		aHiY := make([]*scalar, nprime)
		for i := range aHiY {
			aHiY[i] = sMul(aprime[nprime+i], yPowers[nprime])
		}
		cR := weightedInnerProduct(aHiY, bprime[:nprime], y)
		dL, err := primitives.RandomScalar(rand)
		if err != nil {
			return nil, err
		}
		dR, err := primitives.RandomScalar(rand)
		if err != nil {
			return nil, err
		}
		L[round] = computeLR(nprime, yinvpow[nprime], Gprime, nprime, Hprime, 0, aprime, 0, bprime, nprime, cL, dL)
		R[round] = computeLR(nprime, yPowers[nprime], Gprime, 0, Hprime, nprime, aprime, nprime, bprime, 0, cR, dR)
		challenge := transcriptUpdate(&transcript, L[round], R[round])
		if isZero(challenge) {
			goto tryAgain
		}
		challengeInv := new(scalar).Invert(challenge)

		Gprime = hadamardFold(Gprime, challengeInv, sMul(yinvpow[nprime], challenge))
		Hprime = hadamardFold(Hprime, challenge, challengeInv)

		t := sMul(challengeInv, yPowers[nprime])
		na := make([]*scalar, nprime)
		nb := make([]*scalar, nprime)
		for i := 0; i < nprime; i++ {
			na[i] = sAdd(sMul(aprime[i], challenge), sMul(aprime[nprime+i], t))
			nb[i] = sAdd(sMul(bprime[i], challengeInv), sMul(bprime[nprime+i], challenge))
		}
		aprime, bprime = na, nb

		alpha1.MultiplyAdd(dL, sMul(challenge, challenge), alpha1)
		alpha1.MultiplyAdd(dR, sMul(challengeInv, challengeInv), alpha1)
		primitives.WipeScalar(dL)
		primitives.WipeScalar(dR)
	}

	// Final round
	var rr [4]*scalar // r, s, d_, eta
	for i := range rr {
		if rr[i], err = primitives.RandomScalar(rand); err != nil {
			return nil, err
		}
	}
	r, s, d_, eta := rr[0], rr[1], rr[2], rr[3]

	// A1 = (r/8)·G'0 + (s/8)·H'0 + (d_/8)·G + ((r·y·b'0 + s·y·a'0)/8)·H
	hs := sAdd(sMul(sMul(r, y), bprime[0]), sMul(sMul(s, y), aprime[0]))
	A1 := ringct.Key(ctMultiexp(
		[]*scalar{sMul(r, inv8), sMul(s, inv8), sMul(d_, inv8), sMul(hs, inv8)},
		[]*point{Gprime[0], Hprime[0], edwards25519.NewGeneratorPoint(), ringct.H()},
	).Bytes())
	// B = (eta/8)·G + (r·y·s/8)·H
	B := ringct.Key(ctMultiexp(
		[]*scalar{sMul(eta, inv8), sMul(sMul(sMul(r, y), s), inv8)},
		[]*point{edwards25519.NewGeneratorPoint(), ringct.H()},
	).Bytes())

	e := transcriptUpdate(&transcript, A1, B)
	if isZero(e) {
		goto tryAgain
	}
	eSquared := sMul(e, e)
	r1 := new(scalar).MultiplyAdd(aprime[0], e, r)
	s1 := new(scalar).MultiplyAdd(bprime[0], e, s)
	d1 := new(scalar).MultiplyAdd(d_, e, eta)
	d1.MultiplyAdd(alpha1, eSquared, d1)

	for _, x := range append([]*scalar{alpha, alpha1, r, s, d_, eta}, append(aprime, bprime...)...) {
		primitives.WipeScalar(x)
	}
	return &ringct.BulletproofPlus{
		V: V, A: A, A1: A1, B: B,
		R1: key(r1), S1: key(s1), D1: key(d1),
		L: L, R: R,
	}, nil
}
