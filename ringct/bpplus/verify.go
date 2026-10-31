// Copyright (c) 2014-2026, The Monero Project
// Copyright (c) 2026, The monergo Authors
// SPDX-License-Identifier: BSD-3-Clause

package bpplus

import (
	"crypto/rand"
	"errors"

	"filippo.io/edwards25519"
	"github.com/sina-haseli/monergo/primitives"
	"github.com/sina-haseli/monergo/ringct"
)

// ErrInvalid is returned when a proof (or any proof in a batch) does not verify.
var ErrInvalid = errors.New("bpplus: invalid proof")

type proofData struct {
	y, z, e    *edwards25519.Scalar
	challenges []*edwards25519.Scalar
	logM       int
}

func decode8(k ringct.Key) (*edwards25519.Point, error) {
	p, err := primitives.DecodePoint(k)
	if err != nil {
		return nil, err
	}
	return p.MultByCofactor(p), nil
}

func randomWeight() *edwards25519.Scalar {
	for {
		var b [64]byte
		if _, err := rand.Read(b[:]); err != nil {
			panic(err)
		}
		w, _ := new(edwards25519.Scalar).SetUniformBytes(b[:])
		if !isZero(w) {
			return w
		}
	}
}

// Verify checks a batch of proofs. Each proof's V must already be set (for a
// transaction: outPk[i]·8^-1). Any decoding failure is a verification failure, as
// upstream's verBulletproofPlus catches the throw.
//
// Ported from monero src/ringct/bulletproofs_plus.cc: bulletproof_plus_VERIFY.
func Verify(proofs []*ringct.BulletproofPlus) error {
	if len(proofs) == 0 {
		return ErrInvalid
	}
	g := initGenerators()

	maxLength := 0
	pds := make([]proofData, len(proofs))
	for k, proof := range proofs {
		// Sanity checks
		for _, s := range []ringct.Key{proof.R1, proof.S1, proof.D1} {
			if !primitives.ScCheck(s) {
				return ErrInvalid // "Input scalar not in range"
			}
		}
		if len(proof.V) < 1 || len(proof.V) > maxM || len(proof.L) != len(proof.R) || len(proof.L) == 0 {
			return ErrInvalid
		}
		if len(proof.L) > maxLength {
			maxLength = len(proof.L)
		}
		pd := &pds[k]

		// Reconstruct the challenges
		transcript := g.initialTranscript
		transcriptUpdate(&transcript, key(ringct.HashToScalarKeys(proof.V...)))
		pd.y = transcriptUpdate(&transcript, proof.A)
		if isZero(pd.y) {
			return ErrInvalid
		}
		pd.z = ringct.HashToScalarKeys(key(pd.y))
		transcript = key(pd.z)
		if isZero(pd.z) {
			return ErrInvalid
		}

		// Number of inner-product rounds from the proof size
		for pd.logM = 0; 1<<pd.logM <= maxM && 1<<pd.logM < len(proof.V); pd.logM++ {
		}
		if len(proof.L) != 6+pd.logM {
			return ErrInvalid // "Proof is not the expected size"
		}
		rounds := pd.logM + logN
		pd.challenges = make([]*edwards25519.Scalar, rounds)
		for j := 0; j < rounds; j++ {
			pd.challenges[j] = transcriptUpdate(&transcript, proof.L[j], proof.R[j])
			if isZero(pd.challenges[j]) {
				return ErrInvalid
			}
		}
		pd.e = transcriptUpdate(&transcript, proof.A1, proof.B)
		if isZero(pd.e) {
			return ErrInvalid
		}
	}
	if maxLength >= 32 {
		return ErrInvalid // "At least one proof is too large"
	}
	maxMN := 1 << maxLength
	if maxMN > maxN*maxM {
		return ErrInvalid
	}

	var scalars []*edwards25519.Scalar
	var points []*edwards25519.Point
	add := func(s *edwards25519.Scalar, p *edwards25519.Point) {
		scalars = append(scalars, s)
		points = append(points, p)
	}

	gScalar := scalarZero()
	hScalar := scalarZero()
	giScalars := make([]*edwards25519.Scalar, maxMN)
	hiScalars := make([]*edwards25519.Scalar, maxMN)
	for i := range giScalars {
		giScalars[i] = scalarZero()
		hiScalars[i] = scalarZero()
	}
	minusOne := new(edwards25519.Scalar).Negate(scalarFromUint(1))

	for k, proof := range proofs {
		pd := &pds[k]
		M := 1 << pd.logM
		MN := M * maxN

		weight := randomWeight()

		// Rescale previously offset proof elements into the prime-order subgroup.
		v8 := make([]*edwards25519.Point, len(proof.V))
		for i, v := range proof.V {
			p, err := decode8(v)
			if err != nil {
				return ErrInvalid
			}
			v8[i] = p
		}
		l8 := make([]*edwards25519.Point, len(proof.L))
		r8 := make([]*edwards25519.Point, len(proof.R))
		for i := range proof.L {
			var err error
			if l8[i], err = decode8(proof.L[i]); err != nil {
				return ErrInvalid
			}
			if r8[i], err = decode8(proof.R[i]); err != nil {
				return ErrInvalid
			}
		}
		a18, err := decode8(proof.A1)
		if err != nil {
			return ErrInvalid
		}
		b8, err := decode8(proof.B)
		if err != nil {
			return ErrInvalid
		}
		a8, err := decode8(proof.A)
		if err != nil {
			return ErrInvalid
		}

		// Powers of the y-challenge
		yMN := new(edwards25519.Scalar).Set(pd.y)
		for t := MN; t > 1; t /= 2 {
			yMN.Multiply(yMN, yMN)
		}
		yMN1 := new(edwards25519.Scalar).Multiply(yMN, pd.y)

		// V_j: -e**2 * z**(2*j+1) * y**(MN+1) * weight
		eSquared := new(edwards25519.Scalar).Multiply(pd.e, pd.e)
		zSquared := new(edwards25519.Scalar).Multiply(pd.z, pd.z)
		temp := new(edwards25519.Scalar).Negate(eSquared)
		temp.Multiply(temp, yMN1)
		temp.Multiply(temp, weight)
		for j := range v8 {
			temp.Multiply(temp, zSquared)
			add(new(edwards25519.Scalar).Set(temp), v8[j])
		}

		// B: -weight
		temp = new(edwards25519.Scalar).Multiply(minusOne, weight)
		add(new(edwards25519.Scalar).Set(temp), b8)
		// A1: -weight*e
		temp.Multiply(temp, pd.e)
		add(new(edwards25519.Scalar).Set(temp), a18)
		// A: -weight*e*e
		minusWeightESquared := new(edwards25519.Scalar).Multiply(temp, pd.e)
		add(minusWeightESquared, a8)

		// G: weight*d1
		d1, _ := primitives.ScalarFromCanonical(proof.D1)
		gScalar.MultiplyAdd(weight, d1, gScalar)

		// Windowed vector d[j*N+i] = z**(2*(j+1)) * 2**i
		d := make([]*edwards25519.Scalar, MN)
		d[0] = new(edwards25519.Scalar).Set(zSquared)
		for i := 1; i < maxN; i++ {
			d[i] = new(edwards25519.Scalar).Add(d[i-1], d[i-1])
		}
		for j := 1; j < M; j++ {
			for i := 0; i < maxN; i++ {
				d[j*maxN+i] = new(edwards25519.Scalar).Multiply(d[(j-1)*maxN+i], zSquared)
			}
		}

		sumD := new(edwards25519.Scalar).Multiply(g.twoSixtyFourMinus1, sumOfEvenPowers(pd.z, 2*M))

		// H: weight*( r1*y*s1 + e**2*( y**(MN+1)*z*sum(d) + (z**2-z)*sum(y) ) )
		r1, _ := primitives.ScalarFromCanonical(proof.R1)
		s1, _ := primitives.ScalarFromCanonical(proof.S1)
		sumY := sumOfScalarPowers(pd.y, MN)
		temp = new(edwards25519.Scalar).Subtract(zSquared, pd.z)
		temp.Multiply(temp, sumY)
		temp2 := new(edwards25519.Scalar).Multiply(yMN1, pd.z)
		temp2.Multiply(temp2, sumD)
		temp.Add(temp, temp2)
		temp.Multiply(temp, eSquared)
		temp2.Multiply(r1, pd.y)
		temp2.Multiply(temp2, s1)
		temp.Add(temp, temp2)
		hScalar.MultiplyAdd(temp, weight, hScalar)

		rounds := pd.logM + logN
		challengesInv := make([]*edwards25519.Scalar, rounds)
		for j, c := range pd.challenges {
			challengesInv[j] = new(edwards25519.Scalar).Invert(c)
		}
		yinv := new(edwards25519.Scalar).Invert(pd.y)

		// Challenge products: cache[s] for s's binary decomposition
		cache := make([]*edwards25519.Scalar, 1<<rounds)
		cache[0] = new(edwards25519.Scalar).Set(challengesInv[0])
		cache[1] = new(edwards25519.Scalar).Set(pd.challenges[0])
		for j := 1; j < rounds; j++ {
			slots := 1 << (j + 1)
			// Upstream walks s = slots-1, slots-3, ..., 1 writing (s, s-1) from s/2.
			for s := slots - 1; s > 0; s -= 2 {
				parent := new(edwards25519.Scalar).Set(cache[s/2])
				cache[s] = new(edwards25519.Scalar).Multiply(parent, pd.challenges[j])
				cache[s-1] = new(edwards25519.Scalar).Multiply(parent, challengesInv[j])
			}
		}

		// Gi and Hi
		eR1WY := new(edwards25519.Scalar).Multiply(pd.e, r1)
		eR1WY.Multiply(eR1WY, weight)
		eS1W := new(edwards25519.Scalar).Multiply(pd.e, s1)
		eS1W.Multiply(eS1W, weight)
		eSquaredZW := new(edwards25519.Scalar).Multiply(eSquared, pd.z)
		eSquaredZW.Multiply(eSquaredZW, weight)
		minusESquaredZW := new(edwards25519.Scalar).Negate(eSquaredZW)
		minusESquaredWY := new(edwards25519.Scalar).Negate(eSquared)
		minusESquaredWY.Multiply(minusESquaredWY, weight)
		minusESquaredWY.Multiply(minusESquaredWY, yMN)
		for i := 0; i < MN; i++ {
			gS := new(edwards25519.Scalar).MultiplyAdd(eR1WY, cache[i], eSquaredZW)
			hS := new(edwards25519.Scalar).MultiplyAdd(eS1W, cache[(^i)&(MN-1)], minusESquaredZW)
			giScalars[i].Add(giScalars[i], gS)
			hS.MultiplyAdd(minusESquaredWY, d[i], hS)
			hiScalars[i].Add(hiScalars[i], hS)
			eR1WY.Multiply(eR1WY, yinv)
			minusESquaredWY.Multiply(minusESquaredWY, yinv)
		}

		// L_j: -weight*e*e*challenges[j]**2, R_j: -weight*e*e*challenges[j]**(-2)
		for j := 0; j < rounds; j++ {
			t := new(edwards25519.Scalar).Multiply(pd.challenges[j], pd.challenges[j])
			t.Multiply(t, minusWeightESquared)
			add(t, l8[j])
			t = new(edwards25519.Scalar).Multiply(challengesInv[j], challengesInv[j])
			t.Multiply(t, minusWeightESquared)
			add(t, r8[j])
		}
	}

	add(gScalar, edwards25519.NewGeneratorPoint())
	add(hScalar, ringct.H())
	for i := 0; i < maxMN; i++ {
		add(giScalars[i], g.Gi[i])
		add(hiScalars[i], g.Hi[i])
	}
	res := new(edwards25519.Point).VarTimeMultiScalarMult(scalars, points)
	if !primitives.IsIdentity(res) {
		return ErrInvalid
	}
	return nil
}
