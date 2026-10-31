// Copyright (c) 2026, The monergo Authors
// SPDX-License-Identifier: BSD-3-Clause

package builder

import (
	"io"

	"filippo.io/edwards25519"
	"github.com/sina-haseli/monergo/ringct"
	"github.com/sina-haseli/monergo/ringct/clsag"
)

// SpendInput is everything an InputSigner needs to prove one input.
type SpendInput struct {
	Ring      []clsag.Member
	RealIndex int
	// OneTimeSecret is the private key of Ring[RealIndex].Dest.
	OneTimeSecret *edwards25519.Scalar
	// Mask is the blinding factor of Ring[RealIndex].Mask.
	Mask *edwards25519.Scalar
	// PseudoMask and PseudoOut are the re-randomized commitment of this input.
	PseudoMask *edwards25519.Scalar
	PseudoOut  ringct.Key
}

// InputSigner produces the membership proof and spend authorization of one input.
// CLSAG is the only implementation; FCMP++ will add another without changing the
// public Sign API.
type InputSigner interface {
	SignInput(rand io.Reader, message ringct.Key, in SpendInput) (ringct.CLSAG, ringct.Key, error)
}

// CLSAGSigner signs inputs with CLSAG (RingCT types 5 and 6).
type CLSAGSigner struct{}

// SignInput implements InputSigner.
func (CLSAGSigner) SignInput(rand io.Reader, message ringct.Key, in SpendInput) (ringct.CLSAG, ringct.Key, error) {
	return clsag.SignSimple(rand, message, in.Ring, in.RealIndex, in.OneTimeSecret, in.Mask, in.PseudoMask, in.PseudoOut)
}

// signerFor returns the InputSigner for an RCT type, from protocol.Rules.
func signerFor(rctType uint8) (InputSigner, bool) {
	switch rctType {
	case ringct.TypeBulletproofPlus:
		return CLSAGSigner{}, true
	}
	return nil, false
}
