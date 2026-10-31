// Copyright (c) 2014-2026, The Monero Project
// Copyright (c) 2026, The monergo Authors
// SPDX-License-Identifier: BSD-3-Clause

// Package verify checks the RingCT part of a transaction: input rules, balance,
// Bulletproofs+ and every CLSAG. It does not check anything that needs the chain
// (spent key images, output unlock times, decoy ages); the caller supplies the
// ring members.
//
// Ported from monero @3fd0f88c20f559839cafb20911cb13cb45eba7bd:
// src/ringct/rctSigs.cpp (verRctSemanticsSimple, verRctNonSemanticsSimple),
// src/cryptonote_basic/cryptonote_format_utils.cpp (expand_transaction_1),
// src/cryptonote_core/blockchain.cpp (expand_transaction_2, sorted inputs) and
// src/cryptonote_core/cryptonote_core.cpp (check_tx_inputs_keyimages_diff,
// check_tx_inputs_ring_members_diff, check_tx_inputs_keyimages_domain).
package verify

import (
	"bytes"
	"errors"
	"fmt"

	"filippo.io/edwards25519"
	"github.com/sina-haseli/monergo/primitives"
	"github.com/sina-haseli/monergo/ringct"
	"github.com/sina-haseli/monergo/ringct/bpplus"
	"github.com/sina-haseli/monergo/ringct/clsag"
	"github.com/sina-haseli/monergo/tx"
)

var (
	// ErrInvalid is returned when a check fails.
	ErrInvalid = errors.New("verify: invalid transaction")
	// ErrUnsupported is returned for RCT types whose range proofs are not implemented.
	ErrUnsupported = errors.New("verify: unsupported rct type")
)

// RingMember is one ring member as returned by /get_outs: output key and commitment.
type RingMember = clsag.Member

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

// Inputs checks the consensus rules on inputs that need no chain data: distinct
// key images, key images in the prime-order subgroup and not the identity, strictly
// decreasing key images (memcmp order), and no repeated ring member.
func Inputs(t *tx.Transaction) error {
	if t.IsCoinbase() || len(t.Inputs) == 0 {
		return invalid("no key inputs")
	}
	seen := map[[32]byte]bool{}
	for i, in := range t.Inputs {
		if in.Gen {
			return invalid("txin_gen in a non-coinbase transaction")
		}
		if len(in.KeyOffsets) == 0 {
			return invalid("input %d has no key offsets", i)
		}
		// check_tx_inputs_ring_members_diff (hf >= 6)
		for n := 1; n < len(in.KeyOffsets); n++ {
			if in.KeyOffsets[n] == 0 {
				return invalid("input %d repeats a ring member", i)
			}
		}
		// check_tx_inputs_keyimages_diff
		if seen[in.KeyImage] {
			return invalid("duplicate key image")
		}
		seen[in.KeyImage] = true
		// check_tx_inputs_keyimages_domain
		if in.KeyImage == ringct.IdentityBytes {
			return invalid("identity key image")
		}
		p, err := primitives.DecodePoint(in.KeyImage)
		if err != nil || !primitives.IsInMainSubgroup(p) {
			return invalid("key image %d out of the prime-order subgroup", i)
		}
		// Blockchain::check_tx_inputs: "from v7, sorted ins"
		if i > 0 && bytes.Compare(in.KeyImage[:], t.Inputs[i-1].KeyImage[:]) >= 0 {
			return invalid("unsorted inputs")
		}
	}
	return nil
}

// Balance checks Σ pseudoOuts = Σ outPk + fee·H.
//
// Ported from monero src/ringct/rctSigs.cpp: verRctSemanticsSimple (sum check).
func Balance(t *tx.Transaction) error {
	if len(t.RCT.PseudoOuts) != len(t.Inputs) || len(t.RCT.OutPk) != len(t.Outputs) {
		return invalid("pseudoOuts/outPk sizes")
	}
	sumOut := new(edwards25519.Point).ScalarMult(ringct.AmountScalar(t.RCT.Fee), ringct.H())
	for _, c := range t.RCT.OutPk {
		p, err := primitives.DecodePoint(c)
		if err != nil {
			return invalid("bad output commitment")
		}
		sumOut.Add(sumOut, p)
	}
	sumIn := edwards25519.NewIdentityPoint()
	for _, c := range t.RCT.PseudoOuts {
		p, err := primitives.DecodePoint(c)
		if err != nil {
			return invalid("bad pseudo output")
		}
		sumIn.Add(sumIn, p)
	}
	if sumIn.Equal(sumOut) != 1 {
		return invalid("sum check failed")
	}
	return nil
}

// RangeProofs checks the Bulletproof+ of a type 6 transaction, after restoring its
// commitments V = outPk·8^-1.
//
// Ported from monero src/cryptonote_basic/cryptonote_format_utils.cpp:
// expand_transaction_1 and src/ringct/rctSigs.cpp: verBulletproofPlus.
func RangeProofs(t *tx.Transaction) error {
	if t.RCT.Type != ringct.TypeBulletproofPlus {
		return fmt.Errorf("%w: %d", ErrUnsupported, t.RCT.Type)
	}
	if len(t.RCT.BulletproofsPlus) != 1 {
		return invalid("want exactly one bulletproof+")
	}
	p := t.RCT.BulletproofsPlus[0]
	if len(p.L) < 6 || ringct.MaxAmountsBase(len(p.L), len(p.R)) < len(t.Outputs) {
		return invalid("bulletproof+ too small")
	}
	inv8 := ringct.InvEight()
	p.V = make([]ringct.Key, len(t.RCT.OutPk))
	for i, c := range t.RCT.OutPk {
		pt, err := primitives.DecodePoint(c)
		if err != nil {
			return invalid("bad output commitment")
		}
		p.V[i] = ringct.Key(new(edwards25519.Point).ScalarMult(inv8, pt).Bytes())
	}
	if err := bpplus.Verify([]*ringct.BulletproofPlus{&p}); err != nil {
		return invalid("bulletproof+: %v", err)
	}
	return nil
}

// CLSAGs checks every input's CLSAG over the signature hash, with the input's key
// image and pseudo output.
//
// Ported from monero src/ringct/rctSigs.cpp: verRctNonSemanticsSimple.
func CLSAGs(t *tx.Transaction, rings [][]RingMember) error {
	if len(rings) != len(t.Inputs) || len(t.RCT.CLSAGs) != len(t.Inputs) || len(t.RCT.PseudoOuts) != len(t.Inputs) {
		return invalid("ring/CLSAG/pseudoOut counts")
	}
	msg, err := t.SignatureHash()
	if err != nil {
		return err
	}
	for i, in := range t.Inputs {
		if len(rings[i]) != len(in.KeyOffsets) {
			return invalid("input %d: ring has %d members, key offsets %d", i, len(rings[i]), len(in.KeyOffsets))
		}
		if err := clsag.Verify(msg, t.RCT.CLSAGs[i], in.KeyImage, rings[i], t.RCT.PseudoOuts[i]); err != nil {
			return invalid("input %d: %v", i, err)
		}
	}
	return nil
}

// Transaction runs every check: inputs, sizes, balance, range proofs and CLSAGs.
// Only RCT type 6 (BulletproofPlus) is fully supported.
func Transaction(t *tx.Transaction, rings [][]RingMember) error {
	if t.RCT.Type != ringct.TypeBulletproofPlus {
		return fmt.Errorf("%w: %d", ErrUnsupported, t.RCT.Type)
	}
	if err := Inputs(t); err != nil {
		return err
	}
	if len(t.RCT.OutPk) != len(t.Outputs) || len(t.RCT.EcdhAmounts) != len(t.Outputs) {
		return invalid("outPk/ecdhInfo sizes")
	}
	if err := Balance(t); err != nil {
		return err
	}
	if err := RangeProofs(t); err != nil {
		return err
	}
	return CLSAGs(t, rings)
}
