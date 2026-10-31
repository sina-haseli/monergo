// Copyright (c) 2014-2026, The Monero Project
// Copyright (c) 2026, The monergo Authors
// SPDX-License-Identifier: BSD-3-Clause

package tx

import (
	"fmt"

	"github.com/sina-haseli/monergo/ringct"
)

// weightClawback returns the Bulletproof(+) weight clawback for a transaction whose
// range proofs cover nPaddedOutputs amounts.
//
// Ported from monero src/cryptonote_basic/cryptonote_format_utils.cpp:
// get_transaction_weight_clawback.
func weightClawback(plus bool, nOutputs, nPaddedOutputs int) (uint64, error) {
	fields := 9
	if plus {
		fields = 6
	}
	bpBase := uint64(32*(fields+7*2)) / 2 // notional size of a 2-output proof, per output
	if nPaddedOutputs <= 2 {
		return 0, nil
	}
	nlr := 0
	for 1<<nlr < nPaddedOutputs {
		nlr++
	}
	nlr += 6
	bpSize := uint64(32 * (fields + 2*nlr))
	if nOutputs > 16 {
		return 0, fmt.Errorf("%w: maximum number of outputs is 16 per transaction", ErrMalformed)
	}
	if bpBase*uint64(nPaddedOutputs) < bpSize {
		return 0, fmt.Errorf("%w: invalid bulletproof clawback", ErrMalformed)
	}
	return (bpBase*uint64(nPaddedOutputs) - bpSize) * 4 / 5, nil
}

// Weight returns the transaction weight used for fees and block limits: the blob
// size plus the Bulletproof(+) clawback.
//
// Ported from monero src/cryptonote_basic/cryptonote_format_utils.cpp:
// get_transaction_weight(const transaction&, size_t).
func (t *Transaction) Weight() (uint64, error) {
	raw, err := t.Serialize()
	if err != nil {
		return 0, err
	}
	size := uint64(len(raw))
	var padded int
	switch t.RCT.Type {
	case ringct.TypeBulletproofPlus:
		for _, p := range t.RCT.BulletproofsPlus {
			padded += ringct.MaxAmountsBase(len(p.L), len(p.R))
		}
	case ringct.TypeCLSAG:
		for _, p := range t.RCT.Bulletproofs {
			padded += ringct.MaxAmountsBase(len(p.L), len(p.R))
		}
	default:
		return size, nil
	}
	claw, err := weightClawback(t.RCT.Type == ringct.TypeBulletproofPlus, len(t.Outputs), padded)
	if err != nil {
		return 0, err
	}
	return size + claw, nil
}
