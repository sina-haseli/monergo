// Copyright (c) 2014-2026, The Monero Project
// Copyright (c) 2026, The monergo Authors
// SPDX-License-Identifier: BSD-3-Clause

package ringct

import (
	"encoding/binary"

	"filippo.io/edwards25519"
	"github.com/sina-haseli/monergo/primitives"
)

// GenCommitmentMask returns the deterministic output mask Hs("commitment_mask" ‖ k)
// for amount key k = Hs(derivation ‖ output index), used by RCT types 4 to 6.
//
// Ported from monero src/ringct/rctOps.cpp: genCommitmentMask.
func GenCommitmentMask(amountKey Key) *edwards25519.Scalar {
	return primitives.HashToScalar([]byte("commitment_mask"), amountKey[:])
}

// amountEncodingFactor is Keccak("amount" ‖ k), unreduced.
//
// Ported from monero src/ringct/rctOps.cpp: genAmountEncodingFactor.
func amountEncodingFactor(amountKey Key) [32]byte {
	return primitives.Keccak256([]byte("amount"), amountKey[:])
}

// EncryptAmount XORs the 8-byte little-endian amount with the encoding factor
// (compressed v2 ecdhInfo).
//
// Ported from monero src/ringct/rctOps.cpp: ecdhEncode (v2).
func EncryptAmount(amount uint64, amountKey Key) [8]byte {
	f := amountEncodingFactor(amountKey)
	var out [8]byte
	binary.LittleEndian.PutUint64(out[:], amount)
	for i := range out {
		out[i] ^= f[i]
	}
	clear(f[:])
	return out
}

// DecryptAmount reverses EncryptAmount.
//
// Ported from monero src/ringct/rctOps.cpp: ecdhDecode (v2).
func DecryptAmount(enc [8]byte, amountKey Key) uint64 {
	f := amountEncodingFactor(amountKey)
	for i := range enc {
		enc[i] ^= f[i]
	}
	clear(f[:])
	return binary.LittleEndian.Uint64(enc[:])
}
