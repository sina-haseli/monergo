// Copyright (c) 2014-2026, The Monero Project
// Copyright (c) 2026, The monergo Authors
// SPDX-License-Identifier: BSD-3-Clause

// Package ringct holds the RingCT data types and Pedersen commitment helpers.
// CLSAG and Bulletproofs+ live in the clsag and bpplus subpackages.
//
// Types follow monero src/ringct/rctTypes.h @3fd0f88c20f559839cafb20911cb13cb45eba7bd.
package ringct

// Key is a 32-byte curve point or scalar, as rct::key.
type Key = [32]byte

// RCT signature types (rctTypes.h: RCTTypeNull ... RCTTypeBulletproofPlus).
const (
	TypeNull            uint8 = 0
	TypeFull            uint8 = 1
	TypeSimple          uint8 = 2
	TypeBulletproof     uint8 = 3
	TypeBulletproof2    uint8 = 4
	TypeCLSAG           uint8 = 5
	TypeBulletproofPlus uint8 = 6
)

// CLSAG is one CLSAG signature. The key image I is not serialized; it is the
// input's key image.
type CLSAG struct {
	S  []Key
	C1 Key
	D  Key
}

// BulletproofPlus is an aggregated Bulletproof+ range proof. The commitments V are
// not serialized; they are the outputs' commitments divided by 8.
type BulletproofPlus struct {
	V          []Key
	A, A1, B   Key
	R1, S1, D1 Key
	L, R       []Key
}

// Bulletproof is an original (pre-HF15) aggregated Bulletproof, used by RCT type 5.
type Bulletproof struct {
	V            []Key
	A, S, T1, T2 Key
	Taux, Mu     Key
	L, R         []Key
	Aa, B, T     Key // a, b, t
}

// MaxAmountsBase returns the number of amounts a (B)P(+) with these L/R sizes can
// cover, or 0 if the sizes are invalid.
//
// Ported from monero src/ringct/rctTypes.cpp: n_bulletproof_max_amounts_base
// (BULLETPROOF_MAX_OUTPUTS = BULLETPROOF_PLUS_MAX_OUTPUTS = 16).
func MaxAmountsBase(lSize, rSize int) int {
	const extraBits = 4
	if lSize < 6 || lSize != rSize || lSize > 6+extraBits {
		return 0
	}
	return 1 << (lSize - 6)
}
