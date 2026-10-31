// Copyright (c) 2014-2026, The Monero Project
// Copyright (c) 2026, The monergo Authors
// SPDX-License-Identifier: BSD-3-Clause

package protocol

import "fmt"

// CurrentHardFork is the newest hard fork this library can build transactions for.
// v16 has been live on mainnet, testnet and stagenet since 2022. FCMP++ (expected
// v17) changes the transaction format; until it is implemented, signing for any
// other version is refused.
const CurrentHardFork uint8 = 16

// Hard-fork thresholds from monero src/cryptonote_config.h @3fd0f88.
const (
	hfVersionMin2Outputs     = 12 // HF_VERSION_MIN_2_OUTPUTS
	hfVersionMinMixin15      = 15 // HF_VERSION_MIN_MIXIN_15
	hfVersionBulletproofPlus = 15 // HF_VERSION_BULLETPROOF_PLUS
	hfVersionViewTags        = 15 // HF_VERSION_VIEW_TAGS
)

// Consensus and relay limits.
const (
	// MaxOutputs is BULLETPROOF_PLUS_MAX_OUTPUTS: one aggregated range proof per tx.
	MaxOutputs = 16
	// MaxTxExtraSize is MAX_TX_EXTRA_SIZE.
	MaxTxExtraSize = 1060
	// MaxTxWeight is the relay limit for a transaction since v8:
	// CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5 / 2 - CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE
	// (wallet2::get_upper_transaction_weight_limit).
	MaxTxWeight = 300000/2 - 600
)

// Rules are the transaction-building rules of one hard fork.
type Rules struct {
	Version    uint8
	RingSize   int  // exact number of ring members per input
	MinOutputs int  // minimum outputs per transaction
	ViewTags   bool // outputs are txout_to_tagged_key
	RCTType    uint8
}

// RulesFor returns the rules for hard fork hf. Only CurrentHardFork is supported
// for building; other forks are rejected rather than half-supported.
//
// The ring size rule ports src/cryptonote_core/blockchain.cpp check_tx_inputs: from
// HF_VERSION_MIN_MIXIN_15 every ring has exactly 16 members (mixin 15).
func RulesFor(hf uint8) (Rules, error) {
	if hf != CurrentHardFork {
		return Rules{}, fmt.Errorf("protocol: hard fork %d is not supported (only %d)", hf, CurrentHardFork)
	}
	r := Rules{Version: hf, RingSize: 16, MinOutputs: 1, RCTType: 5}
	if hf >= hfVersionMin2Outputs {
		r.MinOutputs = 2
	}
	if hf >= hfVersionMinMixin15 {
		r.RingSize = 16
	}
	if hf >= hfVersionViewTags {
		r.ViewTags = true
	}
	if hf >= hfVersionBulletproofPlus {
		r.RCTType = 6 // RCTTypeBulletproofPlus
	}
	return r, nil
}
