// Copyright (c) 2026, The monergo Authors
// SPDX-License-Identifier: BSD-3-Clause

package builder

import (
	"github.com/sina-haseli/monergo/keys"
	"github.com/sina-haseli/monergo/protocol"
)

// PrivateKeys are the wallet's private spend and view keys.
type PrivateKeys = keys.AccountKeys

// RingMember is one member of an input's ring, as returned by the daemon's
// /get_outs: the output's global index, its one-time key and its commitment.
type RingMember struct {
	GlobalIndex uint64         `json:"global_index"`
	Key         keys.PublicKey `json:"key"`
	Commitment  keys.PublicKey `json:"commitment"`
}

// Input is one owned output to spend, with its ring.
type Input struct {
	// TxPubKey and AdditionalTxPubKeys come from the extra of the transaction that
	// created the output.
	TxPubKey            keys.PublicKey   `json:"tx_pub_key"`
	AdditionalTxPubKeys []keys.PublicKey `json:"additional_tx_pub_keys,omitempty"`
	// OutputIndex is the output's position inside that transaction.
	OutputIndex uint64         `json:"output_index"`
	OutputKey   keys.PublicKey `json:"output_key"`
	Amount      uint64         `json:"amount"`
	// Coinbase marks an output of a coinbase (RCT type Null) transaction, whose
	// commitment is G + amount·H.
	Coinbase   bool                 `json:"coinbase,omitempty"`
	Subaddress keys.SubaddressIndex `json:"subaddress"`
	// Ring is sorted by global index and contains the real output at RealIndex.
	Ring      []RingMember `json:"ring"`
	RealIndex int          `json:"real_index"`
}

// Destination is a recipient address and amount in atomic units.
type Destination struct {
	Address string `json:"address"`
	Amount  uint64 `json:"amount"`
}

// TransferRequest is everything the stateless signer needs. It is
// JSON-serializable; keys are hex.
type TransferRequest struct {
	Network protocol.Network `json:"network"`
	// HardFork defaults to protocol.CurrentHardFork; any other value is refused.
	HardFork     uint8         `json:"hard_fork,omitempty"`
	Inputs       []Input       `json:"inputs"`
	Destinations []Destination `json:"destinations"`
	// ChangeSubaddress receives the change. When omitted it is (account, 0), where
	// account is the inputs' account, as wallet2 does.
	ChangeSubaddress *keys.SubaddressIndex `json:"change_subaddress,omitempty"`
	// FeePerByte is the daemon's per-byte fee for the chosen priority
	// (get_fee_estimate fee × priority multiplier).
	FeePerByte uint64 `json:"fee_per_byte"`
	// FeeQuantizationMask is get_fee_estimate's quantization_mask (usually 10000).
	FeeQuantizationMask uint64 `json:"fee_quantization_mask"`
	// MaxFee is a hard cap: signing fails rather than pay more.
	MaxFee uint64 `json:"max_fee"`
}

// Signed is a signed transaction with what a caller may want to keep.
type Signed struct {
	TxHex  string `json:"tx_hex"`
	TxHash string `json:"tx_hash"`
	Fee    uint64 `json:"fee"`
	Weight uint64 `json:"weight"`
	// TxKey and AdditionalTxKeys prove payments (check_tx_key). Treat as secret.
	TxKey            keys.SecretKey   `json:"tx_key"`
	AdditionalTxKeys []keys.SecretKey `json:"additional_tx_keys,omitempty"`
	KeyImages        []keys.KeyImage  `json:"key_images"`
	Change           uint64           `json:"change"`
}

// Wipe zeroes the secret keys in s.
func (s *Signed) Wipe() {
	s.TxKey.Wipe()
	for i := range s.AdditionalTxKeys {
		s.AdditionalTxKeys[i].Wipe()
	}
}
