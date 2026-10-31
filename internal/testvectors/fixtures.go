package testvectors

import (
	_ "embed"
	"encoding/json"
	"testing"
)

//go:embed data/wallet_fixtures.json
var walletFixturesJSON []byte

//go:embed data/base58_unit_tests.json
var base58UnitTestsJSON []byte

// WalletAddress is one address the reference wallet reported.
type WalletAddress struct {
	Major   uint32 `json:"major"`
	Minor   uint32 `json:"minor"`
	Address string `json:"address"`
}

// Wallet is one restored seed on one network, as reported by monero-wallet-rpc.
type Wallet struct {
	Seed       string          `json:"seed"`
	SpendKey   string          `json:"spend_key"`
	ViewKey    string          `json:"view_key"`
	Mnemonic   string          `json:"mnemonic"`
	Addresses  []WalletAddress `json:"addresses"`
	Integrated struct {
		PaymentID string `json:"payment_id"`
		Address   string `json:"address"`
	} `json:"integrated"`
}

// WalletFixtures is data/wallet_fixtures.json.
type WalletFixtures struct {
	WalletRPCVersion int                 `json:"wallet_rpc_version"`
	Networks         map[string][]Wallet `json:"networks"`
}

// LoadWalletFixtures parses data/wallet_fixtures.json.
func LoadWalletFixtures(t *testing.T) WalletFixtures {
	t.Helper()
	var f WalletFixtures
	if err := json.Unmarshal(walletFixturesJSON, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Networks) != 3 {
		t.Fatalf("want 3 networks, got %d", len(f.Networks))
	}
	return f
}

// Base58UnitTests is data/base58_unit_tests.json, extracted from monero
// tests/unit_tests/base58.cpp. All byte strings are hex.
type Base58UnitTests struct {
	EncodeBlock      []struct{ Data, Enc string } `json:"encode_block"`
	DecodeBlockPos   []struct{ Enc, Data string } `json:"decode_block_pos"`
	DecodeBlockNeg   []struct{ Enc string }       `json:"decode_block_neg"`
	Encode           []struct{ Enc, Data string } `json:"encode"`
	DecodePos        []struct{ Enc, Data string } `json:"decode_pos"`
	DecodeNeg        []struct{ Enc string }       `json:"decode_neg"`
	EncodeDecodeAddr []struct {
		Addr string
		Tag  string
		Data string
	} `json:"encode_decode_addr"`
	DecodeAddrNeg []struct {
		AddrHex string `json:"addr_hex"`
		Name    string
	} `json:"decode_addr_neg"`
}

// LoadBase58UnitTests parses data/base58_unit_tests.json.
func LoadBase58UnitTests(t *testing.T) Base58UnitTests {
	t.Helper()
	var b Base58UnitTests
	if err := json.Unmarshal(base58UnitTestsJSON, &b); err != nil {
		t.Fatal(err)
	}
	return b
}

//go:embed data/chain_fixtures.json
var chainFixturesJSON []byte

// RingMember is one output referenced by a ring, from /get_outs.
type RingMember struct {
	Index  uint64 `json:"index"`
	Key    string `json:"key"`
	Mask   string `json:"mask"`
	TxID   string `json:"txid"`
	Height uint64 `json:"height"`
}

// ChainTx is one real transaction with the ring members of each input.
type ChainTx struct {
	Name         string         `json:"name"`
	Network      string         `json:"network"`
	Hash         string         `json:"hash"`
	BlockHeight  uint64         `json:"block_height"`
	PrunableHash string         `json:"prunable_hash"`
	RCTType      int            `json:"rct_type"`
	Inputs       int            `json:"inputs"`
	Outputs      int            `json:"outputs"`
	Coinbase     bool           `json:"coinbase"`
	Hex          string         `json:"hex"`
	Rings        [][]RingMember `json:"rings"`
}

// LoadChainFixtures parses data/chain_fixtures.json.
func LoadChainFixtures(t testing.TB) []ChainTx {
	t.Helper()
	var f struct {
		Txs []ChainTx `json:"txs"`
	}
	if err := json.Unmarshal(chainFixturesJSON, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Txs) == 0 {
		t.Fatal("no chain fixtures")
	}
	return f.Txs
}
