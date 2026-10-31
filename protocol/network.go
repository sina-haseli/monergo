// Copyright (c) 2014-2026, The Monero Project
// Copyright (c) 2026, The monergo Authors
// SPDX-License-Identifier: BSD-3-Clause

// Package protocol is the single home for Monero network parameters and
// hard-fork rules. No other package hard-codes a consensus constant.
package protocol

import (
	"encoding/json"
	"fmt"
)

// Network identifies a Monero network.
type Network uint8

const (
	Mainnet Network = iota
	Testnet
	Stagenet
)

// Networks lists every supported network.
var Networks = []Network{Mainnet, Testnet, Stagenet}

// AddressPrefixes are the base58 address tags of one network.
type AddressPrefixes struct {
	Standard, Integrated, Subaddress uint64
}

// Prefixes returns the address tags for n.
//
// From monero src/cryptonote_config.h @3fd0f88: CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX,
// CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX and
// CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX in config, config::testnet and
// config::stagenet.
func (n Network) Prefixes() AddressPrefixes {
	switch n {
	case Mainnet:
		return AddressPrefixes{18, 19, 42}
	case Testnet:
		return AddressPrefixes{53, 54, 63}
	case Stagenet:
		return AddressPrefixes{24, 25, 36}
	}
	panic(fmt.Sprintf("protocol: unknown network %d", n))
}

func (n Network) String() string {
	switch n {
	case Mainnet:
		return "mainnet"
	case Testnet:
		return "testnet"
	case Stagenet:
		return "stagenet"
	}
	return fmt.Sprintf("Network(%d)", uint8(n))
}

// ParseNetwork parses "mainnet", "testnet" or "stagenet".
func ParseNetwork(s string) (Network, error) {
	for _, n := range Networks {
		if n.String() == s {
			return n, nil
		}
	}
	return 0, fmt.Errorf("protocol: unknown network %q", s)
}

// MarshalJSON encodes the network by name.
func (n Network) MarshalJSON() ([]byte, error) { return json.Marshal(n.String()) }

// UnmarshalJSON decodes a network name.
func (n *Network) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := ParseNetwork(s)
	if err != nil {
		return err
	}
	*n = v
	return nil
}
