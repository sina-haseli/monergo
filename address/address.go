// Copyright (c) 2014-2026, The Monero Project
// Copyright (c) 2026, The monergo Authors
// SPDX-License-Identifier: BSD-3-Clause

// Package address encodes and decodes Monero standard, integrated and subaddress
// strings for mainnet, testnet and stagenet.
//
// Ported from monero src/cryptonote_basic/cryptonote_basic_impl.cpp
// @3fd0f88c20f559839cafb20911cb13cb45eba7bd.
package address

import (
	"errors"
	"fmt"

	"github.com/sina-haseli/monergo/address/base58"
	"github.com/sina-haseli/monergo/keys"
	"github.com/sina-haseli/monergo/primitives"
	"github.com/sina-haseli/monergo/protocol"
)

// Kind is the address type.
type Kind uint8

const (
	Standard Kind = iota
	Integrated
	Subaddress
)

func (k Kind) String() string {
	switch k {
	case Standard:
		return "standard"
	case Integrated:
		return "integrated"
	case Subaddress:
		return "subaddress"
	}
	return fmt.Sprintf("Kind(%d)", uint8(k))
}

// Address is a decoded Monero address. PaymentID is set only for Integrated.
type Address struct {
	Network   protocol.Network
	Kind      Kind
	Spend     keys.PublicKey
	View      keys.PublicKey
	PaymentID [8]byte
}

var (
	// ErrInvalidFormat covers bad base58, bad checksum and wrong payload length.
	ErrInvalidFormat = errors.New("address: invalid format")
	// ErrWrongNetwork is returned when the prefix belongs to no kind on the network.
	ErrWrongNetwork = errors.New("address: prefix does not match network")
	// ErrInvalidKey is returned when check_address rejects a key.
	ErrInvalidKey = errors.New("address: invalid public key")
)

// String encodes the address.
//
// Ported from monero src/cryptonote_basic/cryptonote_basic_impl.cpp:
// get_account_address_as_str and get_account_integrated_address_as_str.
func (a Address) String() string {
	p := a.Network.Prefixes()
	data := make([]byte, 0, 72)
	data = append(data, a.Spend[:]...)
	data = append(data, a.View[:]...)
	var tag uint64
	switch a.Kind {
	case Standard:
		tag = p.Standard
	case Subaddress:
		tag = p.Subaddress
	case Integrated:
		tag = p.Integrated
		data = append(data, a.PaymentID[:]...)
	default:
		panic("address: unknown kind")
	}
	return base58.EncodeAddr(tag, data)
}

// Parse decodes an address for network net.
//
// Ported from monero src/cryptonote_basic/cryptonote_basic_impl.cpp:
// get_account_address_from_str (with check_address). As upstream, the payload must
// be exactly 64 bytes (72 for integrated), and both keys must be valid points that
// are not the identity and have no torsion component.
func Parse(s string, net protocol.Network) (Address, error) {
	tag, data, err := base58.DecodeAddr(s)
	if err != nil {
		return Address{}, ErrInvalidFormat
	}
	p := net.Prefixes()
	a := Address{Network: net}
	wantLen := 64
	switch tag {
	case p.Integrated:
		a.Kind, wantLen = Integrated, 72
	case p.Standard:
		a.Kind = Standard
	case p.Subaddress:
		a.Kind = Subaddress
	default:
		return Address{}, ErrWrongNetwork
	}
	if len(data) != wantLen {
		return Address{}, ErrInvalidFormat
	}
	copy(a.Spend[:], data[:32])
	copy(a.View[:], data[32:64])
	if a.Kind == Integrated {
		copy(a.PaymentID[:], data[64:])
	}
	if !validKey(a.Spend) || !validKey(a.View) {
		return Address{}, ErrInvalidKey
	}
	return a, nil
}

// ParseAny decodes an address for whichever network its prefix belongs to.
func ParseAny(s string) (Address, error) {
	var lastErr error = ErrWrongNetwork
	for _, net := range protocol.Networks {
		a, err := Parse(s, net)
		if err == nil {
			return a, nil
		}
		if !errors.Is(err, ErrWrongNetwork) {
			return Address{}, err
		}
		lastErr = err
	}
	return Address{}, lastErr
}

// validKey is the per-key check in check_address: a decodable point that is not the
// identity and is in the prime-order subgroup.
//
// Ported from monero src/cryptonote_basic/cryptonote_basic_impl.cpp: check_address.
func validKey(k keys.PublicKey) bool {
	p, err := primitives.DecodePoint(k)
	if err != nil {
		return false
	}
	return !primitives.IsIdentity(p) && primitives.IsInMainSubgroup(p)
}

// FromAccount returns the address of subaddress idx; (0, 0) is the standard
// primary address.
//
// Ported from monero src/device/device_default.cpp: get_subaddress.
func FromAccount(net protocol.Network, acct keys.AccountKeys, idx keys.SubaddressIndex) (Address, error) {
	spend, view, err := acct.SubaddressPublicKeys(idx)
	if err != nil {
		return Address{}, err
	}
	kind := Subaddress
	if idx.IsZero() {
		kind = Standard
	}
	return Address{Network: net, Kind: kind, Spend: spend, View: view}, nil
}

// WithPaymentID returns the integrated address for a standard address and an
// 8-byte payment ID. Subaddresses cannot be integrated.
func (a Address) WithPaymentID(pid [8]byte) (Address, error) {
	if a.Kind != Standard {
		return Address{}, fmt.Errorf("address: cannot integrate a %s address", a.Kind)
	}
	a.Kind = Integrated
	a.PaymentID = pid
	return a, nil
}
