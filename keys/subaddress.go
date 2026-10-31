// Copyright (c) 2014-2026, The Monero Project
// Copyright (c) 2026, The monergo Authors
// SPDX-License-Identifier: BSD-3-Clause

package keys

import (
	"encoding/binary"

	"filippo.io/edwards25519"
	"github.com/sina-haseli/monergo/primitives"
)

// AccountKeys holds a wallet's private spend and view keys. Call Wipe when done.
type AccountKeys struct {
	Spend SecretKey
	View  SecretKey
}

// Wipe zeroes both secret keys.
func (a *AccountKeys) Wipe() {
	a.Spend.Wipe()
	a.View.Wipe()
}

// SubaddressIndex is a (major, minor) = (account, address) index. (0, 0) is the
// primary address.
type SubaddressIndex struct {
	Major uint32 `json:"major"`
	Minor uint32 `json:"minor"`
}

// IsZero reports whether i is the primary address index.
func (i SubaddressIndex) IsZero() bool { return i.Major == 0 && i.Minor == 0 }

// hashKeySubaddress is config::HASH_KEY_SUBADDRESS including its null terminator
// (upstream copies sizeof("SubAddr") = 8 bytes).
const hashKeySubaddress = "SubAddr\x00"

// SubaddressSecretKey returns m = Hs("SubAddr\0" ‖ view ‖ le32(major) ‖ le32(minor)).
//
// Ported from monero src/device/device_default.cpp: get_subaddress_secret_key.
func SubaddressSecretKey(view SecretKey, idx SubaddressIndex) SecretKey {
	buf := make([]byte, 0, len(hashKeySubaddress)+32+8)
	buf = append(buf, hashKeySubaddress...)
	buf = append(buf, view[:]...)
	buf = binary.LittleEndian.AppendUint32(buf, idx.Major)
	buf = binary.LittleEndian.AppendUint32(buf, idx.Minor)
	m := primitives.HashToScalar(buf)
	clear(buf)
	out := SecretKey(m.Bytes())
	primitives.WipeScalar(m)
	return out
}

// SubaddressPublicKeys returns the (spend D, view C) public keys of subaddress idx:
// D = B + m·G and C = a·D; index (0, 0) returns the primary keys (B, A).
//
// Ported from monero src/device/device_default.cpp: get_subaddress_spend_public_key
// and get_subaddress.
func (a AccountKeys) SubaddressPublicKeys(idx SubaddressIndex) (spend, view PublicKey, err error) {
	B, err := a.Spend.PublicKey()
	if err != nil {
		return PublicKey{}, PublicKey{}, err
	}
	if idx.IsZero() {
		A, err := a.View.PublicKey()
		return B, A, err
	}
	D, err := SubaddressSpendPublicKey(B, a.View, idx)
	if err != nil {
		return PublicKey{}, PublicKey{}, err
	}
	viewScalar, err := a.View.scalar()
	if err != nil {
		return PublicKey{}, PublicKey{}, err
	}
	defer primitives.WipeScalar(viewScalar)
	dPt, err := D.point()
	if err != nil {
		return PublicKey{}, PublicKey{}, err
	}
	C := new(edwards25519.Point).ScalarMult(viewScalar, dPt)
	return D, PublicKey(C.Bytes()), nil
}

// SubaddressSpendPublicKey returns D = B + m·G for idx, or B for (0, 0).
//
// Ported from monero src/device/device_default.cpp: get_subaddress_spend_public_key.
func SubaddressSpendPublicKey(spendPub PublicKey, view SecretKey, idx SubaddressIndex) (PublicKey, error) {
	if idx.IsZero() {
		return spendPub, nil
	}
	B, err := spendPub.point()
	if err != nil {
		return PublicKey{}, err
	}
	m := SubaddressSecretKey(view, idx)
	defer m.Wipe()
	mScalar, err := m.scalar()
	if err != nil {
		return PublicKey{}, err
	}
	defer primitives.WipeScalar(mScalar)
	M := new(edwards25519.Point).ScalarBaseMult(mScalar)
	return PublicKey(M.Add(B, M).Bytes()), nil
}

// SubaddressSpendSecretKey returns b + m, the private spend key of subaddress idx
// (b for (0, 0)), so that its public key is D. Spending code should use
// OneTimeSecretKey, which follows upstream's order of operations.
func (a AccountKeys) SubaddressSpendSecretKey(idx SubaddressIndex) (SecretKey, error) {
	b, err := a.Spend.scalar()
	if err != nil {
		return SecretKey{}, err
	}
	defer primitives.WipeScalar(b)
	if idx.IsZero() {
		return SecretKey(b.Bytes()), nil
	}
	m := SubaddressSecretKey(a.View, idx)
	defer m.Wipe()
	mScalar, err := m.scalar()
	if err != nil {
		return SecretKey{}, err
	}
	defer primitives.WipeScalar(mScalar)
	mScalar.Add(b, mScalar)
	return SecretKey(mScalar.Bytes()), nil
}

// OneTimeSecretKey returns the private key of an output received at subaddress idx:
// (Hs(d ‖ outputIndex) + b) + m, with m omitted for (0, 0).
//
// Ported from monero src/cryptonote_basic/cryptonote_format_utils.cpp:
// generate_key_image_helper_precomp (non-multisig path, steps 1 and 2).
func (a AccountKeys) OneTimeSecretKey(d KeyDerivation, outputIndex uint64, idx SubaddressIndex) (SecretKey, error) {
	step1, err := DeriveSecretKey(d, outputIndex, a.Spend)
	if err != nil {
		return SecretKey{}, err
	}
	if idx.IsZero() {
		return step1, nil
	}
	defer step1.Wipe()
	s1, err := step1.scalar()
	if err != nil {
		return SecretKey{}, err
	}
	defer primitives.WipeScalar(s1)
	m := SubaddressSecretKey(a.View, idx)
	defer m.Wipe()
	mScalar, err := m.scalar()
	if err != nil {
		return SecretKey{}, err
	}
	defer primitives.WipeScalar(mScalar)
	mScalar.Add(s1, mScalar)
	return SecretKey(mScalar.Bytes()), nil
}

// AccountFromRecoveryKey derives the account keys from a 32-byte recovery key (the
// value a 25-word seed encodes): spend = sc_reduce32(key), view =
// sc_reduce32(Keccak256(spend)).
//
// Ported from monero src/cryptonote_basic/account.cpp: account_base::generate
// (recover = true, two_random = false) with crypto_ops::generate_keys.
func AccountFromRecoveryKey(recovery [32]byte) AccountKeys {
	spend := primitives.ScReduce32(recovery)
	second := primitives.Keccak256(spend[:])
	view := primitives.ScReduce32(second)
	clear(second[:])
	return AccountKeys{Spend: SecretKey(spend), View: SecretKey(view)}
}
