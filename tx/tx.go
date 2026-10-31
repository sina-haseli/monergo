// Copyright (c) 2014-2026, The Monero Project
// Copyright (c) 2026, The monergo Authors
// SPDX-License-Identifier: BSD-3-Clause

// Package tx implements Monero transaction types, their exact binary
// (de)serialization, and the prefix, transaction and signature hashes.
//
// Ported from monero @3fd0f88c20f559839cafb20911cb13cb45eba7bd:
// src/cryptonote_basic/cryptonote_basic.h (transaction_prefix, transaction),
// src/ringct/rctTypes.h (rctSigBase::serialize_rctsig_base,
// rctSigPrunable::serialize_rctsig_prunable), and
// src/cryptonote_basic/cryptonote_format_utils.cpp (calculate_transaction_hash).
//
// Only version 2 transactions with RCT type Null (coinbase), CLSAG (5) or
// BulletproofPlus (6) are supported. Everything else is rejected with
// ErrUnsupported.
package tx

import (
	"errors"
	"fmt"

	"github.com/sina-haseli/monergo/primitives"
	"github.com/sina-haseli/monergo/ringct"
)

var (
	// ErrTruncated is returned when the input ends early.
	ErrTruncated = errors.New("tx: truncated")
	// ErrMalformed is returned for data upstream's deserializer rejects.
	ErrMalformed = errors.New("tx: malformed")
	// ErrUnsupported is returned for valid but unsupported formats (v1, old RCT types).
	ErrUnsupported = errors.New("tx: unsupported transaction format")
)

// Consensus ceilings from cryptonote_basic.h and cryptonote_config.h.
const (
	currentTransactionVersion = 2       // CURRENT_TRANSACTION_VERSION
	maxTxSize                 = 1000000 // CRYPTONOTE_MAX_TX_SIZE
	maxVinCount               = maxTxSize / 32
	maxNonCoinbaseVoutCount   = maxTxSize / 32
	maxCoinbaseVoutCount      = 100000000 / 32
	maxTotalKeyOffsets        = maxTxSize / 32
)

// Variant tags (cryptonote_basic.h VARIANT_TAG for binary_archive).
const (
	tagTxinGen          = 0xff
	tagTxinToKey        = 0x02
	tagTxoutToKey       = 0x02
	tagTxoutToTaggedKey = 0x03
)

// Input is either a coinbase input (Gen) or a key input.
type Input struct {
	Gen    bool
	Height uint64 // txin_gen

	Amount     uint64 // txin_to_key
	KeyOffsets []uint64
	KeyImage   [32]byte
}

// AbsoluteOffsets converts the relative key offsets to global output indices.
//
// Ported from monero src/cryptonote_basic/cryptonote_format_utils.cpp:
// relative_output_offsets_to_absolute.
func (in Input) AbsoluteOffsets() []uint64 {
	out := make([]uint64, len(in.KeyOffsets))
	var acc uint64
	for i, o := range in.KeyOffsets {
		acc += o
		out[i] = acc
	}
	return out
}

// Output is a txout_to_key or, with HasViewTag, a txout_to_tagged_key.
type Output struct {
	Amount     uint64
	Key        [32]byte
	HasViewTag bool
	ViewTag    byte
}

// RCT holds rct_signatures: the base (type, fee, ecdhInfo, outPk) and the
// prunable part (range proofs, CLSAGs, pseudo outputs).
type RCT struct {
	Type uint8
	Fee  uint64
	// EcdhAmounts are the 8-byte encrypted amounts (compressed ecdhInfo, v2 ECDH).
	EcdhAmounts [][8]byte
	// OutPk are the output commitments (outPk[i].mask).
	OutPk [][32]byte

	BulletproofsPlus []ringct.BulletproofPlus // type 6
	Bulletproofs     []ringct.Bulletproof     // type 5
	CLSAGs           []ringct.CLSAG
	PseudoOuts       [][32]byte
}

// Transaction is a version 2 Monero transaction.
type Transaction struct {
	Version    uint64
	UnlockTime uint64
	Inputs     []Input
	Outputs    []Output
	Extra      []byte
	RCT        RCT
}

// IsCoinbase reports whether the transaction has exactly one txin_gen input.
//
// Ported from monero src/cryptonote_basic/cryptonote_basic.h:
// transaction_prefix::is_coinbase.
func (t *Transaction) IsCoinbase() bool {
	return len(t.Inputs) == 1 && t.Inputs[0].Gen
}

// mixin returns key_offsets.size() - 1 of the first input, as upstream passes to
// serialize_rctsig_prunable.
func (t *Transaction) mixin() (int, error) {
	if len(t.Inputs) == 0 || t.Inputs[0].Gen {
		return 0, nil
	}
	n := len(t.Inputs[0].KeyOffsets)
	if n == 0 {
		return 0, ErrMalformed // upstream: size_t underflow, then mixin >= 0xffffffff fails
	}
	return n - 1, nil
}

// Parse decodes a full (unpruned) transaction blob. The whole input must be
// consumed, as in parse_and_validate_tx_from_blob.
func Parse(b []byte) (*Transaction, error) {
	r := &reader{b: b}
	t := &Transaction{}
	if err := t.readPrefix(r); err != nil {
		return nil, err
	}
	if err := t.readRCT(r); err != nil {
		return nil, err
	}
	if r.remaining() != 0 {
		return nil, fmt.Errorf("%w: %d trailing bytes", ErrMalformed, r.remaining())
	}
	return t, nil
}

// readPrefix ports transaction_prefix::serialize (loading) with deserialize_vin.
func (t *Transaction) readPrefix(r *reader) error {
	var err error
	if t.Version, err = r.varint(); err != nil {
		return err
	}
	if t.Version == 0 || t.Version > currentTransactionVersion {
		return fmt.Errorf("%w: version %d", ErrMalformed, t.Version)
	}
	if t.Version != 2 {
		return fmt.Errorf("%w: version %d", ErrUnsupported, t.Version)
	}
	if t.UnlockTime, err = r.varint(); err != nil {
		return err
	}

	// vin (deserialize_vin)
	nIn, err := r.count(1)
	if err != nil {
		return err
	}
	if nIn > maxVinCount {
		return fmt.Errorf("%w: too many inputs", ErrMalformed)
	}
	t.Inputs = make([]Input, 0, nIn)
	totalOffsets := 0
	for i := 0; i < nIn; i++ {
		tag, err := r.byte()
		if err != nil {
			return err
		}
		switch tag {
		case tagTxinGen:
			h, err := r.varint()
			if err != nil {
				return err
			}
			t.Inputs = append(t.Inputs, Input{Gen: true, Height: h})
			if i == 0 {
				if nIn > 1 {
					return fmt.Errorf("%w: coinbase with several inputs", ErrMalformed)
				}
				continue
			}
			return fmt.Errorf("%w: txin_gen after the first input", ErrMalformed)
		case tagTxinToKey:
			in := Input{}
			if in.Amount, err = r.varint(); err != nil {
				return err
			}
			n, err := r.count(1)
			if err != nil {
				return err
			}
			if n >= maxTotalKeyOffsets {
				return fmt.Errorf("%w: too many key offsets", ErrMalformed)
			}
			in.KeyOffsets = make([]uint64, n)
			for j := range in.KeyOffsets {
				if in.KeyOffsets[j], err = r.varint(); err != nil {
					return err
				}
			}
			if in.KeyImage, err = r.key(); err != nil {
				return err
			}
			totalOffsets += n
			if totalOffsets >= maxTotalKeyOffsets {
				return fmt.Errorf("%w: too many key offsets", ErrMalformed)
			}
			t.Inputs = append(t.Inputs, in)
		case 0x00, 0x01:
			return fmt.Errorf("%w: script inputs", ErrMalformed)
		default:
			return fmt.Errorf("%w: input tag %#x", ErrMalformed, tag)
		}
	}

	// vout
	maxVout := maxNonCoinbaseVoutCount
	if t.IsCoinbase() || len(t.Inputs) == 0 {
		maxVout = maxCoinbaseVoutCount
	}
	nOut, err := r.count(1 + 1 + 32)
	if err != nil {
		return err
	}
	if nOut > maxVout {
		return fmt.Errorf("%w: too many outputs", ErrMalformed)
	}
	t.Outputs = make([]Output, nOut)
	for i := range t.Outputs {
		o := &t.Outputs[i]
		if o.Amount, err = r.varint(); err != nil {
			return err
		}
		tag, err := r.byte()
		if err != nil {
			return err
		}
		switch tag {
		case tagTxoutToKey:
			if o.Key, err = r.key(); err != nil {
				return err
			}
		case tagTxoutToTaggedKey:
			if o.Key, err = r.key(); err != nil {
				return err
			}
			if o.ViewTag, err = r.byte(); err != nil {
				return err
			}
			o.HasViewTag = true
		case 0x00, 0x01:
			return fmt.Errorf("%w: script outputs", ErrUnsupported)
		default:
			return fmt.Errorf("%w: output tag %#x", ErrMalformed, tag)
		}
	}

	// extra
	n, err := r.count(1)
	if err != nil {
		return err
	}
	t.Extra, err = r.bytes(n)
	return err
}

// readRCT ports the version 2 branch of transaction::serialize (loading).
func (t *Transaction) readRCT(r *reader) error {
	if len(t.Inputs) == 0 {
		return nil
	}
	// serialize_rctsig_base
	var err error
	if t.RCT.Type, err = r.byte(); err != nil {
		return err
	}
	switch t.RCT.Type {
	case ringct.TypeNull:
		return nil
	case ringct.TypeCLSAG, ringct.TypeBulletproofPlus:
	case ringct.TypeFull, ringct.TypeSimple, ringct.TypeBulletproof, ringct.TypeBulletproof2:
		return fmt.Errorf("%w: rct type %d", ErrUnsupported, t.RCT.Type)
	default:
		return fmt.Errorf("%w: rct type %d", ErrMalformed, t.RCT.Type)
	}
	if t.IsCoinbase() {
		return fmt.Errorf("%w: coinbase with rct type %d", ErrUnsupported, t.RCT.Type)
	}
	if t.RCT.Fee, err = r.varint(); err != nil {
		return err
	}
	outputs := len(t.Outputs)
	if outputs > r.remaining()/(8+32) {
		return ErrTruncated
	}
	t.RCT.EcdhAmounts = make([][8]byte, outputs)
	for i := range t.RCT.EcdhAmounts {
		b, err := r.bytes(8)
		if err != nil {
			return err
		}
		copy(t.RCT.EcdhAmounts[i][:], b)
	}
	if t.RCT.OutPk, err = r.keys(outputs); err != nil {
		return err
	}

	// serialize_rctsig_prunable
	mixin, err := t.mixin()
	if err != nil {
		return err
	}
	inputs := len(t.Inputs)
	if inputs >= 0xffffffff || outputs >= 0xffffffff || mixin >= 0xffffffff {
		return ErrMalformed
	}
	nbp, err := r.varint()
	if err != nil {
		return err
	}
	if nbp > uint64(outputs) || nbp > 0xffffffff {
		return fmt.Errorf("%w: too many range proofs", ErrMalformed)
	}
	maxAmounts := 0
	if t.RCT.Type == ringct.TypeBulletproofPlus {
		if int(nbp) > r.remaining()/(32*6) {
			return ErrTruncated
		}
		t.RCT.BulletproofsPlus = make([]ringct.BulletproofPlus, nbp)
		for i := range t.RCT.BulletproofsPlus {
			p := &t.RCT.BulletproofsPlus[i]
			for _, k := range []*[32]byte{&p.A, &p.A1, &p.B, &p.R1, &p.S1, &p.D1} {
				if *k, err = r.key(); err != nil {
					return err
				}
			}
			if p.L, err = r.keyVector(); err != nil {
				return err
			}
			if p.R, err = r.keyVector(); err != nil {
				return err
			}
			if len(p.L) == 0 || len(p.L) != len(p.R) {
				return fmt.Errorf("%w: bad BP+ L/R", ErrMalformed)
			}
			m := ringct.MaxAmountsBase(len(p.L), len(p.R))
			if m == 0 {
				return fmt.Errorf("%w: bad BP+ L/R", ErrMalformed)
			}
			maxAmounts += m
		}
	} else { // TypeCLSAG: original Bulletproofs, VARINT nbp
		if int(nbp) > r.remaining()/(32*9) {
			return ErrTruncated
		}
		t.RCT.Bulletproofs = make([]ringct.Bulletproof, nbp)
		for i := range t.RCT.Bulletproofs {
			p := &t.RCT.Bulletproofs[i]
			for _, k := range []*[32]byte{&p.A, &p.S, &p.T1, &p.T2, &p.Taux, &p.Mu} {
				if *k, err = r.key(); err != nil {
					return err
				}
			}
			if p.L, err = r.keyVector(); err != nil {
				return err
			}
			if p.R, err = r.keyVector(); err != nil {
				return err
			}
			for _, k := range []*[32]byte{&p.Aa, &p.B, &p.T} {
				if *k, err = r.key(); err != nil {
					return err
				}
			}
			if len(p.L) == 0 || len(p.L) != len(p.R) {
				return fmt.Errorf("%w: bad BP L/R", ErrMalformed)
			}
			m := ringct.MaxAmountsBase(len(p.L), len(p.R))
			if m == 0 {
				return fmt.Errorf("%w: bad BP L/R", ErrMalformed)
			}
			maxAmounts += m
		}
	}
	if maxAmounts < outputs {
		return fmt.Errorf("%w: range proofs cover too few outputs", ErrMalformed)
	}

	// CLSAGs
	if inputs > r.remaining()/(32*3) || mixin+1 > r.remaining()/32 {
		return ErrTruncated
	}
	t.RCT.CLSAGs = make([]ringct.CLSAG, inputs)
	for i := range t.RCT.CLSAGs {
		c := &t.RCT.CLSAGs[i]
		if c.S, err = r.keys(mixin + 1); err != nil {
			return err
		}
		if c.C1, err = r.key(); err != nil {
			return err
		}
		if c.D, err = r.key(); err != nil {
			return err
		}
	}
	t.RCT.PseudoOuts, err = r.keys(inputs)
	return err
}

// Serialize encodes the transaction exactly as upstream's binary_archive<true>.
func (t *Transaction) Serialize() ([]byte, error) {
	prefix, base, prunable, err := t.parts()
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(prefix)+len(base)+len(prunable))
	out = append(out, prefix...)
	out = append(out, base...)
	return append(out, prunable...), nil
}

// SerializePrefix encodes the transaction prefix.
func (t *Transaction) SerializePrefix() []byte {
	w := &writer{}
	w.varint(t.Version)
	w.varint(t.UnlockTime)
	w.varint(uint64(len(t.Inputs)))
	for _, in := range t.Inputs {
		if in.Gen {
			w.byte(tagTxinGen)
			w.varint(in.Height)
			continue
		}
		w.byte(tagTxinToKey)
		w.varint(in.Amount)
		w.varint(uint64(len(in.KeyOffsets)))
		for _, o := range in.KeyOffsets {
			w.varint(o)
		}
		w.key(in.KeyImage)
	}
	w.varint(uint64(len(t.Outputs)))
	for _, o := range t.Outputs {
		w.varint(o.Amount)
		if o.HasViewTag {
			w.byte(tagTxoutToTaggedKey)
			w.key(o.Key)
			w.byte(o.ViewTag)
		} else {
			w.byte(tagTxoutToKey)
			w.key(o.Key)
		}
	}
	w.varint(uint64(len(t.Extra)))
	w.bytes(t.Extra)
	return w.b
}

// serializeBase ports rctSigBase::serialize_rctsig_base (saving).
func (t *Transaction) serializeBase() ([]byte, error) {
	if len(t.Inputs) == 0 {
		return nil, nil
	}
	w := &writer{}
	w.byte(t.RCT.Type)
	switch t.RCT.Type {
	case ringct.TypeNull:
		return w.b, nil
	case ringct.TypeCLSAG, ringct.TypeBulletproofPlus:
	default:
		return nil, fmt.Errorf("%w: rct type %d", ErrUnsupported, t.RCT.Type)
	}
	if len(t.RCT.EcdhAmounts) != len(t.Outputs) || len(t.RCT.OutPk) != len(t.Outputs) {
		return nil, fmt.Errorf("%w: ecdhInfo/outPk size", ErrMalformed)
	}
	w.varint(t.RCT.Fee)
	for _, a := range t.RCT.EcdhAmounts {
		w.bytes(a[:])
	}
	w.keys(t.RCT.OutPk)
	return w.b, nil
}

// serializePrunable ports rctSigPrunable::serialize_rctsig_prunable (saving).
func (t *Transaction) serializePrunable() ([]byte, error) {
	if len(t.Inputs) == 0 || t.RCT.Type == ringct.TypeNull {
		return nil, nil
	}
	mixin, err := t.mixin()
	if err != nil {
		return nil, err
	}
	w := &writer{}
	switch t.RCT.Type {
	case ringct.TypeBulletproofPlus:
		w.varint(uint64(len(t.RCT.BulletproofsPlus)))
		for _, p := range t.RCT.BulletproofsPlus {
			if len(p.L) == 0 || len(p.L) != len(p.R) {
				return nil, fmt.Errorf("%w: bad BP+ L/R", ErrMalformed)
			}
			for _, k := range [][32]byte{p.A, p.A1, p.B, p.R1, p.S1, p.D1} {
				w.key(k)
			}
			w.keyVector(p.L)
			w.keyVector(p.R)
		}
	case ringct.TypeCLSAG:
		w.varint(uint64(len(t.RCT.Bulletproofs)))
		for _, p := range t.RCT.Bulletproofs {
			if len(p.L) == 0 || len(p.L) != len(p.R) {
				return nil, fmt.Errorf("%w: bad BP L/R", ErrMalformed)
			}
			for _, k := range [][32]byte{p.A, p.S, p.T1, p.T2, p.Taux, p.Mu} {
				w.key(k)
			}
			w.keyVector(p.L)
			w.keyVector(p.R)
			for _, k := range [][32]byte{p.Aa, p.B, p.T} {
				w.key(k)
			}
		}
	default:
		return nil, fmt.Errorf("%w: rct type %d", ErrUnsupported, t.RCT.Type)
	}
	if len(t.RCT.CLSAGs) != len(t.Inputs) || len(t.RCT.PseudoOuts) != len(t.Inputs) {
		return nil, fmt.Errorf("%w: CLSAG/pseudoOuts count", ErrMalformed)
	}
	for _, c := range t.RCT.CLSAGs {
		if len(c.S) != mixin+1 {
			return nil, fmt.Errorf("%w: CLSAG ring size", ErrMalformed)
		}
		w.keys(c.S)
		w.key(c.C1)
		w.key(c.D)
	}
	w.keys(t.RCT.PseudoOuts)
	return w.b, nil
}

func (t *Transaction) parts() (prefix, base, prunable []byte, err error) {
	if t.Version != 2 {
		return nil, nil, nil, fmt.Errorf("%w: version %d", ErrUnsupported, t.Version)
	}
	prefix = t.SerializePrefix()
	if base, err = t.serializeBase(); err != nil {
		return nil, nil, nil, err
	}
	if prunable, err = t.serializePrunable(); err != nil {
		return nil, nil, nil, err
	}
	return prefix, base, prunable, nil
}

// PrefixHash is Keccak-256 of the serialized prefix (the CLSAG "message").
//
// Ported from monero src/cryptonote_basic/cryptonote_format_utils.cpp:
// get_transaction_prefix_hash.
func (t *Transaction) PrefixHash() [32]byte {
	return primitives.Keccak256(t.SerializePrefix())
}

// PrunableHash is Keccak-256 of the serialized prunable RCT data.
//
// Ported from monero src/cryptonote_basic/cryptonote_format_utils.cpp:
// calculate_transaction_prunable_hash.
func (t *Transaction) PrunableHash() ([32]byte, error) {
	_, _, prunable, err := t.parts()
	if err != nil {
		return [32]byte{}, err
	}
	return primitives.Keccak256(prunable), nil
}

// Hash is the transaction ID: Keccak(prefixHash ‖ Keccak(base) ‖ prunableHash),
// where prunableHash is all zeros for RCT type Null.
//
// Ported from monero src/cryptonote_basic/cryptonote_format_utils.cpp:
// calculate_transaction_hash (version 2).
func (t *Transaction) Hash() ([32]byte, error) {
	prefix, base, prunable, err := t.parts()
	if err != nil {
		return [32]byte{}, err
	}
	h0 := primitives.Keccak256(prefix)
	h1 := primitives.Keccak256(base)
	var h2 [32]byte
	if t.RCT.Type != ringct.TypeNull {
		h2 = primitives.Keccak256(prunable)
	}
	return primitives.Keccak256(h0[:], h1[:], h2[:]), nil
}

// SignatureHash is the message every CLSAG signs:
// Keccak(prefixHash ‖ Keccak(rctSigBase) ‖ Keccak(range proof keys)).
//
// Ported from monero src/ringct/rctSigs.cpp: get_pre_mlsag_hash (with
// device_default::mlsag_prehash). rv.message is the prefix hash.
func (t *Transaction) SignatureHash() ([32]byte, error) {
	if len(t.Inputs) == 0 || t.IsCoinbase() || t.RCT.Type == ringct.TypeNull {
		return [32]byte{}, fmt.Errorf("%w: no ring signatures to hash", ErrMalformed)
	}
	base, err := t.serializeBase()
	if err != nil {
		return [32]byte{}, err
	}
	message := t.PrefixHash()
	baseHash := primitives.Keccak256(base)
	var kv []byte
	switch t.RCT.Type {
	case ringct.TypeBulletproofPlus:
		for _, p := range t.RCT.BulletproofsPlus {
			for _, k := range [][32]byte{p.A, p.A1, p.B, p.R1, p.S1, p.D1} {
				kv = append(kv, k[:]...)
			}
			for _, k := range p.L {
				kv = append(kv, k[:]...)
			}
			for _, k := range p.R {
				kv = append(kv, k[:]...)
			}
		}
	case ringct.TypeCLSAG:
		for _, p := range t.RCT.Bulletproofs {
			for _, k := range [][32]byte{p.A, p.S, p.T1, p.T2, p.Taux, p.Mu} {
				kv = append(kv, k[:]...)
			}
			for _, k := range p.L {
				kv = append(kv, k[:]...)
			}
			for _, k := range p.R {
				kv = append(kv, k[:]...)
			}
			for _, k := range [][32]byte{p.Aa, p.B, p.T} {
				kv = append(kv, k[:]...)
			}
		}
	}
	kvHash := primitives.Keccak256(kv)
	return primitives.Keccak256(message[:], baseHash[:], kvHash[:]), nil
}
