// Copyright (c) 2014-2026, The Monero Project
// Copyright (c) 2026, The monergo Authors
// SPDX-License-Identifier: BSD-3-Clause

// Package builder turns a TransferRequest into a signed transaction, without any
// network access.
//
// The construction is a port of monero @3fd0f88c20f559839cafb20911cb13cb45eba7bd:
// src/wallet/wallet2.cpp (transfer_selected_rct: change and dummy outputs, fee
// from weight), src/cryptonote_core/cryptonote_tx_utils.cpp
// (construct_tx_and_get_tx_key, construct_tx_with_tx_key) and
// src/ringct/rctSigs.cpp (genRctSimple). Every signed transaction is verified
// with package verify before it is returned.
package builder

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"sort"

	"filippo.io/edwards25519"
	"github.com/sina-haseli/monergo/address"
	"github.com/sina-haseli/monergo/keys"
	"github.com/sina-haseli/monergo/primitives"
	"github.com/sina-haseli/monergo/protocol"
	"github.com/sina-haseli/monergo/ringct"
	"github.com/sina-haseli/monergo/ringct/bpplus"
	"github.com/sina-haseli/monergo/ringct/clsag"
	"github.com/sina-haseli/monergo/scan"
	"github.com/sina-haseli/monergo/tx"
	"github.com/sina-haseli/monergo/verify"
)

var (
	// ErrInvalidRequest is returned for malformed or unsupported requests.
	ErrInvalidRequest = errors.New("builder: invalid request")
	// ErrInputNotOwned is returned when an input does not belong to the keys, or
	// its amount or ring does not match the output.
	ErrInputNotOwned = errors.New("builder: input does not match the keys")
	// ErrInsufficientFunds is returned when inputs do not cover outputs plus fee.
	ErrInsufficientFunds = errors.New("builder: insufficient funds")
	// ErrFeeTooHigh is returned when the required fee exceeds MaxFee.
	ErrFeeTooHigh = errors.New("builder: fee exceeds max_fee")
)

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidRequest, fmt.Sprintf(format, args...))
}

// hashKeyEncryptedPaymentID is config::HASH_KEY_ENCRYPTED_PAYMENT_ID.
const hashKeyEncryptedPaymentID = 0x8d

// Sign builds and signs the transfer, returning the transaction hex and hash.
func Sign(k PrivateKeys, req TransferRequest) (txHex string, txHash string, err error) {
	s, err := SignWithRand(rand.Reader, k, req)
	if err != nil {
		return "", "", err
	}
	defer s.Wipe()
	return s.TxHex, s.TxHash, nil
}

// pubPair is an account_public_address.
type pubPair struct {
	spend, view keys.PublicKey
}

type destination struct {
	addr     pubPair
	amount   uint64
	isSub    bool
	isChange bool
}

type source struct {
	in     Input
	opened scan.Opened
	mask   *edwards25519.Scalar
	ring   []clsag.Member
	offs   []uint64
}

type build struct {
	rng       io.Reader
	acct      keys.AccountKeys
	req       TransferRequest
	rules     protocol.Rules
	signer    InputSigner
	sources   []source // sorted by key image, descending
	dests     []destination
	sumIn     uint64
	sumOut    uint64
	pid       *[8]byte // payment ID of an integrated destination
	change    pubPair
	changeSub bool
	dummy     *pubPair
	txKey     *edwards25519.Scalar
	addKeys   []*edwards25519.Scalar // one per possible output
}

// SignWithRand is Sign with an explicit randomness source and full result. A
// nil rng means crypto/rand.
func SignWithRand(rng io.Reader, k PrivateKeys, req TransferRequest) (*Signed, error) {
	if rng == nil {
		rng = rand.Reader
	}
	b := &build{rng: rng, acct: k, req: req}
	defer b.wipe()
	if err := b.validate(); err != nil {
		return nil, err
	}
	return b.run()
}

func (b *build) wipe() {
	for i := range b.sources {
		b.sources[i].opened.Wipe()
		primitives.WipeScalar(b.sources[i].mask)
	}
	primitives.WipeScalar(b.txKey)
	for _, k := range b.addKeys {
		primitives.WipeScalar(k)
	}
}

func (b *build) validate() error {
	hf := b.req.HardFork
	if hf == 0 {
		hf = protocol.CurrentHardFork
	}
	rules, err := protocol.RulesFor(hf)
	if err != nil {
		return invalid("%v", err)
	}
	b.rules = rules
	signer, ok := signerFor(rules.RCTType)
	if !ok {
		return invalid("no signer for rct type %d", rules.RCTType)
	}
	b.signer = signer
	if len(b.req.Inputs) == 0 {
		return invalid("no inputs")
	}
	if len(b.req.Destinations) == 0 {
		return invalid("no destinations")
	}
	if b.req.FeePerByte == 0 || b.req.FeeQuantizationMask == 0 || b.req.MaxFee == 0 {
		return invalid("fee_per_byte, fee_quantization_mask and max_fee are required")
	}
	if _, err := b.acct.Spend.PublicKey(); err != nil {
		return invalid("spend key: %v", err)
	}
	if _, err := b.acct.View.PublicKey(); err != nil {
		return invalid("view key: %v", err)
	}
	if err := b.validateDestinations(); err != nil {
		return err
	}
	return b.validateInputs()
}

func (b *build) validateDestinations() error {
	for i, d := range b.req.Destinations {
		a, err := address.Parse(d.Address, b.req.Network)
		if err != nil {
			return invalid("destination %d: %v", i, err)
		}
		if d.Amount == 0 {
			return invalid("destination %d: zero amount", i) // wallet2: error::zero_amount
		}
		if b.sumOut+d.Amount < b.sumOut {
			return invalid("destination amounts overflow")
		}
		b.sumOut += d.Amount
		if a.Kind == address.Integrated {
			if b.pid != nil && *b.pid != a.PaymentID {
				return invalid("a single payment ID is allowed per transaction")
			}
			pid := a.PaymentID
			b.pid = &pid
		}
		b.dests = append(b.dests, destination{
			addr:   pubPair{a.Spend, a.View},
			amount: d.Amount,
			isSub:  a.Kind == address.Subaddress,
		})
	}
	return nil
}

func (b *build) validateInputs() error {
	spendPub, _ := b.acct.Spend.PublicKey()
	seen := map[keys.KeyImage]bool{}
	major := b.req.Inputs[0].Subaddress.Major
	for i, in := range b.req.Inputs {
		if in.Subaddress.Major != major {
			// wallet2::transfer_selected_rct: "the tx uses funds from multiple accounts"
			return invalid("input %d: inputs from several accounts", i)
		}
		if len(in.Ring) != b.rules.RingSize {
			return invalid("input %d: ring size %d, want %d", i, len(in.Ring), b.rules.RingSize)
		}
		if in.RealIndex < 0 || in.RealIndex >= len(in.Ring) {
			return invalid("input %d: real_index out of range", i)
		}
		src := source{in: in}
		var prev uint64
		for j, m := range in.Ring {
			if j > 0 && m.GlobalIndex <= prev {
				return invalid("input %d: ring not strictly increasing by global index", i)
			}
			off := m.GlobalIndex
			if j > 0 {
				off = m.GlobalIndex - prev
			}
			prev = m.GlobalIndex
			src.offs = append(src.offs, off)
			if !primitives.CheckKey(m.Key) || !primitives.CheckKey(m.Commitment) {
				return invalid("input %d: ring member %d is not a valid point", i, j)
			}
			src.ring = append(src.ring, clsag.Member{Dest: m.Key, Mask: m.Commitment})
		}
		real := in.Ring[in.RealIndex]
		if real.Key != in.OutputKey {
			return fmt.Errorf("%w: input %d: ring[real_index] is not the output key", ErrInputNotOwned, i)
		}
		// Recompute the one-time key from our keys (generate_key_image_helper).
		D, err := keys.SubaddressSpendPublicKey(spendPub, b.acct.View, in.Subaddress)
		if err != nil {
			return err
		}
		opened, err := scan.Open(b.acct, scan.SubaddressTable{D: in.Subaddress}, scan.Output{
			TxPubKey:            in.TxPubKey,
			AdditionalTxPubKeys: in.AdditionalTxPubKeys,
			OutputIndex:         in.OutputIndex,
			OutputKey:           in.OutputKey,
		})
		if err != nil {
			return fmt.Errorf("%w: input %d: %v", ErrInputNotOwned, i, err)
		}
		src.opened = opened
		// Recompute the commitment and compare with the ring member's.
		var want ringct.Key
		if in.Coinbase {
			src.mask = scalarOne()
			want = ringct.ZeroCommit(in.Amount)
		} else {
			src.mask = opened.Mask()
			want = ringct.Key(ringct.Commit(in.Amount, src.mask).Bytes())
		}
		if want != real.Commitment {
			return fmt.Errorf("%w: input %d: amount and mask do not open the commitment", ErrInputNotOwned, i)
		}
		if seen[opened.KeyImage] {
			return invalid("input %d: duplicate key image", i)
		}
		seen[opened.KeyImage] = true
		if b.sumIn+in.Amount < b.sumIn {
			return invalid("input amounts overflow")
		}
		b.sumIn += in.Amount
		b.sources = append(b.sources, src)
	}
	// Change address: the requested subaddress, or (account, 0).
	idx := keys.SubaddressIndex{Major: major}
	if b.req.ChangeSubaddress != nil {
		idx = *b.req.ChangeSubaddress
	}
	cs, cv, err := b.acct.SubaddressPublicKeys(idx)
	if err != nil {
		return err
	}
	b.change, b.changeSub = pubPair{cs, cv}, !idx.IsZero()
	// construct_tx_with_tx_key: sort ins by their key image, descending memcmp.
	sort.SliceStable(b.sources, func(x, y int) bool {
		return bytes.Compare(b.sources[x].opened.KeyImage[:], b.sources[y].opened.KeyImage[:]) > 0
	})
	return nil
}

func scalarOne() *edwards25519.Scalar { return ringct.AmountScalar(1) }

func (b *build) randScalar() (*edwards25519.Scalar, error) { return primitives.RandomScalar(b.rng) }

// feeFromWeight ports wallet2's calculate_fee_from_weight.
func feeFromWeight(baseFee, weight, mask uint64) (uint64, error) {
	if baseFee != 0 && weight > math.MaxUint64/baseFee {
		return 0, invalid("fee calculation overflow")
	}
	fee := weight * baseFee
	if fee > math.MaxUint64-(mask-1) {
		return 0, invalid("fee calculation overflow")
	}
	return (fee + mask - 1) / mask * mask, nil
}

func (b *build) run() (*Signed, error) {
	var err error
	if b.txKey, err = b.randScalar(); err != nil {
		return nil, err
	}
	// Additional tx keys are drawn up front (keypair::generate per destination).
	for i := 0; i < protocol.MaxOutputs; i++ {
		k, err := b.randScalar()
		if err != nil {
			return nil, err
		}
		b.addKeys = append(b.addKeys, k)
	}

	// wallet2 builds with an estimated fee, then rebuilds while the fee the actual
	// weight needs exceeds the fee used. The proofs have a fixed size, so the
	// weight is computed on a draft with placeholder proofs and the proofs are
	// made once, at the end.
	var fee uint64
	var d *draft
	var weight uint64
	for iter := 0; ; iter++ {
		if iter > 8 {
			return nil, errors.New("builder: fee did not converge")
		}
		if d, err = b.draft(fee); err != nil {
			return nil, err
		}
		w, err := d.estimateWeight()
		if err != nil {
			return nil, err
		}
		weight = w
		need, err := feeFromWeight(b.req.FeePerByte, w, b.req.FeeQuantizationMask)
		if err != nil {
			return nil, err
		}
		if need <= fee {
			break
		}
		fee = need
	}
	if fee > b.req.MaxFee {
		return nil, fmt.Errorf("%w: need %d, max %d", ErrFeeTooHigh, fee, b.req.MaxFee)
	}
	// Reject an over-weight transaction before spending time on proofs.
	if weight >= protocol.MaxTxWeight {
		return nil, invalid("transaction weight %d exceeds %d", weight, protocol.MaxTxWeight)
	}
	if err := d.prove(b); err != nil {
		return nil, err
	}
	return b.finish(d)
}

// plan ports the change handling of wallet2::transfer_selected_rct.
func (b *build) plan(fee uint64) (dsts []destination, changeAddr *pubPair, change uint64, err error) {
	needed := b.sumOut + fee
	if needed < fee {
		return nil, nil, 0, invalid("amounts overflow")
	}
	if b.sumIn < needed {
		return nil, nil, 0, fmt.Errorf("%w: have %d, need %d", ErrInsufficientFunds, b.sumIn, needed)
	}
	change = b.sumIn - needed
	dsts = append([]destination{}, b.dests...)
	if change == 0 {
		if len(dsts) == 1 {
			// "If the change is 0, send it to a random address, to avoid confusing
			// the sender with a 0 amount output."
			if b.dummy == nil {
				s, err := b.randScalar()
				if err != nil {
					return nil, nil, 0, err
				}
				dummy := keys.AccountFromRecoveryKey([32]byte(s.Bytes()))
				ds, _ := dummy.Spend.PublicKey()
				dv, _ := dummy.View.PublicKey()
				dummy.Wipe()
				b.dummy = &pubPair{ds, dv}
			}
			dsts = append(dsts, destination{addr: *b.dummy, isChange: true})
			changeAddr = b.dummy
		}
	} else {
		dsts = append(dsts, destination{addr: b.change, amount: change, isSub: b.changeSub, isChange: true})
		changeAddr = &b.change
	}
	if len(dsts) > protocol.MaxOutputs {
		return nil, nil, 0, invalid("%d outputs, max %d", len(dsts), protocol.MaxOutputs)
	}
	if len(dsts) < b.rules.MinOutputs {
		return nil, nil, 0, invalid("fewer than %d outputs", b.rules.MinOutputs)
	}
	return dsts, changeAddr, change, nil
}

type draft struct {
	t          *tx.Transaction
	fee        uint64
	change     uint64
	outAmounts []uint64
	amountKeys []ringct.Key
	addKeys    []*edwards25519.Scalar // additional tx keys used, in output order
}

// classify ports classify_addresses.
func classify(dsts []destination, changeAddr *pubPair) (numStd, numSub int, single pubPair) {
	seen := map[pubPair]bool{}
	for _, d := range dsts {
		if changeAddr != nil && d.addr == *changeAddr {
			continue
		}
		if seen[d.addr] {
			continue
		}
		seen[d.addr] = true
		if d.isSub {
			numSub++
			single = d.addr
		} else {
			numStd++
		}
	}
	return
}

// destinationViewKey ports get_destination_view_key_pub; ok is false for null_pkey.
func destinationViewKey(dsts []destination, changeAddr *pubPair) (keys.PublicKey, bool) {
	var addr pubPair
	have := false
	for _, d := range dsts {
		if d.amount == 0 {
			continue
		}
		if changeAddr != nil && d.addr == *changeAddr {
			continue
		}
		if have && d.addr == addr {
			continue
		}
		if have {
			return keys.PublicKey{}, false
		}
		addr, have = d.addr, true
	}
	if !have {
		if changeAddr != nil {
			return changeAddr.view, true
		}
		return keys.PublicKey{}, false
	}
	return addr.view, true
}

func mulPoint(s *edwards25519.Scalar, p keys.PublicKey) (keys.PublicKey, error) {
	pt, err := primitives.DecodePoint(p)
	if err != nil {
		return keys.PublicKey{}, err
	}
	return keys.PublicKey(new(edwards25519.Point).ScalarMult(s, pt).Bytes()), nil
}

// encryptPaymentID ports device_default::encrypt_payment_id.
func encryptPaymentID(pid [8]byte, pub keys.PublicKey, sec keys.SecretKey) ([8]byte, error) {
	d, err := keys.GenerateKeyDerivation(pub, sec)
	if err != nil {
		return pid, err
	}
	h := primitives.Keccak256(d[:], []byte{hashKeyEncryptedPaymentID})
	for i := range pid {
		pid[i] ^= h[i]
	}
	return pid, nil
}

// shuffle is std::shuffle with a cryptographic source (Fisher-Yates).
func (b *build) shuffle(dsts []destination) error {
	for i := len(dsts) - 1; i > 0; i-- {
		j, err := rand.Int(b.rng, big.NewInt(int64(i+1)))
		if err != nil {
			return err
		}
		k := int(j.Int64())
		dsts[i], dsts[k] = dsts[k], dsts[i]
	}
	return nil
}

// draft ports construct_tx_with_tx_key up to (not including) the RingCT proofs.
func (b *build) draft(fee uint64) (*draft, error) {
	dsts, changeAddr, change, err := b.plan(fee)
	if err != nil {
		return nil, err
	}
	txKey := keys.SecretKey(b.txKey.Bytes())
	defer txKey.Wipe()

	// Payment ID nonce: encrypt a real one, or add a dummy encrypted one.
	var nonce []byte
	addDummy := b.pid == nil
	if len(dsts) > 2 {
		addDummy = false // "we don't add one if we've got more than the usual 1 destination plus change"
	}
	if b.pid != nil || addDummy {
		view, ok := destinationViewKey(dsts, changeAddr)
		switch {
		case !ok && b.pid != nil:
			return nil, invalid("destinations have to have exactly one output to support encrypted payment ids")
		case ok:
			var pid [8]byte
			if b.pid != nil {
				pid = *b.pid
			}
			enc, err := encryptPaymentID(pid, view, txKey)
			if err != nil {
				return nil, err
			}
			nonce = append([]byte{tx.ExtraNonceEncryptedPaymentID}, enc[:]...)
		}
		// !ok with a dummy: upstream logs "Failed to get key to encrypt dummy
		// payment id with" and continues without it.
	}

	t := &tx.Transaction{Version: 2, UnlockTime: 0}
	for _, s := range b.sources {
		t.Inputs = append(t.Inputs, tx.Input{Amount: 0, KeyOffsets: s.offs, KeyImage: s.opened.KeyImage})
	}

	if err := b.shuffle(dsts); err != nil {
		return nil, err
	}
	numStd, numSub, single := classify(dsts, changeAddr)
	var txPub keys.PublicKey
	if numStd == 0 && numSub == 1 {
		// "single-destination transfer to a subaddress, we set the tx pubkey to R=s*D"
		if txPub, err = mulPoint(b.txKey, single.spend); err != nil {
			return nil, err
		}
	} else {
		txPub = keys.PublicKey(new(edwards25519.Point).ScalarBaseMult(b.txKey).Bytes())
	}
	needAdditional := numSub > 0 && (numStd > 0 || numSub > 1)

	d := &draft{t: t, fee: fee, change: change}
	var additionalPubs [][32]byte
	for i, dst := range dsts {
		idx := uint64(i)
		var addPub keys.PublicKey
		var addSec keys.SecretKey
		if needAdditional {
			ak := b.addKeys[i]
			d.addKeys = append(d.addKeys, ak)
			addSec = keys.SecretKey(ak.Bytes())
			if dst.isSub {
				if addPub, err = mulPoint(ak, dst.addr.spend); err != nil {
					return nil, err
				}
			} else {
				addPub = keys.PublicKey(new(edwards25519.Point).ScalarBaseMult(ak).Bytes())
			}
			additionalPubs = append(additionalPubs, addPub)
		}
		// generate_output_ephemeral_keys
		var der keys.KeyDerivation
		if changeAddr != nil && dst.addr == *changeAddr {
			der, err = keys.GenerateKeyDerivation(txPub, b.acct.View) // change: a·R
		} else if dst.isSub && needAdditional {
			der, err = keys.GenerateKeyDerivation(dst.addr.view, addSec)
		} else {
			der, err = keys.GenerateKeyDerivation(dst.addr.view, txKey)
		}
		addSec.Wipe()
		if err != nil {
			return nil, err
		}
		ak := keys.DerivationToScalar(der, idx)
		d.amountKeys = append(d.amountKeys, ringct.Key(ak.Bytes()))
		primitives.WipeScalar(ak)
		outKey, err := keys.DerivePublicKey(der, idx, dst.addr.spend)
		if err != nil {
			return nil, err
		}
		o := tx.Output{Amount: 0, Key: outKey}
		if b.rules.ViewTags {
			o.HasViewTag = true
			o.ViewTag = byte(keys.DeriveViewTag(der, idx))
		}
		t.Outputs = append(t.Outputs, o)
		d.outAmounts = append(d.outAmounts, dst.amount)
	}

	// sort_tx_extra order: pubkey, additional pubkeys, nonce.
	fields := []tx.ExtraField{{Tag: tx.ExtraTagPubKey, PubKey: txPub}}
	if needAdditional {
		fields = append(fields, tx.ExtraField{Tag: tx.ExtraTagAdditionalPubKeys, AdditionalPubKeys: additionalPubs})
	}
	if nonce != nil {
		fields = append(fields, tx.ExtraField{Tag: tx.ExtraTagNonce, Nonce: nonce})
	}
	if t.Extra, err = tx.SerializeExtra(fields); err != nil {
		return nil, err
	}
	if len(t.Extra) > protocol.MaxTxExtraSize {
		return nil, invalid("tx extra is %d bytes, max %d", len(t.Extra), protocol.MaxTxExtraSize)
	}

	// RingCT base: fee, encrypted amounts, commitments (genRctSimple).
	t.RCT.Type = b.rules.RCTType
	t.RCT.Fee = fee
	for i, a := range d.outAmounts {
		t.RCT.EcdhAmounts = append(t.RCT.EcdhAmounts, ringct.EncryptAmount(a, d.amountKeys[i]))
		mask := ringct.GenCommitmentMask(d.amountKeys[i])
		t.RCT.OutPk = append(t.RCT.OutPk, ringct.Key(ringct.Commit(a, mask).Bytes()))
		primitives.WipeScalar(mask)
	}
	return d, nil
}

// estimateWeight returns the weight with placeholder proofs of the final sizes.
func (d *draft) estimateWeight() (uint64, error) {
	t := *d.t
	nOut := len(t.Outputs)
	lr := 6
	for 1<<(lr-6) < nOut {
		lr++
	}
	t.RCT.BulletproofsPlus = []ringct.BulletproofPlus{{L: make([]ringct.Key, lr), R: make([]ringct.Key, lr)}}
	t.RCT.CLSAGs = make([]ringct.CLSAG, len(t.Inputs))
	for i, in := range t.Inputs {
		t.RCT.CLSAGs[i].S = make([]ringct.Key, len(in.KeyOffsets))
	}
	t.RCT.PseudoOuts = make([][32]byte, len(t.Inputs))
	return t.Weight()
}

// prove ports the rest of genRctSimple: range proof, pseudo outputs, CLSAGs.
func (d *draft) prove(b *build) error {
	t := d.t
	masks := make([]*edwards25519.Scalar, len(d.outAmounts))
	sumOut := edwards25519.NewScalar()
	for i := range masks {
		masks[i] = ringct.GenCommitmentMask(d.amountKeys[i])
		sumOut.Add(sumOut, masks[i])
	}
	defer func() {
		for _, m := range masks {
			primitives.WipeScalar(m)
		}
		primitives.WipeScalar(sumOut)
	}()
	proof, err := bpplus.Prove(b.rng, d.outAmounts, masks)
	if err != nil {
		return err
	}
	for i, v := range proof.V {
		p, err := primitives.DecodePoint(v)
		if err != nil {
			return err
		}
		if ringct.Key(p.MultByCofactor(p).Bytes()) != t.RCT.OutPk[i] { // outPk = scalarmult8(C)
			return errors.New("builder: range proof commitment mismatch")
		}
	}
	proof.V = nil
	t.RCT.BulletproofsPlus = []ringct.BulletproofPlus{*proof}

	n := len(b.sources)
	pseudoMasks := make([]*edwards25519.Scalar, n)
	sum := edwards25519.NewScalar()
	for i := 0; i < n-1; i++ {
		if pseudoMasks[i], err = b.randScalar(); err != nil {
			return err
		}
		sum.Add(sum, pseudoMasks[i])
	}
	pseudoMasks[n-1] = new(edwards25519.Scalar).Subtract(sumOut, sum)
	defer func() {
		for _, m := range pseudoMasks {
			primitives.WipeScalar(m)
		}
	}()
	t.RCT.PseudoOuts = make([][32]byte, n)
	for i, s := range b.sources {
		t.RCT.PseudoOuts[i] = ringct.Key(ringct.Commit(s.in.Amount, pseudoMasks[i]).Bytes())
	}
	t.RCT.CLSAGs = make([]ringct.CLSAG, n)
	msg, err := t.SignatureHash()
	if err != nil {
		return err
	}
	for i, s := range b.sources {
		x, err := primitives.SecretScalarFromCanonical(s.opened.OneTimeSecret)
		if err != nil {
			return err
		}
		sig, ki, err := b.signer.SignInput(b.rng, msg, SpendInput{
			Ring: s.ring, RealIndex: s.in.RealIndex, OneTimeSecret: x,
			Mask: s.mask, PseudoMask: pseudoMasks[i], PseudoOut: t.RCT.PseudoOuts[i],
		})
		primitives.WipeScalar(x)
		if err != nil {
			return fmt.Errorf("builder: input %d: %w", i, err)
		}
		if ki != s.opened.KeyImage {
			return fmt.Errorf("builder: input %d: key image mismatch", i)
		}
		t.RCT.CLSAGs[i] = sig
	}
	return nil
}

func (b *build) finish(d *draft) (*Signed, error) {
	raw, err := d.t.Serialize()
	if err != nil {
		return nil, err
	}
	// Self-check on exactly the bytes we return.
	parsed, err := tx.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("builder: own transaction does not parse: %w", err)
	}
	rings := make([][]verify.RingMember, len(b.sources))
	for i, s := range b.sources {
		rings[i] = s.ring
	}
	if err := verify.Transaction(parsed, rings); err != nil {
		return nil, fmt.Errorf("builder: own transaction does not verify: %w", err)
	}
	weight, err := parsed.Weight()
	if err != nil {
		return nil, err
	}
	need, err := feeFromWeight(b.req.FeePerByte, weight, b.req.FeeQuantizationMask)
	if err != nil {
		return nil, err
	}
	if need > d.fee {
		return nil, fmt.Errorf("builder: fee %d below the %d the weight needs", d.fee, need)
	}
	if weight >= protocol.MaxTxWeight {
		return nil, invalid("transaction weight %d exceeds %d", weight, protocol.MaxTxWeight)
	}
	h, err := parsed.Hash()
	if err != nil {
		return nil, err
	}
	s := &Signed{
		TxHex:  hex.EncodeToString(raw),
		TxHash: hex.EncodeToString(h[:]),
		Fee:    d.fee,
		Weight: weight,
		TxKey:  keys.SecretKey(b.txKey.Bytes()),
		Change: d.change,
	}
	for _, k := range d.addKeys {
		s.AdditionalTxKeys = append(s.AdditionalTxKeys, keys.SecretKey(k.Bytes()))
	}
	for _, src := range b.sources {
		s.KeyImages = append(s.KeyImages, src.opened.KeyImage)
	}
	return s, nil
}

// keyImagesOf returns the key image of each input, in request order.
func keyImagesOf(acct keys.AccountKeys, inputs []Input) ([]keys.KeyImage, error) {
	var outs []scan.OwnedOutput
	for _, in := range inputs {
		outs = append(outs, scan.OwnedOutput{Output: scan.Output{
			TxPubKey: in.TxPubKey, AdditionalTxPubKeys: in.AdditionalTxPubKeys,
			OutputIndex: in.OutputIndex, OutputKey: in.OutputKey,
		}, Subaddress: in.Subaddress})
	}
	return scan.KeyImages(acct, outs)
}
