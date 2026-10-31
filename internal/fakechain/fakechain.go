// Package fakechain fabricates owned outputs with rings of random decoys, as a
// sender and a daemon would provide them, for tests of the signer.
package fakechain

import (
	"crypto/rand"
	"encoding/binary"

	"filippo.io/edwards25519"
	"github.com/sina-haseli/monergo/builder"
	"github.com/sina-haseli/monergo/keys"
	"github.com/sina-haseli/monergo/primitives"
	"github.com/sina-haseli/monergo/ringct"
)

func randScalar() *edwards25519.Scalar {
	s, err := primitives.RandomScalar(rand.Reader)
	if err != nil {
		panic(err)
	}
	return s
}

func randUint(n uint64) uint64 {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return binary.LittleEndian.Uint64(b[:]) % n
}

// Account returns a random account.
func Account() keys.AccountKeys {
	return keys.AccountFromRecoveryKey([32]byte(randScalar().Bytes()))
}

// Receive returns an Input spending a new RingCT output of amount sent to acct at
// idx, with a ring of 16.
func Receive(acct keys.AccountKeys, idx keys.SubaddressIndex, amount uint64) (builder.Input, error) {
	D, C, err := acct.SubaddressPublicKeys(idx)
	if err != nil {
		return builder.Input{}, err
	}
	r := randScalar()
	rk := keys.SecretKey(r.Bytes())
	defer rk.Wipe()
	txPub, _ := rk.PublicKey()
	if !idx.IsZero() {
		dp, _ := primitives.DecodePoint(D)
		txPub = keys.PublicKey(new(edwards25519.Point).ScalarMult(r, dp).Bytes())
	}
	outIndex := randUint(4)
	der, err := keys.GenerateKeyDerivation(C, rk)
	if err != nil {
		return builder.Input{}, err
	}
	outKey, err := keys.DerivePublicKey(der, outIndex, D)
	if err != nil {
		return builder.Input{}, err
	}
	ak := keys.DerivationToScalar(der, outIndex)
	commitment := ringct.Key(ringct.Commit(amount, ringct.GenCommitmentMask(ringct.Key(ak.Bytes()))).Bytes())
	in := builder.Input{
		TxPubKey: txPub, OutputIndex: outIndex, OutputKey: outKey, Amount: amount,
		Subaddress: idx, RealIndex: int(randUint(16)),
	}
	g := 1000 + randUint(1<<20)
	for j := 0; j < 16; j++ {
		g += 1 + randUint(5000)
		m := builder.RingMember{GlobalIndex: g,
			Key:        keys.PublicKey(new(edwards25519.Point).ScalarBaseMult(randScalar()).Bytes()),
			Commitment: keys.PublicKey(new(edwards25519.Point).ScalarBaseMult(randScalar()).Bytes())}
		if j == in.RealIndex {
			m.Key, m.Commitment = outKey, commitment
		}
		in.Ring = append(in.Ring, m)
	}
	return in, nil
}
