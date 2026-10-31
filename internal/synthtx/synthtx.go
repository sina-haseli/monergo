// Package synthtx builds structurally valid, fully signed RCT type 6 transactions
// from random keys, for testing the provers against verifiers. It does no address
// or output derivation; it is not a wallet.
package synthtx

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"sort"

	"filippo.io/edwards25519"
	"github.com/sina-haseli/monergo/keys"
	"github.com/sina-haseli/monergo/primitives"
	"github.com/sina-haseli/monergo/ringct"
	"github.com/sina-haseli/monergo/ringct/bpplus"
	"github.com/sina-haseli/monergo/ringct/clsag"
	"github.com/sina-haseli/monergo/tx"
)

// Result is a signed transaction and the ring members of each input.
type Result struct {
	Tx    *tx.Transaction
	Rings [][]clsag.Member
}

func randScalar() *edwards25519.Scalar {
	s, err := primitives.RandomScalar(rand.Reader)
	if err != nil {
		panic(err)
	}
	return s
}

func randPoint() ringct.Key {
	return ringct.Key(new(edwards25519.Point).ScalarBaseMult(randScalar()).Bytes())
}

func randUint(n uint64) uint64 {
	var b [8]byte
	if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
		panic(err)
	}
	return binary.LittleEndian.Uint64(b[:]) % n
}

type input struct {
	amount  uint64
	mask    *edwards25519.Scalar
	secret  *edwards25519.Scalar
	ring    []clsag.Member
	real    int
	offsets []uint64
	ki      ringct.Key
}

// Build returns a signed transaction with nIn inputs, nOut outputs and rings of
// ringSize members.
func Build(nIn, nOut, ringSize int) (*Result, error) {
	if nIn < 1 || nOut < 1 || nOut > 16 || ringSize < 1 {
		return nil, fmt.Errorf("synthtx: bad shape %d/%d/%d", nIn, nOut, ringSize)
	}
	fee := 1000 + randUint(100000)
	ins := make([]input, nIn)
	var total uint64
	for i := range ins {
		in := &ins[i]
		in.amount = 1_000_000 + randUint(1<<40)
		total += in.amount
		in.mask = randScalar()
		in.secret = randScalar()
		in.real = int(randUint(uint64(ringSize)))
		for j := 0; j < ringSize; j++ {
			in.ring = append(in.ring, clsag.Member{Dest: randPoint(), Mask: randPoint()})
		}
		in.ring[in.real].Dest = ringct.Key(new(edwards25519.Point).ScalarBaseMult(in.secret).Bytes())
		in.ring[in.real].Mask = ringct.Key(ringct.Commit(in.amount, in.mask).Bytes())
		var prev uint64
		for j := 0; j < ringSize; j++ {
			abs := prev + 1 + randUint(1000)
			if j == 0 {
				abs = randUint(1 << 30)
			}
			in.offsets = append(in.offsets, abs-prev)
			prev = abs
		}
		ki, err := keys.GenerateKeyImage(keys.PublicKey(in.ring[in.real].Dest), keys.SecretKey(in.secret.Bytes()))
		if err != nil {
			return nil, err
		}
		in.ki = ringct.Key(ki)
	}
	// Consensus: key images strictly decreasing in memcmp order.
	sort.Slice(ins, func(a, b int) bool { return bytes.Compare(ins[a].ki[:], ins[b].ki[:]) > 0 })

	// Outputs share total - fee.
	outAmounts := make([]uint64, nOut)
	remaining := total - fee
	for j := 0; j < nOut-1; j++ {
		outAmounts[j] = randUint(remaining / uint64(nOut))
		remaining -= outAmounts[j]
	}
	outAmounts[nOut-1] = remaining
	gammas := make([]*edwards25519.Scalar, nOut)
	for j := range gammas {
		gammas[j] = randScalar()
	}

	t := &tx.Transaction{Version: 2}
	for _, in := range ins {
		t.Inputs = append(t.Inputs, tx.Input{Amount: 0, KeyOffsets: in.offsets, KeyImage: in.ki})
	}
	for j := 0; j < nOut; j++ {
		var tag [1]byte
		_, _ = rand.Read(tag[:])
		t.Outputs = append(t.Outputs, tx.Output{Key: randPoint(), HasViewTag: true, ViewTag: tag[0]})
		var amt [8]byte
		_, _ = rand.Read(amt[:])
		t.RCT.EcdhAmounts = append(t.RCT.EcdhAmounts, amt)
		t.RCT.OutPk = append(t.RCT.OutPk, ringct.Key(ringct.Commit(outAmounts[j], gammas[j]).Bytes()))
	}
	txPub := randPoint()
	t.Extra = append([]byte{tx.ExtraTagPubKey}, txPub[:]...)
	t.RCT.Type = ringct.TypeBulletproofPlus
	t.RCT.Fee = fee

	proof, err := bpplus.Prove(rand.Reader, outAmounts, gammas)
	if err != nil {
		return nil, err
	}
	t.RCT.BulletproofsPlus = []ringct.BulletproofPlus{*proof}

	// Pseudo outputs: masks summing to the output masks.
	sumGamma := edwards25519.NewScalar()
	for _, g := range gammas {
		sumGamma.Add(sumGamma, g)
	}
	pseudoMasks := make([]*edwards25519.Scalar, nIn)
	sumPseudo := edwards25519.NewScalar()
	for i := 0; i < nIn-1; i++ {
		pseudoMasks[i] = randScalar()
		sumPseudo.Add(sumPseudo, pseudoMasks[i])
	}
	pseudoMasks[nIn-1] = new(edwards25519.Scalar).Subtract(sumGamma, sumPseudo)
	for i, in := range ins {
		t.RCT.PseudoOuts = append(t.RCT.PseudoOuts, ringct.Key(ringct.Commit(in.amount, pseudoMasks[i]).Bytes()))
	}
	t.RCT.CLSAGs = make([]ringct.CLSAG, nIn)

	msg, err := t.SignatureHash()
	if err != nil {
		return nil, err
	}
	res := &Result{Tx: t}
	for i, in := range ins {
		sig, I, err := clsag.SignSimple(rand.Reader, msg, in.ring, in.real, in.secret, in.mask, pseudoMasks[i], t.RCT.PseudoOuts[i])
		if err != nil {
			return nil, err
		}
		if I != in.ki {
			return nil, fmt.Errorf("synthtx: key image mismatch")
		}
		t.RCT.CLSAGs[i] = sig
		res.Rings = append(res.Rings, in.ring)
	}
	return res, nil
}
