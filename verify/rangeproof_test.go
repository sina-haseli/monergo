package verify

import (
	"testing"

	"filippo.io/edwards25519"
	"github.com/sina-haseli/monergo/internal/testvectors"
	"github.com/sina-haseli/monergo/primitives"
	"github.com/sina-haseli/monergo/ringct"
	"github.com/sina-haseli/monergo/ringct/bpplus"
	"github.com/sina-haseli/monergo/tx"
)

// bppWithV returns the transaction's BP+ with V restored from outPk.
func bppWithV(t *testing.T, parsed *tx.Transaction) *ringct.BulletproofPlus {
	t.Helper()
	p := parsed.RCT.BulletproofsPlus[0]
	inv8 := ringct.InvEight()
	p.V = nil
	for _, c := range parsed.RCT.OutPk {
		pt, err := primitives.DecodePoint(c)
		if err != nil {
			t.Fatal(err)
		}
		p.V = append(p.V, ringct.Key(new(edwards25519.Point).ScalarMult(inv8, pt).Bytes()))
	}
	return &p
}

func bppFixtures(t *testing.T) []*ringct.BulletproofPlus {
	var out []*ringct.BulletproofPlus
	for _, f := range testvectors.LoadChainFixtures(t) {
		if f.Coinbase || f.RCTType != int(ringct.TypeBulletproofPlus) {
			continue
		}
		parsed, _ := load(t, f)
		out = append(out, bppWithV(t, parsed))
	}
	if len(out) < 5 {
		t.Fatalf("only %d BP+ fixtures", len(out))
	}
	return out
}

// Each field of a real proof, tampered on its own, must fail the range proof check
// (independently of CLSAG, whose message would also change).
func TestBulletproofPlusTampering(t *testing.T) {
	proofs := bppFixtures(t)
	for _, p := range proofs {
		if err := bpplus.Verify([]*ringct.BulletproofPlus{p}); err != nil {
			t.Fatalf("baseline: %v", err)
		}
	}
	p := proofs[len(proofs)-1]
	fields := map[string]func(q *ringct.BulletproofPlus){
		"A":                func(q *ringct.BulletproofPlus) { q.A[1] ^= 1 },
		"A1":               func(q *ringct.BulletproofPlus) { q.A1[1] ^= 1 },
		"B":                func(q *ringct.BulletproofPlus) { q.B[1] ^= 1 },
		"r1":               func(q *ringct.BulletproofPlus) { q.R1[1] ^= 1 },
		"s1":               func(q *ringct.BulletproofPlus) { q.S1[1] ^= 1 },
		"d1":               func(q *ringct.BulletproofPlus) { q.D1[1] ^= 1 },
		"L0":               func(q *ringct.BulletproofPlus) { q.L[0][1] ^= 1 },
		"Llast":            func(q *ringct.BulletproofPlus) { q.L[len(q.L)-1][1] ^= 1 },
		"R3":               func(q *ringct.BulletproofPlus) { q.R[3][1] ^= 1 },
		"V0":               func(q *ringct.BulletproofPlus) { q.V[0][1] ^= 1 },
		"drop V":           func(q *ringct.BulletproofPlus) { q.V = q.V[:len(q.V)-1] },
		"swap L/R":         func(q *ringct.BulletproofPlus) { q.L, q.R = q.R, q.L },
		"non-canonical r1": func(q *ringct.BulletproofPlus) { q.R1[31] |= 0xf0 },
	}
	for name, mutate := range fields {
		q := *p
		q.V = append([]ringct.Key{}, p.V...)
		q.L = append([]ringct.Key{}, p.L...)
		q.R = append([]ringct.Key{}, p.R...)
		mutate(&q)
		if err := bpplus.Verify([]*ringct.BulletproofPlus{&q}); err == nil {
			t.Errorf("%s: tampered proof verified", name)
		}
	}
}

// Batch verification accepts all real proofs together and rejects the batch if
// any one of them is bad.
func TestBulletproofPlusBatch(t *testing.T) {
	proofs := bppFixtures(t)
	if err := bpplus.Verify(proofs); err != nil {
		t.Fatalf("batch of %d: %v", len(proofs), err)
	}
	bad := *proofs[2]
	bad.D1[0] ^= 1
	batch := append(append([]*ringct.BulletproofPlus{}, proofs...), &bad)
	if err := bpplus.Verify(batch); err == nil {
		t.Fatal("batch with a bad proof verified")
	}
}

func TestBalanceAlone(t *testing.T) {
	for _, f := range testvectors.LoadChainFixtures(t) {
		if f.Coinbase {
			continue
		}
		parsed, _ := load(t, f)
		if err := Balance(parsed); err != nil {
			t.Fatalf("%s: %v", f.Name, err)
		}
		parsed.RCT.Fee++
		if err := Balance(parsed); err == nil {
			t.Fatalf("%s: fee+1 balanced", f.Name)
		}
	}
}

func TestConstants(t *testing.T) {
	eight := ringct.AmountScalar(8)
	if got := new(edwards25519.Scalar).Invert(eight); got.Equal(ringct.InvEight()) != 1 {
		t.Fatal("INV_EIGHT is not 8^-1")
	}
	if ringct.ZeroCommit(0) != [32]byte(edwards25519.NewGeneratorPoint().Bytes()) {
		t.Fatal("ZeroCommit(0) != G")
	}
}
