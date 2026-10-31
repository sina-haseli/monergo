package bpplus

import (
	"crypto/rand"
	mrand "math/rand/v2"
	"testing"

	"filippo.io/edwards25519"
	"github.com/sina-haseli/monergo/primitives"
	"github.com/sina-haseli/monergo/ringct"
)

func gammas(t testing.TB, n int) []*edwards25519.Scalar {
	out := make([]*edwards25519.Scalar, n)
	for i := range out {
		s, err := primitives.RandomScalar(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		out[i] = s
	}
	return out
}

// Every proof we produce must verify, for every aggregation size, and its V must
// be the commitments divided by 8.
func TestProveVerify(t *testing.T) {
	rng := mrand.New(mrand.NewPCG(1, 2))
	for _, n := range []int{1, 2, 3, 4, 5, 8, 16} {
		amounts := make([]uint64, n)
		for i := range amounts {
			switch i % 3 {
			case 0:
				amounts[i] = rng.Uint64()
			case 1:
				amounts[i] = 0
			default:
				amounts[i] = ^uint64(0)
			}
		}
		gs := gammas(t, n)
		p, err := Prove(rand.Reader, amounts, gs)
		if err != nil {
			t.Fatal(err)
		}
		if err := Verify([]*ringct.BulletproofPlus{p}); err != nil {
			t.Fatalf("n=%d: own proof does not verify: %v", n, err)
		}
		for i := range amounts {
			v, _ := primitives.DecodePoint(p.V[i])
			c := ringct.Commit(amounts[i], gs[i])
			if new(edwards25519.Point).MultByCofactor(v).Equal(c) != 1 {
				t.Fatalf("n=%d: 8·V[%d] is not the commitment", n, i)
			}
		}
		wantL := 6
		for 1<<(wantL-6) < n {
			wantL++
		}
		if len(p.L) != wantL {
			t.Fatalf("n=%d: |L| = %d, want %d", n, len(p.L), wantL)
		}
	}
}

// A proof is bound to its commitments: swapping in another commitment fails.
func TestProofBoundToCommitments(t *testing.T) {
	gs := gammas(t, 2)
	p, err := Prove(rand.Reader, []uint64{10, 20}, gs)
	if err != nil {
		t.Fatal(err)
	}
	q := *p
	q.V = []ringct.Key{p.V[1], p.V[0]}
	if Verify([]*ringct.BulletproofPlus{&q}) == nil {
		t.Fatal("proof verified with swapped commitments")
	}
}

func TestProveRejects(t *testing.T) {
	if _, err := Prove(rand.Reader, nil, nil); err == nil {
		t.Error("empty input accepted")
	}
	if _, err := Prove(rand.Reader, make([]uint64, 17), gammas(t, 17)); err == nil {
		t.Error("17 amounts accepted")
	}
	if _, err := Prove(rand.Reader, []uint64{1, 2}, gammas(t, 1)); err == nil {
		t.Error("mismatched lengths accepted")
	}
}

func BenchmarkProve2(b *testing.B) {
	gs := gammas(b, 2)
	initGenerators()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Prove(rand.Reader, []uint64{1, 2}, gs); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerify2(b *testing.B) {
	gs := gammas(b, 2)
	p, _ := Prove(rand.Reader, []uint64{1, 2}, gs)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := Verify([]*ringct.BulletproofPlus{p}); err != nil {
			b.Fatal(err)
		}
	}
}
