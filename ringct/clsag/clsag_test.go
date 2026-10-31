package clsag

import (
	"crypto/rand"
	"testing"

	"filippo.io/edwards25519"
	"github.com/sina-haseli/monergo/keys"
	"github.com/sina-haseli/monergo/primitives"
	"github.com/sina-haseli/monergo/ringct"
)

type fixture struct {
	ring      []Member
	l         int
	p, inMask *edwards25519.Scalar
	outMask   *edwards25519.Scalar
	cOut      ringct.Key
	message   ringct.Key
}

func randScalar(t *testing.T) *edwards25519.Scalar {
	s, err := primitives.RandomScalar(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func randPoint(t *testing.T) ringct.Key {
	return ringct.Key(new(edwards25519.Point).ScalarBaseMult(randScalar(t)).Bytes())
}

func newFixture(t *testing.T, n, l int, amount uint64) fixture {
	f := fixture{l: l, p: randScalar(t), inMask: randScalar(t), outMask: randScalar(t)}
	for i := 0; i < n; i++ {
		f.ring = append(f.ring, Member{Dest: randPoint(t), Mask: randPoint(t)})
	}
	f.ring[l].Dest = ringct.Key(new(edwards25519.Point).ScalarBaseMult(f.p).Bytes())
	f.ring[l].Mask = ringct.Key(ringct.Commit(amount, f.inMask).Bytes())
	f.cOut = ringct.Key(ringct.Commit(amount, f.outMask).Bytes())
	f.message = randPoint(t)
	return f
}

// Every signature we produce must pass our verifier, for every ring position.
func TestSignVerify(t *testing.T) {
	for _, n := range []int{1, 2, 11, 16} {
		for _, l := range []int{0, n / 2, n - 1} {
			f := newFixture(t, n, l, 123456789)
			sig, I, err := SignSimple(rand.Reader, f.message, f.ring, f.l, f.p, f.inMask, f.outMask, f.cOut)
			if err != nil {
				t.Fatal(err)
			}
			if err := Verify(f.message, sig, I, f.ring, f.cOut); err != nil {
				t.Fatalf("n=%d l=%d: %v", n, l, err)
			}
			// The key image is the standard one: p·Hp(P_l).
			want, err := keys.GenerateKeyImage(keys.PublicKey(f.ring[l].Dest), keys.SecretKey(f.p.Bytes()))
			if err != nil {
				t.Fatal(err)
			}
			if I != ringct.Key(want) {
				t.Fatalf("n=%d l=%d: key image mismatch", n, l)
			}
		}
	}
}

func TestSignVerifyRejects(t *testing.T) {
	f := newFixture(t, 16, 7, 42)
	sig, I, err := SignSimple(rand.Reader, f.message, f.ring, f.l, f.p, f.inMask, f.outMask, f.cOut)
	if err != nil {
		t.Fatal(err)
	}
	other := f.message
	other[0] ^= 1
	if Verify(other, sig, I, f.ring, f.cOut) == nil {
		t.Error("verified for another message")
	}
	badRing := append([]Member{}, f.ring...)
	badRing[3].Dest = randPoint(t)
	if Verify(f.message, sig, I, badRing, f.cOut) == nil {
		t.Error("verified with another ring")
	}
	if Verify(f.message, sig, randPoint(t), f.ring, f.cOut) == nil {
		t.Error("verified with another key image")
	}
	if Verify(f.message, sig, I, f.ring, randPoint(t)) == nil {
		t.Error("verified with another pseudo output")
	}
}

// Signing for a different amount (cOut does not commit to the input's amount)
// cannot produce a valid signature: the signer's ownership check rejects it.
func TestSignRejectsWrongAmountOrKey(t *testing.T) {
	f := newFixture(t, 4, 1, 1000)
	wrongOut := ringct.Key(ringct.Commit(999, f.outMask).Bytes())
	if _, _, err := SignSimple(rand.Reader, f.message, f.ring, f.l, f.p, f.inMask, f.outMask, wrongOut); err == nil {
		t.Error("signed with an unbalanced pseudo output")
	}
	if _, _, err := SignSimple(rand.Reader, f.message, f.ring, f.l, randScalar(t), f.inMask, f.outMask, f.cOut); err == nil {
		t.Error("signed with a key that does not own ring member l")
	}
	if _, _, err := SignSimple(rand.Reader, f.message, f.ring, 4, f.p, f.inMask, f.outMask, f.cOut); err == nil {
		t.Error("signed with an out-of-range index")
	}
}

func BenchmarkSign16(b *testing.B) {
	t := &testing.T{}
	f := newFixture(t, 16, 5, 1)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := SignSimple(rand.Reader, f.message, f.ring, f.l, f.p, f.inMask, f.outMask, f.cOut); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerify16(b *testing.B) {
	t := &testing.T{}
	f := newFixture(t, 16, 5, 1)
	sig, I, _ := SignSimple(rand.Reader, f.message, f.ring, f.l, f.p, f.inMask, f.outMask, f.cOut)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := Verify(f.message, sig, I, f.ring, f.cOut); err != nil {
			b.Fatal(err)
		}
	}
}
