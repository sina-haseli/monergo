package primitives

import (
	"encoding/hex"
	"testing"

	"filippo.io/edwards25519"
	"github.com/sina-haseli/monergo/internal/testvectors"
)

func TestKeccak256(t *testing.T) {
	// Original Keccak-256 (not SHA3-256) of the empty string.
	got := Keccak256()
	want := "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
	if hex.EncodeToString(got[:]) != want {
		t.Fatalf("Keccak256() = %x, want %s", got, want)
	}
	a, b := Keccak256([]byte("ab"), []byte("c")), Keccak256([]byte("abc"))
	if a != b {
		t.Fatal("Keccak256 must hash the concatenation of its arguments")
	}
}

func TestCheckScalarVectors(t *testing.T) {
	testvectors.Run(t, "check_scalar", func(t *testing.T, v testvectors.Vector) {
		s, want := v.Hex32(t, 0), v.Bool(t, 1)
		if got := ScCheck(s); got != want {
			t.Fatalf("ScCheck(%x) = %v, want %v", s, got, want)
		}
	})
}

func TestHashToScalarVectors(t *testing.T) {
	testvectors.Run(t, "hash_to_scalar", func(t *testing.T, v testvectors.Vector) {
		data, want := v.Hex(t, 0), v.Hex32(t, 1)
		if got := HashToScalar(data); [32]byte(got.Bytes()) != want {
			t.Fatalf("HashToScalar(%x) = %x, want %x", data, got.Bytes(), want)
		}
	})
}

func TestCheckKeyVectors(t *testing.T) {
	testvectors.Run(t, "check_key", func(t *testing.T, v testvectors.Vector) {
		k, want := v.Hex32(t, 0), v.Bool(t, 1)
		if got := CheckKey(k); got != want {
			t.Fatalf("CheckKey(%x) = %v, want %v", k, got, want)
		}
	})
}

func TestHashToPointVectors(t *testing.T) {
	testvectors.Run(t, "hash_to_point", func(t *testing.T, v testvectors.Vector) {
		h, want := v.Hex32(t, 0), v.Hex32(t, 1)
		if got := HashToPoint(h); got != want {
			t.Fatalf("HashToPoint(%x) = %x, want %x", h, got, want)
		}
	})
}

func TestBiasedHashToECVectors(t *testing.T) {
	testvectors.Run(t, "biased_hash_to_ec", func(t *testing.T, v testvectors.Vector) {
		k, want := v.Hex32(t, 0), v.Hex32(t, 1)
		if got := BiasedHashToEC(k).Bytes(); [32]byte(got) != want {
			t.Fatalf("BiasedHashToEC(%x) = %x, want %x", k, got, want)
		}
	})
}

// check_ge_p3_identity computes (K+K)-K-K, an identity with non-normalized ref10
// coordinates, and checks that the identity test recognizes it. The "bad" column
// tests a ref10 limb-comparison bug that has no counterpart here.
func TestIdentityVectors(t *testing.T) {
	testvectors.Run(t, "check_ge_p3_identity", func(t *testing.T, v testvectors.Vector) {
		k, wantGood := v.Hex32(t, 0), v.Bool(t, 2)
		p, err := DecodePoint(k)
		if err != nil {
			t.Fatal(err)
		}
		q := new(edwards25519.Point).Add(p, p)
		q.Subtract(q, p)
		q.Subtract(q, p)
		if got := IsIdentity(q); got != wantGood {
			t.Fatalf("IsIdentity((K+K)-K-K) = %v, want %v", got, wantGood)
		}
		if IsIdentity(p) {
			t.Fatal("K itself must not be the identity")
		}
	})
}

// DecodePoint must reject the two non-canonical encodings that edwards25519's
// SetBytes accepts but Monero's ge_frombytes_vartime rejects.
func TestDecodePointRejectsNonCanonical(t *testing.T) {
	// y = p (2^255 - 19), the non-reduced encoding of y = 0.
	var yP [32]byte
	yP[0] = 0xed
	for i := 1; i < 31; i++ {
		yP[i] = 0xff
	}
	yP[31] = 0x7f
	if _, err := new(edwards25519.Point).SetBytes(yP[:]); err != nil {
		t.Fatalf("precondition: edwards25519 accepts y=p: %v", err)
	}
	if CheckKey(yP) {
		t.Error("CheckKey accepted non-reduced y = p")
	}
	// y = 1 with the sign bit set: x = 0, "negative zero".
	var negZero [32]byte
	negZero[0] = 1
	negZero[31] = 0x80
	if _, err := new(edwards25519.Point).SetBytes(negZero[:]); err != nil {
		t.Fatalf("precondition: edwards25519 accepts -0: %v", err)
	}
	if CheckKey(negZero) {
		t.Error("CheckKey accepted x = 0 with the sign bit set")
	}
	// The identity itself (y = 1, sign 0) is a valid encoding.
	var ident [32]byte
	ident[0] = 1
	if !CheckKey(ident) {
		t.Error("CheckKey rejected the identity")
	}
}

func TestScReduce32(t *testing.T) {
	// l, the group order, reduces to zero; l+1 to one.
	l, _ := hex.DecodeString("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010")
	if got := ScReduce32([32]byte(l)); got != ([32]byte{}) {
		t.Fatalf("ScReduce32(l) = %x", got)
	}
	l[0]++
	if got := ScReduce32([32]byte(l)); got != ([32]byte{1}) {
		t.Fatalf("ScReduce32(l+1) = %x", got)
	}
}

func TestFieldConstants(t *testing.T) {
	// The fe_fffb* constants are documented square roots; check they square to the
	// documented values so a transcription error cannot slip through.
	a := feFromInt(486662)
	aa2 := new(fieldElement).Multiply(a, new(fieldElement).Add(a, feFromInt(2))) // A(A+2)
	two := feFromInt(2)
	sq := func(x *fieldElement) *fieldElement { return new(fieldElement).Square(x) }
	neg := func(x *fieldElement) *fieldElement { return new(fieldElement).Negate(x) }
	mul := func(x, y *fieldElement) *fieldElement { return new(fieldElement).Multiply(x, y) }
	checks := []struct {
		name      string
		got, want *fieldElement
	}{
		{"ma = -A", feMA, neg(a)},
		{"ma2 = -A^2", feMA2, neg(sq(a))},
		{"sqrtm1^2 = -1", sq(feSqrtM1), neg(feFromInt(1))},
		{"fffb1^2 = -2A(A+2)", sq(feFFFB1), neg(mul(two, aa2))},
		{"fffb2^2 = 2A(A+2)", sq(feFFFB2), mul(two, aa2)},
		{"fffb3^2 = -sqrt(-1)A(A+2)", sq(feFFFB3), neg(mul(feSqrtM1, aa2))},
		{"fffb4^2 = sqrt(-1)A(A+2)", sq(feFFFB4), mul(feSqrtM1, aa2)},
	}
	for _, c := range checks {
		if c.got.Equal(c.want) != 1 {
			t.Errorf("%s: mismatch", c.name)
		}
	}
}
