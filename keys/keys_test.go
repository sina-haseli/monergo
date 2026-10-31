package keys

import (
	"errors"
	"testing"

	"filippo.io/edwards25519"
	"github.com/sina-haseli/monergo/internal/testvectors"
	"github.com/sina-haseli/monergo/primitives"
)

func TestSecretKeyToPublicKeyVectors(t *testing.T) {
	testvectors.Run(t, "secret_key_to_public_key", func(t *testing.T, v testvectors.Vector) {
		sec, ok := SecretKey(v.Hex32(t, 0)), v.Bool(t, 1)
		pub, err := sec.PublicKey()
		if ok != (err == nil) {
			t.Fatalf("PublicKey(%x) err = %v, want ok=%v", sec, err, ok)
		}
		if ok && pub != PublicKey(v.Hex32(t, 2)) {
			t.Fatalf("PublicKey(%x) = %x, want %s", sec, pub, v.Args[2])
		}
	})
}

func TestGenerateKeyDerivationVectors(t *testing.T) {
	testvectors.Run(t, "generate_key_derivation", func(t *testing.T, v testvectors.Vector) {
		pub, sec, ok := PublicKey(v.Hex32(t, 0)), SecretKey(v.Hex32(t, 1)), v.Bool(t, 2)
		d, err := GenerateKeyDerivation(pub, sec)
		if ok != (err == nil) {
			t.Fatalf("err = %v, want ok=%v", err, ok)
		}
		if ok && d != KeyDerivation(v.Hex32(t, 3)) {
			t.Fatalf("derivation = %x, want %s", d, v.Args[3])
		}
	})
}

func TestDerivePublicKeyVectors(t *testing.T) {
	testvectors.Run(t, "derive_public_key", func(t *testing.T, v testvectors.Vector) {
		d, idx, base, ok := KeyDerivation(v.Hex32(t, 0)), v.Uint(t, 1), PublicKey(v.Hex32(t, 2)), v.Bool(t, 3)
		got, err := DerivePublicKey(d, idx, base)
		if ok != (err == nil) {
			t.Fatalf("err = %v, want ok=%v", err, ok)
		}
		if ok && got != PublicKey(v.Hex32(t, 4)) {
			t.Fatalf("got %x, want %s", got, v.Args[4])
		}
	})
}

func TestDeriveSecretKeyVectors(t *testing.T) {
	testvectors.Run(t, "derive_secret_key", func(t *testing.T, v testvectors.Vector) {
		d, idx, base := KeyDerivation(v.Hex32(t, 0)), v.Uint(t, 1), SecretKey(v.Hex32(t, 2))
		got, err := DeriveSecretKey(d, idx, base)
		if err != nil {
			t.Fatal(err)
		}
		if got != SecretKey(v.Hex32(t, 3)) {
			t.Fatalf("got %x, want %s", got, v.Args[3])
		}
	})
}

func TestGenerateKeyImageVectors(t *testing.T) {
	testvectors.Run(t, "generate_key_image", func(t *testing.T, v testvectors.Vector) {
		pub, sec := PublicKey(v.Hex32(t, 0)), SecretKey(v.Hex32(t, 1))
		got, err := GenerateKeyImage(pub, sec)
		if err != nil {
			t.Fatal(err)
		}
		if got != KeyImage(v.Hex32(t, 2)) {
			t.Fatalf("got %x, want %s", got, v.Args[2])
		}
	})
}

func TestDeriveViewTagVectors(t *testing.T) {
	testvectors.Run(t, "derive_view_tag", func(t *testing.T, v testvectors.Vector) {
		d, idx, want := KeyDerivation(v.Hex32(t, 0)), v.Uint(t, 1), v.Hex(t, 2)
		if len(want) != 1 {
			t.Fatalf("view tag must be one byte, got %x", want)
		}
		if got := DeriveViewTag(d, idx); got != ViewTag(want[0]) {
			t.Fatalf("got %02x, want %02x", got, want[0])
		}
	})
}

func TestDeriveKeyImageGeneratorVectors(t *testing.T) {
	ran := 0
	testvectors.Run(t, "derive_key_image_generator", func(t *testing.T, v testvectors.Vector) {
		if !v.Bool(t, 1) {
			t.Skip(testvectors.PartiallySkipped["derive_key_image_generator"])
		}
		ran++
		pub := PublicKey(v.Hex32(t, 0))
		if got := DeriveKeyImageGenerator(pub); got != v.Hex32(t, 2) {
			t.Fatalf("got %x, want %s", got, v.Args[2])
		}
	})
	if ran == 0 {
		t.Fatal("no biased=true vectors ran")
	}
	t.Logf("biased=true vectors run: %d", ran)
}

func TestKeyImageMatchesGenerator(t *testing.T) {
	// I = x * Hp(P) must equal x * DeriveKeyImageGenerator(P).
	sec := SecretKey{1, 2, 3}
	pub, err := sec.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	ki, err := GenerateKeyImage(pub, sec)
	if err != nil {
		t.Fatal(err)
	}
	gen := DeriveKeyImageGenerator(pub)
	genPt, err := primitives.DecodePoint(gen)
	if err != nil {
		t.Fatal(err)
	}
	x, _ := primitives.ScalarFromCanonical(sec)
	want := new(edwards25519.Point).ScalarMult(x, genPt).Bytes()
	if ki != KeyImage(want) {
		t.Fatalf("key image %x != x*generator %x", ki, want)
	}
}

func TestRejectsNonCanonicalSecret(t *testing.T) {
	var big SecretKey
	for i := range big {
		big[i] = 0xff
	}
	if _, err := big.PublicKey(); !errors.Is(err, ErrInvalidSecretKey) {
		t.Errorf("PublicKey: err = %v", err)
	}
	if _, err := GenerateKeyImage(PublicKey{1}, big); !errors.Is(err, ErrInvalidSecretKey) {
		t.Errorf("GenerateKeyImage: err = %v", err)
	}
	if _, err := DeriveSecretKey(KeyDerivation{}, 0, big); !errors.Is(err, ErrInvalidSecretKey) {
		t.Errorf("DeriveSecretKey: err = %v", err)
	}
}

func TestDeriveSubaddressPublicKeyInvertsDerivePublicKey(t *testing.T) {
	spend := SecretKey{7}
	spendPub, _ := spend.PublicKey()
	view := SecretKey{9}
	txSec := SecretKey{11}
	txPub, _ := txSec.PublicKey()
	d, err := GenerateKeyDerivation(txPub, view)
	if err != nil {
		t.Fatal(err)
	}
	out, err := DerivePublicKey(d, 3, spendPub)
	if err != nil {
		t.Fatal(err)
	}
	back, err := DeriveSubaddressPublicKey(out, d, 3)
	if err != nil {
		t.Fatal(err)
	}
	if back != spendPub {
		t.Fatalf("DeriveSubaddressPublicKey did not recover the spend key")
	}
}

func TestWipe(t *testing.T) {
	s := SecretKey{1, 2, 3}
	s.Wipe()
	if s != (SecretKey{}) {
		t.Fatal("Wipe left data behind")
	}
}
