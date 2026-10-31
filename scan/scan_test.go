package scan

import (
	"errors"
	"testing"

	"filippo.io/edwards25519"
	"github.com/sina-haseli/monergo/keys"
	"github.com/sina-haseli/monergo/ringct"
)

func pubMul(t *testing.T, s keys.SecretKey, p keys.PublicKey) keys.PublicKey {
	t.Helper()
	x, err := edwards25519.NewScalar().SetCanonicalBytes(s[:])
	if err != nil {
		t.Fatal(err)
	}
	pt, err := new(edwards25519.Point).SetBytes(p[:])
	if err != nil {
		t.Fatal(err)
	}
	return keys.PublicKey(new(edwards25519.Point).ScalarMult(x, pt).Bytes())
}

// send builds an output to (D, C) the way construct_tx does: derivation r·C, output
// key Hs(8rC‖i)·G + D.
func send(t *testing.T, r keys.SecretKey, D, C keys.PublicKey, i uint64) keys.PublicKey {
	d, err := keys.GenerateKeyDerivation(C, r)
	if err != nil {
		t.Fatal(err)
	}
	out, err := keys.DerivePublicKey(d, i, D)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestFindAndOpen(t *testing.T) {
	acct := keys.AccountKeys{Spend: keys.SecretKey{41}, View: keys.SecretKey{42}}
	table, err := NewSubaddressTable(acct, 3, 5)
	if err != nil {
		t.Fatal(err)
	}
	r := keys.SecretKey{77}
	rG, _ := r.PublicKey()
	cases := []struct {
		name string
		idx  keys.SubaddressIndex
		mk   func(D, C keys.PublicKey) Output
	}{
		{"primary, R = rG", keys.SubaddressIndex{}, func(D, C keys.PublicKey) Output {
			return Output{TxPubKey: rG, OutputIndex: 1, OutputKey: send(t, r, D, C, 1)}
		}},
		{"single subaddress, R = rD", keys.SubaddressIndex{Major: 1, Minor: 4}, func(D, C keys.PublicKey) Output {
			return Output{TxPubKey: pubMul(t, r, D), OutputIndex: 0, OutputKey: send(t, r, D, C, 0)}
		}},
		{"additional key", keys.SubaddressIndex{Major: 2, Minor: 3}, func(D, C keys.PublicKey) Output {
			ra := keys.SecretKey{99}
			return Output{
				TxPubKey:            rG,
				AdditionalTxPubKeys: []keys.PublicKey{rG, pubMul(t, ra, D)},
				OutputIndex:         1,
				OutputKey:           send(t, ra, D, C, 1),
			}
		}},
	}
	for _, c := range cases {
		D, C, err := acct.SubaddressPublicKeys(c.idx)
		if err != nil {
			t.Fatal(err)
		}
		out := c.mk(D, C)
		opened, err := Open(acct, table, out)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if opened.Subaddress != c.idx {
			t.Fatalf("%s: found %v", c.name, opened.Subaddress)
		}
		want, _ := keys.GenerateKeyImage(out.OutputKey, opened.OneTimeSecret)
		if opened.KeyImage != want {
			t.Fatalf("%s: key image", c.name)
		}
		kis, err := KeyImages(acct, []OwnedOutput{{Output: out, Subaddress: c.idx}})
		if err != nil || kis[0] != want {
			t.Fatalf("%s: KeyImages = %v, %v", c.name, kis, err)
		}
		// A wrong view tag short-circuits; the right one is accepted.
		tag := keys.DeriveViewTag(opened.Derivation, out.OutputIndex)
		out.ViewTag = &tag
		if _, err := Find(table, acct.View, out); err != nil {
			t.Fatalf("%s: with view tag: %v", c.name, err)
		}
		bad := tag + 1
		out.ViewTag = &bad
		if _, err := Find(table, acct.View, out); !errors.Is(err, ErrNotOwned) {
			t.Fatalf("%s: wrong view tag accepted", c.name)
		}
	}
}

func TestNotOwned(t *testing.T) {
	acct := keys.AccountKeys{Spend: keys.SecretKey{41}, View: keys.SecretKey{42}}
	other := keys.AccountKeys{Spend: keys.SecretKey{51}, View: keys.SecretKey{52}}
	table, _ := NewSubaddressTable(acct, 1, 2)
	D, C, _ := other.SubaddressPublicKeys(keys.SubaddressIndex{})
	r := keys.SecretKey{3}
	rG, _ := r.PublicKey()
	out := Output{TxPubKey: rG, OutputIndex: 0, OutputKey: send(t, r, D, C, 0)}
	if _, err := Open(acct, table, out); !errors.Is(err, ErrNotOwned) {
		t.Fatalf("err = %v", err)
	}
	if _, err := KeyImages(acct, []OwnedOutput{{Output: out}}); err == nil {
		t.Fatal("KeyImages accepted a foreign output")
	}
}

func TestAmountRoundTrip(t *testing.T) {
	k := ringct.Key{1, 2, 3}
	for _, a := range []uint64{0, 1, 123456789012, ^uint64(0)} {
		if got := ringct.DecryptAmount(ringct.EncryptAmount(a, k), k); got != a {
			t.Fatalf("amount %d -> %d", a, got)
		}
	}
	if ringct.GenCommitmentMask(k).Equal(ringct.GenCommitmentMask(ringct.Key{1, 2, 4})) == 1 {
		t.Fatal("masks collide")
	}
}
