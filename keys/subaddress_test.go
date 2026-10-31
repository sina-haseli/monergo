package keys

import (
	"encoding/hex"
	"testing"

	"filippo.io/edwards25519"
)

func mustSecret(t *testing.T, s string) SecretKey {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		t.Fatalf("bad secret %q", s)
	}
	return SecretKey(b)
}

func TestSubaddressZeroIsPrimary(t *testing.T) {
	acct := AccountKeys{Spend: SecretKey{5}, View: SecretKey{6}}
	spendPub, viewPub, err := acct.SubaddressPublicKeys(SubaddressIndex{})
	if err != nil {
		t.Fatal(err)
	}
	wantSpend, _ := acct.Spend.PublicKey()
	wantView, _ := acct.View.PublicKey()
	if spendPub != wantSpend || viewPub != wantView {
		t.Fatal("index (0,0) must be the primary address keys")
	}
}

// The subaddress secret key m must make D = B + m·G and C = a·D, and the one-time
// secret for an output to D must be Hs(8aR‖i) + b + m.
func TestSubaddressSecretSpendKey(t *testing.T) {
	acct := AccountKeys{
		Spend: mustSecret(t, "148d78d2aba7dbca5cd8f6abcfb0b3c009ffbdbea1ff373d50ed94d78286640e"),
		View:  mustSecret(t, "49774391fa5e8d249fc2c5b45dadef13534bf2483dede880dac88f061e809100"),
	}
	idx := SubaddressIndex{Major: 1, Minor: 2}
	D, _, err := acct.SubaddressPublicKeys(idx)
	if err != nil {
		t.Fatal(err)
	}
	sub, err := acct.SubaddressSpendSecretKey(idx)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := sub.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if pub != D {
		t.Fatalf("b + m does not match D")
	}
}

// An output sent to subaddress D with tx key r has one-time key Hs(8rC||i)G + D,
// and the receiver's one-time secret key must open it.
func TestOneTimeSecretKeyOpensSubaddressOutput(t *testing.T) {
	acct := AccountKeys{Spend: SecretKey{21}, View: SecretKey{22}}
	for _, idx := range []SubaddressIndex{{0, 0}, {0, 3}, {2, 7}} {
		D, C, err := acct.SubaddressPublicKeys(idx)
		if err != nil {
			t.Fatal(err)
		}
		r := SecretKey{33}
		// Sender: derivation 8rC, with C the destination's view key.
		senderD, err := GenerateKeyDerivation(C, r)
		if err != nil {
			t.Fatal(err)
		}
		out, err := DerivePublicKey(senderD, 1, D)
		if err != nil {
			t.Fatal(err)
		}
		// Receiver: tx pubkey R = rD for a single subaddress destination, rG otherwise.
		var R PublicKey
		if idx.IsZero() {
			R, _ = r.PublicKey()
		} else {
			R = mulPub(t, r, D)
		}
		recvD, err := GenerateKeyDerivation(R, acct.View)
		if err != nil {
			t.Fatal(err)
		}
		if recvD != senderD {
			t.Fatalf("%v: derivations differ", idx)
		}
		x, err := acct.OneTimeSecretKey(recvD, 1, idx)
		if err != nil {
			t.Fatal(err)
		}
		if got, _ := x.PublicKey(); got != out {
			t.Fatalf("%v: one-time secret does not open the output", idx)
		}
	}
}

func mulPub(t *testing.T, s SecretKey, p PublicKey) PublicKey {
	t.Helper()
	x, err := s.scalar()
	if err != nil {
		t.Fatal(err)
	}
	pt, err := p.point()
	if err != nil {
		t.Fatal(err)
	}
	return PublicKey(new(edwards25519.Point).ScalarMult(x, pt).Bytes())
}
