package verify

import (
	"encoding/hex"
	"errors"
	"testing"

	"github.com/sina-haseli/monergo/internal/testvectors"
	"github.com/sina-haseli/monergo/ringct"
	"github.com/sina-haseli/monergo/tx"
)

func hex32(t testing.TB, s string) [32]byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		t.Fatalf("bad hex %q", s)
	}
	return [32]byte(b)
}

func load(t testing.TB, f testvectors.ChainTx) (*tx.Transaction, [][]RingMember) {
	t.Helper()
	b, err := hex.DecodeString(f.Hex)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := tx.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	rings := make([][]RingMember, len(f.Rings))
	for i, ring := range f.Rings {
		for _, m := range ring {
			rings[i] = append(rings[i], RingMember{Dest: hex32(t, m.Key), Mask: hex32(t, m.Mask)})
		}
	}
	return parsed, rings
}

// TestChainFixtures verifies every real non-coinbase transaction: full verification
// for BulletproofPlus (type 6), CLSAGs and balance for type 5 (original
// Bulletproofs are not implemented).
func TestChainFixtures(t *testing.T) {
	n := 0
	for _, f := range testvectors.LoadChainFixtures(t) {
		if f.Coinbase {
			continue
		}
		t.Run(f.Name, func(t *testing.T) {
			parsed, rings := load(t, f)
			switch parsed.RCT.Type {
			case ringct.TypeBulletproofPlus:
				if err := Transaction(parsed, rings); err != nil {
					t.Fatal(err)
				}
			case ringct.TypeCLSAG:
				if err := Transaction(parsed, rings); !errors.Is(err, ErrUnsupported) {
					t.Fatalf("type 5 full verification: err = %v, want ErrUnsupported", err)
				}
				if err := Balance(parsed); err != nil {
					t.Fatal(err)
				}
				if err := CLSAGs(parsed, rings); err != nil {
					t.Fatal(err)
				}
			}
			n += len(parsed.Inputs)
		})
	}
	t.Logf("verified %d real CLSAGs", n)
}

// Flipping any bit of the signed data or the proofs must make verification fail.
func TestTampering(t *testing.T) {
	var f testvectors.ChainTx
	for _, c := range testvectors.LoadChainFixtures(t) {
		if c.Name == "mainnet_bpp_2in_2out" {
			f = c
		}
	}
	type mut struct {
		name string
		do   func(tx *tx.Transaction, rings [][]RingMember)
	}
	muts := []mut{
		{"clsag s", func(t *tx.Transaction, _ [][]RingMember) { t.RCT.CLSAGs[0].S[3][0] ^= 1 }},
		{"clsag c1", func(t *tx.Transaction, _ [][]RingMember) { t.RCT.CLSAGs[1].C1[0] ^= 1 }},
		{"clsag D", func(t *tx.Transaction, _ [][]RingMember) { t.RCT.CLSAGs[0].D[0] ^= 1 }},
		{"pseudo out", func(t *tx.Transaction, _ [][]RingMember) { t.RCT.PseudoOuts[0][0] ^= 1 }},
		{"out commitment", func(t *tx.Transaction, _ [][]RingMember) { t.RCT.OutPk[1][0] ^= 1 }},
		{"ecdh amount", func(t *tx.Transaction, _ [][]RingMember) { t.RCT.EcdhAmounts[0][0] ^= 1 }},
		{"fee", func(t *tx.Transaction, _ [][]RingMember) { t.RCT.Fee++ }},
		{"bp+ A", func(t *tx.Transaction, _ [][]RingMember) { t.RCT.BulletproofsPlus[0].A[0] ^= 1 }},
		{"bp+ r1", func(t *tx.Transaction, _ [][]RingMember) { t.RCT.BulletproofsPlus[0].R1[0] ^= 1 }},
		{"bp+ L", func(t *tx.Transaction, _ [][]RingMember) { t.RCT.BulletproofsPlus[0].L[2][0] ^= 1 }},
		{"output key", func(t *tx.Transaction, _ [][]RingMember) { t.Outputs[0].Key[0] ^= 1 }},
		{"extra", func(t *tx.Transaction, _ [][]RingMember) { t.Extra[3] ^= 1 }},
		{"key image", func(t *tx.Transaction, _ [][]RingMember) { t.Inputs[0].KeyImage[5] ^= 1 }},
		{"ring member key", func(_ *tx.Transaction, r [][]RingMember) { r[0][4].Dest[0] ^= 1 }},
		{"ring member mask", func(_ *tx.Transaction, r [][]RingMember) { r[1][9].Mask[0] ^= 1 }},
		{"swap rings", func(_ *tx.Transaction, r [][]RingMember) { r[0], r[1] = r[1], r[0] }},
		{"swap key images", func(t *tx.Transaction, _ [][]RingMember) {
			t.Inputs[0].KeyImage, t.Inputs[1].KeyImage = t.Inputs[1].KeyImage, t.Inputs[0].KeyImage
		}},
	}
	for _, m := range muts {
		parsed, rings := load(t, f)
		if err := Transaction(parsed, rings); err != nil {
			t.Fatalf("baseline: %v", err)
		}
		m.do(parsed, rings)
		if err := Transaction(parsed, rings); err == nil {
			t.Errorf("%s: tampered transaction verified", m.name)
		}
	}
}
