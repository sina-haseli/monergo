package verify

import (
	"encoding/hex"
	"testing"

	"github.com/sina-haseli/monergo/internal/oxidecheck"
	"github.com/sina-haseli/monergo/internal/testvectors"
)

// TestOxideChainFixtures validates the cross-check harness itself: monero-oxide must
// agree with the node and with us on every real transaction.
func TestOxideChainFixtures(t *testing.T) {
	var reqs []oxidecheck.Tx
	var fixtures []testvectors.ChainTx
	for _, f := range testvectors.LoadChainFixtures(t) {
		raw, _ := hex.DecodeString(f.Hex)
		var rings [][][2][32]byte
		for _, ring := range f.Rings {
			var r [][2][32]byte
			for _, m := range ring {
				r = append(r, [2][32]byte{hex32(t, m.Key), hex32(t, m.Mask)})
			}
			rings = append(rings, r)
		}
		reqs = append(reqs, oxidecheck.NewTx(raw, rings))
		fixtures = append(fixtures, f)
	}
	for i, res := range oxidecheck.Run(t, reqs) {
		f := fixtures[i]
		if res.Error != "" || !res.Parsed || !res.ReserializedEqual {
			t.Fatalf("%s: oxide: %+v", f.Name, res)
		}
		if res.Hash != f.Hash {
			t.Fatalf("%s: oxide hash %s", f.Name, res.Hash)
		}
		if f.Coinbase {
			continue
		}
		parsed, _ := load(t, f)
		ours, _ := parsed.SignatureHash()
		if res.SignatureHash != hex.EncodeToString(ours[:]) {
			t.Fatalf("%s: signature hash: oxide %s, ours %x", f.Name, res.SignatureHash, ours)
		}
		for j, ok := range res.CLSAGs {
			if !ok {
				t.Fatalf("%s: oxide rejects CLSAG %d", f.Name, j)
			}
		}
		if !res.RangeProof {
			t.Fatalf("%s: oxide rejects range proof", f.Name)
		}
		t.Logf("%s: oxide agrees (weight %d)", f.Name, res.Weight)
	}
}
