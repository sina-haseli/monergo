package builder

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/sina-haseli/monergo/internal/oxidecheck"
	"github.com/sina-haseli/monergo/keys"
)

// TestBuiltTransactionsWithOxide: monero-oxide parses every transaction the builder
// produces to the same bytes, agrees on hash, signature hash and weight, and
// accepts every CLSAG and the BP+.
func TestBuiltTransactionsWithOxide(t *testing.T) {
	me := randAccount(t)
	type built struct {
		name   string
		signed *Signed
		req    TransferRequest
	}
	var cases []built
	for _, shape := range []struct{ in, out int }{{1, 1}, {2, 1}, {1, 2}, {3, 5}, {1, 15}} {
		var ins []Input
		for i := 0; i < shape.in; i++ {
			ins = append(ins, receive(t, me, keys.SubaddressIndex{Minor: uint32(i)}, 3e12, false))
		}
		var dests []Destination
		for i := 0; i < shape.out; i++ {
			idx := keys.SubaddressIndex{Minor: uint32(i % 2)}
			dests = append(dests, Destination{addr(t, randAccount(t), idx), 1e10})
		}
		req := baseRequest(ins, dests)
		s, _ := signAndParse(t, me, req)
		cases = append(cases, built{fmt.Sprintf("%din/%ddest", shape.in, shape.out), s, req})
	}
	var reqs []oxidecheck.Tx
	for _, c := range cases {
		raw, _ := hex.DecodeString(c.signed.TxHex)
		var rings [][][2][32]byte
		// Rings in transaction order: inputs are sorted by key image.
		byKI := map[keys.KeyImage]Input{}
		kis, _ := keyImagesOf(me, c.req.Inputs)
		for i, in := range c.req.Inputs {
			byKI[kis[i]] = in
		}
		for _, ki := range c.signed.KeyImages {
			var r [][2][32]byte
			for _, m := range byKI[ki].Ring {
				r = append(r, [2][32]byte{m.Key, m.Commitment})
			}
			rings = append(rings, r)
		}
		reqs = append(reqs, oxidecheck.NewTx(raw, rings))
	}
	for i, res := range oxidecheck.Run(t, reqs) {
		c := cases[i]
		if res.Error != "" || !res.Parsed || !res.ReserializedEqual {
			t.Fatalf("%s: %+v", c.name, res)
		}
		if res.Hash != c.signed.TxHash {
			t.Fatalf("%s: hash %s vs %s", c.name, res.Hash, c.signed.TxHash)
		}
		if uint64(res.Weight) != c.signed.Weight {
			t.Fatalf("%s: weight oxide %d, ours %d", c.name, res.Weight, c.signed.Weight)
		}
		for j, ok := range res.CLSAGs {
			if !ok {
				t.Fatalf("%s: oxide rejects CLSAG %d", c.name, j)
			}
		}
		if !res.RangeProof {
			t.Fatalf("%s: oxide rejects BP+", c.name)
		}
		t.Logf("%s: oxide accepts (weight %d, fee %d)", c.name, res.Weight, c.signed.Fee)
	}
}
