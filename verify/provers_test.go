package verify

import (
	"encoding/hex"
	"testing"

	"github.com/sina-haseli/monergo/internal/oxidecheck"
	"github.com/sina-haseli/monergo/internal/synthtx"
	"github.com/sina-haseli/monergo/tx"
)

var shapes = []struct{ in, out, ring int }{
	{1, 1, 16}, {1, 2, 16}, {2, 2, 16}, {1, 16, 16}, {4, 3, 16}, {3, 5, 11}, {16, 2, 16}, {2, 9, 1},
}

func buildShapes(t *testing.T) []*synthtx.Result {
	var out []*synthtx.Result
	for _, s := range shapes {
		r, err := synthtx.Build(s.in, s.out, s.ring)
		if err != nil {
			t.Fatal(err)
		}
		// Round trip through bytes so verification sees exactly what is serialized.
		raw, err := r.Tx.Serialize()
		if err != nil {
			t.Fatal(err)
		}
		if r.Tx, err = tx.Parse(raw); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

// TestOwnProofsVerify: every CLSAG and BP+ we produce passes our own verifier.
func TestOwnProofsVerify(t *testing.T) {
	for i, r := range buildShapes(t) {
		if err := Transaction(r.Tx, r.Rings); err != nil {
			t.Fatalf("shape %v: %v", shapes[i], err)
		}
	}
}

// TestOwnProofsWithOxide: monero-oxide parses our transactions to the same bytes,
// computes the same hash and signature hash, and accepts every CLSAG and BP+.
func TestOwnProofsWithOxide(t *testing.T) {
	results := buildShapes(t)
	var reqs []oxidecheck.Tx
	for _, r := range results {
		raw, _ := r.Tx.Serialize()
		var rings [][][2][32]byte
		for _, ring := range r.Rings {
			var rr [][2][32]byte
			for _, m := range ring {
				rr = append(rr, [2][32]byte{m.Dest, m.Mask})
			}
			rings = append(rings, rr)
		}
		reqs = append(reqs, oxidecheck.NewTx(raw, rings))
	}
	for i, res := range oxidecheck.Run(t, reqs) {
		r := results[i]
		if res.Error != "" || !res.Parsed || !res.ReserializedEqual {
			t.Fatalf("shape %v: %+v", shapes[i], res)
		}
		h, _ := r.Tx.Hash()
		sh, _ := r.Tx.SignatureHash()
		if res.Hash != hex.EncodeToString(h[:]) || res.SignatureHash != hex.EncodeToString(sh[:]) {
			t.Fatalf("shape %v: hash/signature hash disagree with oxide", shapes[i])
		}
		for j, ok := range res.CLSAGs {
			if !ok {
				t.Fatalf("shape %v: oxide rejects our CLSAG %d", shapes[i], j)
			}
		}
		if !res.RangeProof {
			t.Fatalf("shape %v: oxide rejects our BP+", shapes[i])
		}
		t.Logf("shape %v: oxide accepts (%d CLSAGs, BP+ for %d outputs)", shapes[i], len(res.CLSAGs), shapes[i].out)
	}
}
