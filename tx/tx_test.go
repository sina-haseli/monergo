package tx

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/sina-haseli/monergo/internal/testvectors"
)

func mustHex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestChainFixtures parses real transactions, re-serializes them byte for byte and
// recomputes the tx hash and prunable hash the node reported.
func TestChainFixtures(t *testing.T) {
	for _, f := range testvectors.LoadChainFixtures(t) {
		t.Run(f.Name, func(t *testing.T) {
			raw := mustHex(t, f.Hex)
			tx, err := Parse(raw)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			out, err := tx.Serialize()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(out, raw) {
				t.Fatalf("re-serialization differs (%d vs %d bytes)", len(out), len(raw))
			}
			h, err := tx.Hash()
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(h[:]) != f.Hash {
				t.Fatalf("hash %x, want %s", h, f.Hash)
			}
			if !f.Coinbase {
				ph, err := tx.PrunableHash()
				if err != nil {
					t.Fatal(err)
				}
				if hex.EncodeToString(ph[:]) != f.PrunableHash {
					t.Fatalf("prunable hash %x, want %s", ph, f.PrunableHash)
				}
			}
			if int(tx.RCT.Type) != f.RCTType || len(tx.Inputs) != f.Inputs || len(tx.Outputs) != f.Outputs {
				t.Fatalf("type/in/out = %d/%d/%d, want %d/%d/%d",
					tx.RCT.Type, len(tx.Inputs), len(tx.Outputs), f.RCTType, f.Inputs, f.Outputs)
			}
			if tx.IsCoinbase() != f.Coinbase {
				t.Fatalf("IsCoinbase = %v", tx.IsCoinbase())
			}
			if !f.Coinbase {
				for i, ring := range f.Rings {
					abs := tx.Inputs[i].AbsoluteOffsets()
					if len(abs) != len(ring) {
						t.Fatalf("input %d: ring size %d, fixture %d", i, len(abs), len(ring))
					}
					for j := range abs {
						if abs[j] != ring[j].Index {
							t.Fatalf("input %d member %d: index %d, fixture %d", i, j, abs[j], ring[j].Index)
						}
					}
				}
			}
		})
	}
}

// Every strict prefix of a valid transaction must fail to parse, as must any
// trailing byte.
func TestTruncationAndTrailing(t *testing.T) {
	for _, f := range testvectors.LoadChainFixtures(t) {
		raw := mustHex(t, f.Hex)
		for n := 0; n < len(raw); n++ {
			if _, err := Parse(raw[:n]); err == nil {
				t.Fatalf("%s: prefix of %d/%d bytes parsed", f.Name, n, len(raw))
			}
		}
		if _, err := Parse(append(append([]byte{}, raw...), 0)); err == nil {
			t.Fatalf("%s: trailing byte accepted", f.Name)
		}
	}
}

func TestRejectsBadVersion(t *testing.T) {
	raw := mustHex(t, testvectors.LoadChainFixtures(t)[0].Hex)
	for _, v := range []byte{0, 3} {
		bad := append([]byte{v}, raw[1:]...)
		if _, err := Parse(bad); err == nil {
			t.Errorf("version %d accepted", v)
		}
	}
	v1 := append([]byte{1}, raw[1:]...)
	if _, err := Parse(v1); !errors.Is(err, ErrUnsupported) {
		t.Errorf("version 1: err = %v", err)
	}
}

func TestRejectsNonCanonicalVarint(t *testing.T) {
	raw := mustHex(t, testvectors.LoadChainFixtures(t)[0].Hex)
	// version 2 encoded as 0x82 0x00
	bad := append([]byte{0x82, 0x00}, raw[1:]...)
	if _, err := Parse(bad); err == nil {
		t.Fatal("non-canonical version varint accepted")
	}
}

func TestSignatureHashDiffersFromTxHash(t *testing.T) {
	for _, f := range testvectors.LoadChainFixtures(t) {
		if f.Coinbase {
			continue
		}
		tx, err := Parse(mustHex(t, f.Hex))
		if err != nil {
			t.Fatal(err)
		}
		sh, err := tx.SignatureHash()
		if err != nil {
			t.Fatal(err)
		}
		h, _ := tx.Hash()
		if sh == h || sh == ([32]byte{}) {
			t.Fatalf("%s: suspicious signature hash %x", f.Name, sh)
		}
	}
}

func FuzzParse(f *testing.F) {
	for _, c := range testvectors.LoadChainFixtures(f) {
		f.Add(mustHex(f, c.Hex))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		tx, err := Parse(b)
		if err != nil {
			return
		}
		out, err := tx.Serialize()
		if err != nil {
			t.Fatalf("parsed but cannot serialize: %v", err)
		}
		if !bytes.Equal(out, b) {
			t.Fatalf("round trip differs")
		}
		if _, err := tx.Hash(); err != nil {
			t.Fatal(err)
		}
	})
}
