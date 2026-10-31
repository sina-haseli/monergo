package tx

import (
	"bytes"
	"testing"

	"github.com/sina-haseli/monergo/internal/testvectors"
)

func TestExtraChainFixtures(t *testing.T) {
	sawAdditional := false
	for _, f := range testvectors.LoadChainFixtures(t) {
		tx, err := Parse(mustHex(t, f.Hex))
		if err != nil {
			t.Fatal(err)
		}
		fields, err := ParseExtra(tx.Extra)
		if err != nil {
			t.Fatalf("%s: %v", f.Name, err)
		}
		if _, ok := TxPubKey(fields); !ok {
			t.Fatalf("%s: no tx pubkey", f.Name)
		}
		if add := AdditionalPubKeys(fields); add != nil {
			sawAdditional = true
			if len(add) != len(tx.Outputs) {
				t.Fatalf("%s: %d additional keys for %d outputs", f.Name, len(add), len(tx.Outputs))
			}
			t.Logf("%s: %d additional tx keys", f.Name, len(add))
		}
		out, err := SerializeExtra(fields)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(out, tx.Extra) {
			t.Fatalf("%s: extra does not round-trip", f.Name)
		}
	}
	if !sawAdditional {
		t.Fatal("no fixture exercises additional tx keys")
	}
}

func TestExtraPadding(t *testing.T) {
	ok := append([]byte{0}, make([]byte, 254)...)
	f, err := ParseExtra(ok)
	if err != nil || len(f) != 1 || f[0].PaddingSize != 255 {
		t.Fatalf("255-byte padding: %+v %v", f, err)
	}
	if _, err := ParseExtra(append(ok, 0)); err == nil {
		t.Fatal("256-byte padding accepted")
	}
	if _, err := ParseExtra([]byte{0, 0, 1}); err == nil {
		t.Fatal("non-zero padding accepted")
	}
}

func TestExtraRejects(t *testing.T) {
	cases := map[string][]byte{
		"unknown tag":      {0x05},
		"short pubkey":     {0x01, 1, 2},
		"long nonce":       append([]byte{0x02, 0x80, 0x02}, make([]byte, 256)...),
		"short additional": {0x04, 0x02, 1},
	}
	for name, b := range cases {
		if _, err := ParseExtra(b); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func FuzzParseExtra(f *testing.F) {
	f.Add([]byte{0x01})
	f.Fuzz(func(t *testing.T, b []byte) {
		fields, err := ParseExtra(b)
		if err != nil {
			return
		}
		out, err := SerializeExtra(fields)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(out, b) {
			t.Fatalf("%x does not round-trip: %x", b, out)
		}
	})
}
