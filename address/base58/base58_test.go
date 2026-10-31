package base58

import (
	"bytes"
	"encoding/hex"
	"strconv"
	"testing"

	"github.com/sina-haseli/monergo/internal/testvectors"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The tables below are monero tests/unit_tests/base58.cpp, extracted into
// internal/testvectors/data/base58_unit_tests.json.

func TestUpstreamEncodeBlock(t *testing.T) {
	v := testvectors.LoadBase58UnitTests(t)
	for _, c := range v.EncodeBlock {
		data := mustHex(t, c.Data)
		res := make([]byte, encodedBlockSizes[len(data)])
		for i := range res {
			res[i] = alphabet[0]
		}
		encodeBlock(data, res)
		if string(res) != c.Enc {
			t.Errorf("encodeBlock(%x) = %s, want %s", data, res, c.Enc)
		}
	}
	if len(v.EncodeBlock) == 0 {
		t.Fatal("no cases")
	}
}

func TestUpstreamDecodeBlock(t *testing.T) {
	v := testvectors.LoadBase58UnitTests(t)
	for _, c := range v.DecodeBlockPos {
		want := mustHex(t, c.Data)
		got := make([]byte, len(want))
		if !decodeBlock([]byte(c.Enc), got) || !bytes.Equal(got, want) {
			t.Errorf("decodeBlock(%s) = %x, want %x", c.Enc, got, want)
		}
	}
	for _, c := range v.DecodeBlockNeg {
		out := make([]byte, fullBlockSize)
		if decodeBlock([]byte(c.Enc), out) {
			t.Errorf("decodeBlock(%s) succeeded", c.Enc)
		}
	}
	if len(v.DecodeBlockPos) == 0 || len(v.DecodeBlockNeg) == 0 {
		t.Fatal("no cases")
	}
}

func TestUpstreamEncodeDecode(t *testing.T) {
	v := testvectors.LoadBase58UnitTests(t)
	for _, c := range v.Encode {
		if got := Encode(mustHex(t, c.Data)); got != c.Enc {
			t.Errorf("Encode(%s) = %s, want %s", c.Data, got, c.Enc)
		}
	}
	for _, c := range v.DecodePos {
		got, err := Decode(c.Enc)
		if err != nil || !bytes.Equal(got, mustHex(t, c.Data)) {
			t.Errorf("Decode(%s) = %x, %v; want %s", c.Enc, got, err, c.Data)
		}
	}
	for _, c := range v.DecodeNeg {
		if _, err := Decode(c.Enc); err == nil {
			t.Errorf("Decode(%s) succeeded", c.Enc)
		}
	}
	t.Logf("encode %d, decode_pos %d, decode_neg %d", len(v.Encode), len(v.DecodePos), len(v.DecodeNeg))
}

func TestUpstreamAddr(t *testing.T) {
	v := testvectors.LoadBase58UnitTests(t)
	for _, c := range v.EncodeDecodeAddr {
		tag, err := strconv.ParseUint(c.Tag, 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		data := mustHex(t, c.Data)
		if got := EncodeAddr(tag, data); got != c.Addr {
			t.Errorf("EncodeAddr(%d, %x) = %s, want %s", tag, data, got, c.Addr)
		}
		gotTag, gotData, err := DecodeAddr(c.Addr)
		if err != nil || gotTag != tag || !bytes.Equal(gotData, data) {
			t.Errorf("DecodeAddr(%s) = %d, %x, %v", c.Addr, gotTag, gotData, err)
		}
	}
	for _, c := range v.DecodeAddrNeg {
		if _, _, err := DecodeAddr(string(mustHex(t, c.AddrHex))); err == nil {
			t.Errorf("%s: DecodeAddr succeeded", c.Name)
		}
	}
	t.Logf("encode_decode_addr %d, decode_addr_neg %d", len(v.EncodeDecodeAddr), len(v.DecodeAddrNeg))
}

func FuzzDecode(f *testing.F) {
	f.Add("jpXCZedGfVQ5Q")
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		b, err := Decode(s)
		if err != nil {
			return
		}
		if Encode(b) != s {
			t.Fatalf("Decode(%q) = %x does not re-encode", s, b)
		}
	})
}

func FuzzDecodeAddr(f *testing.F) {
	f.Add("21rhHRT48LN4PriP9")
	f.Fuzz(func(t *testing.T, s string) {
		tag, data, err := DecodeAddr(s)
		if err != nil {
			return
		}
		if EncodeAddr(tag, data) != s {
			t.Fatalf("DecodeAddr(%q) does not re-encode", s)
		}
	})
}
