package varint

import (
	"bytes"
	"errors"
	"math"
	"testing"
)

func TestAppendKnownEncodings(t *testing.T) {
	cases := []struct {
		v    uint64
		want []byte
	}{
		{0, []byte{0x00}},
		{1, []byte{0x01}},
		{0x7f, []byte{0x7f}},
		{0x80, []byte{0x80, 0x01}},
		{300, []byte{0xac, 0x02}},
		{16383, []byte{0xff, 0x7f}},
		{16384, []byte{0x80, 0x80, 0x01}},
		{math.MaxUint64, []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01}},
	}
	for _, c := range cases {
		got := Append(nil, c.v)
		if !bytes.Equal(got, c.want) {
			t.Errorf("Append(%d) = %x, want %x", c.v, got, c.want)
		}
		v, n, err := Read(c.want)
		if err != nil || v != c.v || n != len(c.want) {
			t.Errorf("Read(%x) = %d, %d, %v; want %d, %d, nil", c.want, v, n, err, c.v, len(c.want))
		}
	}
}

func TestReadRejects(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want error
	}{
		{"empty", nil, ErrTruncated},
		{"truncated", []byte{0x80}, ErrTruncated},
		{"non-minimal", []byte{0x80, 0x00}, ErrNonCanonical},
		{"non-minimal-long", []byte{0xff, 0x80, 0x00}, ErrNonCanonical},
		{"overflow-10th-byte", []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02}, ErrOverflow},
		{"overflow-11-bytes", []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x81, 0x01}, ErrOverflow},
	}
	for _, c := range cases {
		if _, _, err := Read(c.in); !errors.Is(err, c.want) {
			t.Errorf("%s: Read(%x) err = %v, want %v", c.name, c.in, err, c.want)
		}
	}
}

func TestReadStopsAtTerminator(t *testing.T) {
	v, n, err := Read([]byte{0xac, 0x02, 0xff})
	if err != nil || v != 300 || n != 2 {
		t.Fatalf("got %d, %d, %v", v, n, err)
	}
}

func FuzzRoundTrip(f *testing.F) {
	f.Add(uint64(0))
	f.Add(uint64(math.MaxUint64))
	f.Fuzz(func(t *testing.T, v uint64) {
		b := Append(nil, v)
		got, n, err := Read(b)
		if err != nil || got != v || n != len(b) {
			t.Fatalf("round trip %d: %x -> %d, %d, %v", v, b, got, n, err)
		}
	})
}
