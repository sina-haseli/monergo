// Copyright (c) 2014-2026, The Monero Project
// Copyright (c) 2026, The monergo Authors
// SPDX-License-Identifier: BSD-3-Clause

package tx

import (
	"github.com/sina-haseli/monergo/internal/varint"
)

// reader is a minimal binary_archive<false>: it fails on any short read and never
// allocates more than the remaining input can justify.
type reader struct {
	b   []byte
	pos int
}

func (r *reader) remaining() int { return len(r.b) - r.pos }

func (r *reader) byte() (byte, error) {
	if r.remaining() < 1 {
		return 0, ErrTruncated
	}
	c := r.b[r.pos]
	r.pos++
	return c, nil
}

func (r *reader) varint() (uint64, error) {
	v, n, err := varint.Read(r.b[r.pos:])
	if err != nil {
		if err == varint.ErrTruncated {
			return 0, ErrTruncated
		}
		return 0, err
	}
	r.pos += n
	return v, nil
}

func (r *reader) key() ([32]byte, error) {
	var k [32]byte
	if r.remaining() < 32 {
		return k, ErrTruncated
	}
	copy(k[:], r.b[r.pos:])
	r.pos += 32
	return k, nil
}

func (r *reader) bytes(n int) ([]byte, error) {
	if n < 0 || r.remaining() < n {
		return nil, ErrTruncated
	}
	out := append([]byte(nil), r.b[r.pos:r.pos+n]...)
	r.pos += n
	return out, nil
}

// count reads a varint element count and checks that the remaining input could
// hold that many elements of at least minSize bytes each (upstream checks
// remaining_bytes before reserving).
func (r *reader) count(minSize int) (int, error) {
	n, err := r.varint()
	if err != nil {
		return 0, err
	}
	if minSize < 1 {
		minSize = 1
	}
	if n > uint64(r.remaining()/minSize) {
		return 0, ErrTruncated
	}
	return int(n), nil
}

func (r *reader) keyVector() ([][32]byte, error) {
	n, err := r.count(32)
	if err != nil {
		return nil, err
	}
	return r.keys(n)
}

func (r *reader) keys(n int) ([][32]byte, error) {
	if n > r.remaining()/32 {
		return nil, ErrTruncated
	}
	out := make([][32]byte, n)
	for i := range out {
		out[i], _ = r.key()
	}
	return out, nil
}

type writer struct{ b []byte }

func (w *writer) byte(c byte)     { w.b = append(w.b, c) }
func (w *writer) varint(v uint64) { w.b = varint.Append(w.b, v) }
func (w *writer) key(k [32]byte)  { w.b = append(w.b, k[:]...) }
func (w *writer) bytes(b []byte)  { w.b = append(w.b, b...) }
func (w *writer) keys(ks [][32]byte) {
	for _, k := range ks {
		w.key(k)
	}
}
func (w *writer) keyVector(ks [][32]byte) {
	w.varint(uint64(len(ks)))
	w.keys(ks)
}
