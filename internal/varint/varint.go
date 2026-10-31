// Copyright (c) 2014-2026, The Monero Project
// Copyright (c) 2026, The monergo Authors
// SPDX-License-Identifier: BSD-3-Clause

// Package varint implements Monero's unsigned LEB128-style varints.
package varint

import "errors"

var (
	// ErrTruncated is returned when the input ends before the terminating byte.
	ErrTruncated = errors.New("varint: truncated")
	// ErrOverflow mirrors upstream EVARINT_OVERFLOW.
	ErrOverflow = errors.New("varint: overflows uint64")
	// ErrNonCanonical mirrors upstream EVARINT_REPRESENT (a zero byte after the first).
	ErrNonCanonical = errors.New("varint: non-canonical encoding")
)

// Append appends the varint encoding of v to dst.
//
// Ported from monero src/common/varint.h: tools::write_varint @3fd0f88.
func Append(dst []byte, v uint64) []byte {
	for v >= 0x80 {
		dst = append(dst, byte(v&0x7f)|0x80)
		v >>= 7
	}
	return append(dst, byte(v))
}

// Read decodes a varint from the start of b and returns the value and the number
// of bytes consumed.
//
// Ported from monero src/common/varint.h: tools::read_varint<64> @3fd0f88. Upstream
// returns the partial count on end of input and leaves the caller to notice; here
// that is an explicit ErrTruncated.
func Read(b []byte) (uint64, int, error) {
	const bits = 64
	var v uint64
	read := 0
	for shift := 0; ; shift += 7 {
		if read == len(b) {
			return 0, read, ErrTruncated
		}
		c := b[read]
		read++
		if shift+7 >= bits && int(c) >= 1<<(bits-shift) {
			return 0, read, ErrOverflow
		}
		if c == 0 && shift != 0 {
			return 0, read, ErrNonCanonical
		}
		v |= uint64(c&0x7f) << shift
		if c&0x80 == 0 {
			return v, read, nil
		}
	}
}
