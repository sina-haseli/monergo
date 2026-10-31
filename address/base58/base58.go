// Copyright (c) 2014-2026, The Monero Project
// Copyright (c) 2026, The monergo Authors
// SPDX-License-Identifier: BSD-3-Clause

// Package base58 implements Monero's block-based base58: data is split into 8-byte
// blocks, each encoded to exactly 11 characters (a shorter final block uses a fixed
// shorter width). This is not Bitcoin base58.
//
// Ported from monero src/common/base58.cpp @3fd0f88c20f559839cafb20911cb13cb45eba7bd.
package base58

import (
	"encoding/binary"
	"errors"
	"math/bits"

	"github.com/sina-haseli/monergo/internal/varint"
	"github.com/sina-haseli/monergo/primitives"
)

const (
	alphabet         = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	alphabetSize     = uint64(len(alphabet))
	fullBlockSize    = 8
	fullEncodedSize  = 11
	addrChecksumSize = 4
)

var encodedBlockSizes = [fullBlockSize + 1]int{0, 2, 3, 5, 6, 7, 9, 10, 11}

// decodedBlockSizes maps an encoded block length to its decoded length, or -1.
var decodedBlockSizes = func() [fullEncodedSize + 1]int {
	var m [fullEncodedSize + 1]int
	for i := range m {
		m[i] = -1
	}
	for i, n := range encodedBlockSizes {
		m[n] = i
	}
	return m
}()

var reverseAlphabet = func() [256]int8 {
	var r [256]int8
	for i := range r {
		r[i] = -1
	}
	for i := 0; i < len(alphabet); i++ {
		r[alphabet[i]] = int8(i)
	}
	return r
}()

var (
	// ErrInvalid is returned for malformed base58 input.
	ErrInvalid = errors.New("base58: invalid encoding")
	// ErrChecksum is returned when an address checksum does not match.
	ErrChecksum = errors.New("base58: bad address checksum")
)

func uint8beTo64(data []byte) uint64 {
	var buf [8]byte
	copy(buf[8-len(data):], data)
	return binary.BigEndian.Uint64(buf[:])
}

func uint64To8be(num uint64, out []byte) {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], num)
	copy(out, buf[8-len(out):])
}

// encodeBlock writes the encoding of block (1..8 bytes) into res, which must be
// pre-filled with alphabet[0] and have length encodedBlockSizes[len(block)].
//
// Ported from monero src/common/base58.cpp: encode_block.
func encodeBlock(block []byte, res []byte) {
	num := uint8beTo64(block)
	i := encodedBlockSizes[len(block)] - 1
	for num > 0 {
		res[i] = alphabet[num%alphabetSize]
		num /= alphabetSize
		i--
	}
}

// decodeBlock decodes one encoded block into res (len = decoded size).
//
// Ported from monero src/common/base58.cpp: decode_block.
func decodeBlock(block []byte, res []byte) bool {
	if len(block) < 1 || len(block) > fullEncodedSize {
		return false
	}
	resSize := decodedBlockSizes[len(block)]
	if resSize <= 0 {
		return false // invalid block size
	}
	var resNum uint64
	order := uint64(1)
	for i := len(block) - 1; i >= 0; i-- {
		digit := reverseAlphabet[block[i]]
		if digit < 0 {
			return false // invalid symbol
		}
		hi, lo := bits.Mul64(order, uint64(digit))
		tmp, carry := bits.Add64(resNum, lo, 0)
		if carry != 0 || hi != 0 {
			return false // overflow
		}
		resNum = tmp
		order *= alphabetSize // only overflows after the last digit, where it is unused
	}
	if resSize < fullBlockSize && uint64(1)<<(8*resSize) <= resNum {
		return false // overflow
	}
	uint64To8be(resNum, res[:resSize])
	return true
}

// Encode encodes data.
//
// Ported from monero src/common/base58.cpp: encode.
func Encode(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	fullBlocks := len(data) / fullBlockSize
	lastSize := len(data) % fullBlockSize
	res := make([]byte, fullBlocks*fullEncodedSize+encodedBlockSizes[lastSize])
	for i := range res {
		res[i] = alphabet[0]
	}
	for i := 0; i < fullBlocks; i++ {
		encodeBlock(data[i*fullBlockSize:(i+1)*fullBlockSize], res[i*fullEncodedSize:])
	}
	if lastSize > 0 {
		encodeBlock(data[fullBlocks*fullBlockSize:], res[fullBlocks*fullEncodedSize:])
	}
	return string(res)
}

// Decode decodes enc.
//
// Ported from monero src/common/base58.cpp: decode.
func Decode(enc string) ([]byte, error) {
	if len(enc) == 0 {
		return []byte{}, nil
	}
	fullBlocks := len(enc) / fullEncodedSize
	lastSize := len(enc) % fullEncodedSize
	lastDecoded := decodedBlockSizes[lastSize]
	if lastDecoded < 0 {
		return nil, ErrInvalid // invalid length
	}
	data := make([]byte, fullBlocks*fullBlockSize+lastDecoded)
	for i := 0; i < fullBlocks; i++ {
		if !decodeBlock([]byte(enc[i*fullEncodedSize:(i+1)*fullEncodedSize]), data[i*fullBlockSize:]) {
			return nil, ErrInvalid
		}
	}
	if lastSize > 0 {
		if !decodeBlock([]byte(enc[fullBlocks*fullEncodedSize:]), data[fullBlocks*fullBlockSize:]) {
			return nil, ErrInvalid
		}
	}
	return data, nil
}

// EncodeAddr encodes varint(tag) ‖ data ‖ checksum, where the checksum is the first
// four bytes of Keccak-256 of the preceding bytes.
//
// Ported from monero src/common/base58.cpp: encode_addr.
func EncodeAddr(tag uint64, data []byte) string {
	buf := varint.Append(nil, tag)
	buf = append(buf, data...)
	h := primitives.Keccak256(buf)
	buf = append(buf, h[:addrChecksumSize]...)
	return Encode(buf)
}

// DecodeAddr reverses EncodeAddr, checking the checksum and the varint tag.
//
// Ported from monero src/common/base58.cpp: decode_addr.
func DecodeAddr(addr string) (tag uint64, data []byte, err error) {
	raw, err := Decode(addr)
	if err != nil {
		return 0, nil, err
	}
	if len(raw) <= addrChecksumSize {
		return 0, nil, ErrInvalid
	}
	body, checksum := raw[:len(raw)-addrChecksumSize], raw[len(raw)-addrChecksumSize:]
	h := primitives.Keccak256(body)
	if string(h[:addrChecksumSize]) != string(checksum) {
		return 0, nil, ErrChecksum
	}
	tag, n, err := varint.Read(body)
	if err != nil {
		return 0, nil, ErrInvalid
	}
	return tag, body[n:], nil
}
