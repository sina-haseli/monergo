// Copyright (c) 2014-2026, The Monero Project
// Copyright (c) 2026, The monergo Authors
// SPDX-License-Identifier: BSD-3-Clause

// Package seed implements Monero's 25-word mnemonic ("electrum words") for the
// English word list.
//
// Ported from monero src/mnemonics/electrum-words.cpp
// @3fd0f88c20f559839cafb20911cb13cb45eba7bd.
package seed

import (
	"encoding/binary"
	"errors"
	"hash/crc32"
	"strings"

	"github.com/sina-haseli/monergo/keys"
)

var (
	// ErrWordCount is returned for anything other than 24 or 25 words.
	ErrWordCount = errors.New("seed: want 25 words (or 24 without checksum)")
	// ErrUnknownWord is returned when a word is not in the English list.
	ErrUnknownWord = errors.New("seed: word not in the English word list")
	// ErrChecksum is returned when the checksum word does not match.
	ErrChecksum = errors.New("seed: invalid checksum word")
	// ErrInvalid is upstream's "mumble mumble": the word triple encodes no uint32.
	ErrInvalid = errors.New("seed: invalid word sequence")
)

const wordListLength = uint32(len(englishWords))

var (
	wordMap    = map[string]uint32{}
	trimmedMap = map[string]uint32{}
)

func init() {
	// Ported from monero src/mnemonics/language_base.h: Base::populate_maps.
	for i, w := range englishWords {
		wordMap[w] = uint32(i)
		t := utf8Prefix(w, englishUniquePrefixLength)
		if _, dup := trimmedMap[t]; dup {
			panic("seed: duplicate prefix " + t)
		}
		trimmedMap[t] = uint32(i)
	}
}

// utf8Prefix returns the first count UTF-8 characters of s.
//
// Ported from monero src/mnemonics/language_base.h: utf8prefix.
func utf8Prefix(s string, count int) string {
	i := 0
	for count > 0 && i < len(s) {
		i++
		for i < len(s) && s[i]&0xc0 == 0x80 {
			i++
		}
		count--
	}
	return s[:i]
}

// canonical lower-cases ASCII letters. Upstream lower-cases with towlower; the
// English list is pure ASCII, so non-ASCII input can never match either way. Only
// ASCII is folded here, so exotic case mappings (for example U+212A KELVIN SIGN to
// 'k') are rejected rather than accepted.
func canonical(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

// split splits on ASCII whitespace (std::isspace in the C locale).
//
// Ported from monero contrib/epee/src/wipeable_string.cpp: wipeable_string::split.
func split(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		switch r {
		case ' ', '\t', '\n', '\v', '\f', '\r':
			return true
		}
		return false
	})
}

// checksumIndex returns CRC32 of the concatenated unique prefixes, mod len(words).
//
// Ported from monero src/mnemonics/electrum-words.cpp: create_checksum_index.
func checksumIndex(words []string) (uint32, error) {
	var b strings.Builder
	for _, w := range words {
		t := canonical(utf8Prefix(w, englishUniquePrefixLength))
		i, ok := trimmedMap[t]
		if !ok {
			return 0, ErrUnknownWord
		}
		b.WriteString(utf8Prefix(englishWords[i], englishUniquePrefixLength))
	}
	return crc32.ChecksumIEEE([]byte(b.String())) % uint32(len(words)), nil
}

// Encode returns the 25-word English mnemonic for a 32-byte key.
//
// Ported from monero src/mnemonics/electrum-words.cpp: bytes_to_words.
func Encode(key keys.SecretKey) (string, error) {
	words := make([]string, 0, 25)
	for i := 0; i < len(key)/4; i++ {
		w0 := binary.LittleEndian.Uint32(key[i*4:])
		w1 := w0 % wordListLength
		w2 := ((w0 / wordListLength) + w1) % wordListLength
		w3 := (((w0 / wordListLength) / wordListLength) + w2) % wordListLength
		words = append(words, englishWords[w1], englishWords[w2], englishWords[w3])
	}
	idx, err := checksumIndex(words)
	if err != nil {
		return "", err
	}
	words = append(words, words[idx])
	return strings.Join(words, " "), nil
}

// Decode returns the 32-byte key encoded by a 25-word mnemonic (words matched by
// their 3-letter prefix, checksum verified) or a 24-word mnemonic (exact words, no
// checksum). Matching is case-insensitive.
//
// Ported from monero src/mnemonics/electrum-words.cpp: words_to_bytes (len = 32),
// find_seed_language and checksum_test. Only English is supported. Upstream's
// 12-word path never yields 32 bytes, so 12 words are rejected here too.
func Decode(mnemonic string) ([32]byte, error) {
	var out [32]byte
	words := split(mnemonic)
	const expected = 32 * 8 * 3 / 32 // 24
	if len(words) != expected && len(words) != expected+1 {
		return out, ErrWordCount
	}
	hasChecksum := len(words) == expected+1

	indices := make([]uint32, len(words))
	defer clear(indices)
	for i, w := range words {
		var (
			idx uint32
			ok  bool
		)
		if hasChecksum {
			idx, ok = trimmedMap[canonical(utf8Prefix(w, englishUniquePrefixLength))]
		} else {
			idx, ok = wordMap[canonical(w)]
		}
		if !ok {
			return out, ErrUnknownWord
		}
		indices[i] = idx
	}

	if hasChecksum {
		idx, err := checksumIndex(words[:expected])
		if err != nil {
			return out, err
		}
		got := canonical(utf8Prefix(words[expected], englishUniquePrefixLength))
		want := canonical(utf8Prefix(words[idx], englishUniquePrefixLength))
		if got != want {
			return out, ErrChecksum
		}
	}

	n := wordListLength
	for i := 0; i < expected/3; i++ {
		w1, w2, w3 := indices[i*3], indices[i*3+1], indices[i*3+2]
		// uint32 arithmetic wraps exactly as upstream's does.
		w0 := w1 + n*(((n-w1)+w2)%n) + n*n*(((n-w2)+w3)%n)
		if w0%n != w1 {
			clear(out[:])
			return out, ErrInvalid
		}
		binary.LittleEndian.PutUint32(out[i*4:], w0)
	}
	return out, nil
}
