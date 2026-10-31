// Copyright (c) 2014-2026, The Monero Project
// Copyright (c) 2026, The monergo Authors
// SPDX-License-Identifier: BSD-3-Clause

// Package decoy selects ring members with wallet2's gamma distribution, given the
// output distribution the caller fetched from a daemon
// (get_output_distribution, amount 0, cumulative). It needs no network access
// itself.
//
// Ported from monero src/wallet/wallet2.cpp @3fd0f88: gamma_picker. The gamma
// variates come from Marsaglia–Tsang sampling on crypto/rand rather than
// std::gamma_distribution, whose algorithm is implementation-defined: the
// distribution is the same, the individual draws are not.
package decoy

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"sort"
)

// Constants from monero src/wallet/wallet2.cpp and src/cryptonote_config.h.
const (
	gammaShape                   = 19.28
	gammaScale                   = 1 / 1.61
	difficultyTargetV2           = 120 // DIFFICULTY_TARGET_V2
	defaultTxSpendableAge        = 10  // CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE
	defaultUnlockTime            = defaultTxSpendableAge * difficultyTargetV2
	recentSpendWindow            = 15 * difficultyTargetV2
	badPick               uint64 = math.MaxUint64
)

var (
	// ErrBadDistribution is returned for a distribution too short to pick from.
	ErrBadDistribution = errors.New("decoy: bad output distribution")
	// ErrNotEnoughOutputs is returned when the chain has too few outputs for the ring.
	ErrNotEnoughOutputs = errors.New("decoy: not enough outputs to fill the ring")
)

// Picker draws global output indices.
type Picker struct {
	rng               io.Reader
	rctOffsets        []uint64
	end               int // rctOffsets[:end] holds the unlocked blocks
	numRctOutputs     uint64
	averageOutputTime float64
}

// NewPicker returns a picker over rctOffsets, the cumulative number of RingCT
// outputs at the end of each block (get_output_distribution with cumulative=true).
//
// Ported from monero src/wallet/wallet2.cpp: gamma_picker::gamma_picker.
func NewPicker(rng io.Reader, rctOffsets []uint64) (*Picker, error) {
	if len(rctOffsets) < defaultTxSpendableAge {
		return nil, ErrBadDistribution // "Bad offset calculation"
	}
	const blocksInAYear = 86400 * 365 / difficultyTargetV2
	blocksToConsider := len(rctOffsets)
	if blocksToConsider > blocksInAYear {
		blocksToConsider = blocksInAYear
	}
	outputsToConsider := rctOffsets[len(rctOffsets)-1]
	if blocksToConsider < len(rctOffsets) {
		outputsToConsider -= rctOffsets[len(rctOffsets)-blocksToConsider-1]
	}
	p := &Picker{rng: rng, rctOffsets: rctOffsets, end: len(rctOffsets) - (defaultTxSpendableAge - 1)}
	p.numRctOutputs = rctOffsets[p.end-1]
	if p.numRctOutputs == 0 || outputsToConsider == 0 {
		return nil, ErrBadDistribution // "No rct outputs" / "No outputs in consideration window"
	}
	// "this assumes constant target over the whole rct range"
	p.averageOutputTime = difficultyTargetV2 * float64(blocksToConsider) / float64(outputsToConsider)
	return p, nil
}

func (p *Picker) uint64() uint64 {
	var b [8]byte
	if _, err := io.ReadFull(p.rng, b[:]); err != nil {
		panic(err)
	}
	return binary.LittleEndian.Uint64(b[:])
}

// randIdx is crypto::rand_idx: uniform in [0, n).
func (p *Picker) randIdx(n uint64) uint64 {
	limit := math.MaxUint64 - math.MaxUint64%n
	for {
		if v := p.uint64(); v < limit {
			return v % n
		}
	}
}

func (p *Picker) unit() float64 { return float64(p.uint64()>>11) / (1 << 53) }

func (p *Picker) normal() float64 {
	// Box–Muller
	u1 := p.unit()
	for u1 == 0 {
		u1 = p.unit()
	}
	return math.Sqrt(-2*math.Log(u1)) * math.Cos(2*math.Pi*p.unit())
}

// gamma draws from Gamma(shape, scale) by Marsaglia–Tsang (shape >= 1).
func (p *Picker) gamma(shape, scale float64) float64 {
	d := shape - 1.0/3
	c := 1 / math.Sqrt(9*d)
	for {
		x := p.normal()
		v := 1 + c*x
		if v <= 0 {
			continue
		}
		v = v * v * v
		u := p.unit()
		if u < 1-0.0331*x*x*x*x || math.Log(u) < 0.5*x*x+d*(1-v+math.Log(v)) {
			return d * v * scale
		}
	}
}

// Pick returns one global output index, or math.MaxUint64 for a bad pick (which
// the caller discards).
//
// Ported from monero src/wallet/wallet2.cpp: gamma_picker::pick.
func (p *Picker) Pick() uint64 {
	x := math.Exp(p.gamma(gammaShape, gammaScale))
	if x > defaultUnlockTime {
		x -= defaultUnlockTime
	} else {
		x = float64(p.randIdx(recentSpendWindow))
	}
	outputIndex := uint64(x / p.averageOutputTime)
	if outputIndex >= p.numRctOutputs {
		return badPick
	}
	outputIndex = p.numRctOutputs - 1 - outputIndex
	// lower_bound over rctOffsets[:end]
	idx := sort.Search(p.end, func(i int) bool { return p.rctOffsets[i] >= outputIndex })
	if idx == p.end {
		return badPick // upstream throws "output_index not found"
	}
	var first uint64
	if idx > 0 {
		first = p.rctOffsets[idx-1]
	}
	n := p.rctOffsets[idx] - first
	if n == 0 {
		return badPick
	}
	return first + p.randIdx(n)
}

// Select returns a sorted ring of ringSize global indices containing real, with
// ringSize-1 distinct gamma-picked decoys, and the position of real in it.
//
// This is a simplification of wallet2::get_outs: it does not fetch extra outputs
// to replace locked or blacklisted ones. Callers should fetch the picked outputs
// with /get_outs and retry any that are not unlocked.
func Select(rng io.Reader, rctOffsets []uint64, real uint64, ringSize int) ([]uint64, int, error) {
	if rng == nil {
		rng = rand.Reader
	}
	p, err := NewPicker(rng, rctOffsets)
	if err != nil {
		return nil, 0, err
	}
	if real >= p.numRctOutputs {
		return nil, 0, errors.New("decoy: real output is not unlocked in this distribution")
	}
	if p.numRctOutputs < uint64(ringSize) {
		return nil, 0, ErrNotEnoughOutputs
	}
	picked := map[uint64]bool{real: true}
	for attempts := 0; len(picked) < ringSize; attempts++ {
		if attempts > 100*ringSize+1000 {
			return nil, 0, ErrNotEnoughOutputs
		}
		if i := p.Pick(); i != badPick {
			picked[i] = true
		}
	}
	ring := make([]uint64, 0, ringSize)
	for i := range picked {
		ring = append(ring, i)
	}
	sort.Slice(ring, func(a, b int) bool { return ring[a] < ring[b] })
	pos := sort.Search(len(ring), func(i int) bool { return ring[i] >= real })
	return ring, pos, nil
}
