package decoy

import (
	"crypto/rand"
	"errors"
	"math"
	"testing"
)

// A synthetic chain of 400k blocks with 40 RingCT outputs each.
func chain(blocks int, perBlock uint64) []uint64 {
	offs := make([]uint64, blocks)
	var acc uint64
	for i := range offs {
		acc += perBlock
		offs[i] = acc
	}
	return offs
}

func TestSelect(t *testing.T) {
	offs := chain(400000, 40)
	real := uint64(15_000_000)
	ring, pos, err := Select(rand.Reader, offs, real, 16)
	if err != nil {
		t.Fatal(err)
	}
	if len(ring) != 16 || ring[pos] != real {
		t.Fatalf("ring %v, pos %d", ring, pos)
	}
	for i := 1; i < len(ring); i++ {
		if ring[i] <= ring[i-1] {
			t.Fatalf("ring not strictly increasing: %v", ring)
		}
	}
	locked := offs[len(offs)-1] - offs[len(offs)-defaultTxSpendableAge]
	for _, g := range ring {
		if g >= offs[len(offs)-1]-locked {
			t.Fatalf("picked a locked output %d", g)
		}
	}
}

// The gamma picker favors recent outputs: about half the picks are younger
// than ~1.8 days (median of exp(Gamma(19.28, 1/1.61)) seconds).
func TestPickDistribution(t *testing.T) {
	offs := chain(400000, 40)
	p, err := NewPicker(rand.Reader, offs)
	if err != nil {
		t.Fatal(err)
	}
	const n = 20000
	tip := p.numRctOutputs
	recent, bad := 0, 0
	threshold := uint64(1.8 * 86400 / p.averageOutputTime)
	for i := 0; i < n; i++ {
		g := p.Pick()
		if g == badPick {
			bad++
			continue
		}
		if tip-g < threshold {
			recent++
		}
	}
	frac := float64(recent) / float64(n-bad)
	if math.Abs(frac-0.5) > 0.08 {
		t.Fatalf("%.3f of picks are recent, want about 0.5", frac)
	}
	t.Logf("recent fraction %.3f, bad picks %d/%d", frac, bad, n)
}

func TestGammaMoments(t *testing.T) {
	p, _ := NewPicker(rand.Reader, chain(100, 10))
	const n = 50000
	var sum, sumSq float64
	for i := 0; i < n; i++ {
		x := p.gamma(gammaShape, gammaScale)
		sum += x
		sumSq += x * x
	}
	mean := sum / n
	variance := sumSq/n - mean*mean
	if wantMean := gammaShape * gammaScale; math.Abs(mean-wantMean) > 0.05 {
		t.Fatalf("mean %.4f, want %.4f", mean, wantMean)
	}
	if wantVar := gammaShape * gammaScale * gammaScale; math.Abs(variance-wantVar)/wantVar > 0.05 {
		t.Fatalf("variance %.4f, want %.4f", variance, wantVar)
	}
}

func TestRejects(t *testing.T) {
	if _, err := NewPicker(rand.Reader, chain(5, 1)); err == nil {
		t.Error("short distribution accepted")
	}
	if _, _, err := Select(rand.Reader, chain(20, 1), 2, 16); err == nil {
		t.Error("tiny chain filled a ring of 16")
	}
	if _, _, err := Select(rand.Reader, chain(1000, 10), 1e9, 16); err == nil {
		t.Error("real output beyond the distribution accepted")
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("no entropy") }

func TestSelectReportsRNGFailure(t *testing.T) {
	if _, _, err := Select(failingReader{}, chain(1000, 10), 5000, 16); err == nil {
		t.Fatal("RNG failure not reported")
	}
}
