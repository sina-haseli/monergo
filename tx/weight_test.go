package tx

import (
	"testing"

	"github.com/sina-haseli/monergo/internal/testvectors"
)

// Weights as computed by monero-oxide (tools/oxide-check) for the chain fixtures.
var oxideWeights = map[string]uint64{
	"mainnet_bpp_1in_2out": 1536,
	"mainnet_bpp_2in_2out": 2222,
	"mainnet_bpp_many_in":  8384,
	"mainnet_bpp_16_out":   13058,
	"mainnet_bpp_3_out":    2913,
	"mainnet_clsag_type5":  1449,
	"stagenet_bpp":         2198,
}

func TestWeightMatchesOxide(t *testing.T) {
	for _, f := range testvectors.LoadChainFixtures(t) {
		want, ok := oxideWeights[f.Name]
		if !ok {
			continue
		}
		parsed, err := Parse(mustHex(t, f.Hex))
		if err != nil {
			t.Fatal(err)
		}
		got, err := parsed.Weight()
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("%s: weight %d, oxide %d", f.Name, got, want)
		}
	}
}
