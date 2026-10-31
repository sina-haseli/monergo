package protocol

import (
	"encoding/json"
	"testing"
)

func TestNetworkJSONRoundTrip(t *testing.T) {
	for _, n := range Networks {
		b, err := json.Marshal(n)
		if err != nil {
			t.Fatal(err)
		}
		var back Network
		if err := json.Unmarshal(b, &back); err != nil || back != n {
			t.Fatalf("%s: round trip gave %v, %v", n, back, err)
		}
	}
	var n Network
	if err := json.Unmarshal([]byte(`"regtest"`), &n); err == nil {
		t.Fatal("accepted unknown network")
	}
}

func TestPrefixesDistinct(t *testing.T) {
	seen := map[uint64]bool{}
	for _, n := range Networks {
		p := n.Prefixes()
		for _, v := range []uint64{p.Standard, p.Integrated, p.Subaddress} {
			if seen[v] {
				t.Fatalf("duplicate prefix %d", v)
			}
			seen[v] = true
		}
	}
}

func TestRulesForCurrentHardFork(t *testing.T) {
	r, err := RulesFor(CurrentHardFork)
	if err != nil {
		t.Fatal(err)
	}
	if r.RingSize != 16 || r.MinOutputs != 2 || !r.ViewTags || r.RCTType != 6 {
		t.Fatalf("unexpected rules %+v", r)
	}
	for _, hf := range []uint8{15, 17} {
		if _, err := RulesFor(hf); err == nil {
			t.Errorf("hard fork %d accepted", hf)
		}
	}
}
