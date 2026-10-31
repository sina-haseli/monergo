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
