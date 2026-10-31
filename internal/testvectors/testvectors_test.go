package testvectors

import (
	"sort"
	"testing"
)

// TestEveryTypeIsAccountedFor makes a new upstream vector type fail loudly instead
// of being silently ignored.
func TestEveryTypeIsAccountedFor(t *testing.T) {
	all, err := CryptoTests()
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, v := range all {
		counts[v.Type]++
	}
	var types []string
	for typ := range counts {
		types = append(types, typ)
	}
	sort.Strings(types)
	for _, typ := range types {
		pkg, impl := Implemented[typ]
		reason, skip := Skipped[typ]
		switch {
		case impl && skip:
			t.Errorf("%s is both implemented and skipped", typ)
		case impl:
			t.Logf("%-28s %5d  run in %s", typ, counts[typ], pkg)
		case skip:
			t.Logf("%-28s %5d  SKIPPED: %s", typ, counts[typ], reason)
		default:
			t.Errorf("unknown vector type %q (%d vectors): implement it or add it to Skipped", typ, counts[typ])
		}
	}
	for typ := range Implemented {
		if counts[typ] == 0 {
			t.Errorf("implemented type %q has no vectors", typ)
		}
	}
}
