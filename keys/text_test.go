package keys

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestJSONHex(t *testing.T) {
	acct := AccountKeys{Spend: SecretKey{1, 2}, View: SecretKey{3}}
	b, err := json.Marshal(acct)
	if err != nil {
		t.Fatal(err)
	}
	var back AccountKeys
	if err := json.Unmarshal(b, &back); err != nil || back != acct {
		t.Fatalf("round trip: %v %v", back, err)
	}
	if err := json.Unmarshal([]byte(`{"Spend":"00"}`), &back); err == nil {
		t.Fatal("short key accepted")
	}
	if s := fmt.Sprintf("%v %+v %#v %s", acct.Spend, acct, acct, acct.Spend); strings.Contains(s, "0102") {
		t.Fatalf("secret leaked by formatting: %s", s)
	}
}
