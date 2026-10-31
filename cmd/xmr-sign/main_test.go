package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/sina-haseli/monergo/address"
	"github.com/sina-haseli/monergo/builder"
	"github.com/sina-haseli/monergo/internal/fakechain"
	"github.com/sina-haseli/monergo/keys"
	"github.com/sina-haseli/monergo/protocol"
)

func TestRejectsBadPayloads(t *testing.T) {
	for name, in := range map[string]string{
		"not json":      "nope",
		"no keys":       `{"request": {}}`,
		"unknown field": `{"request": {}, "extra": 1}`,
		"bad request":   `{"keys": {"Spend": "` + strings.Repeat("00", 32) + `", "View": "` + strings.Repeat("00", 32) + `"}, "request": {"network": "stagenet"}}`,
	} {
		var out bytes.Buffer
		if err := run(strings.NewReader(in), &out, "", false); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestSignsAndHidesTxKeysByDefault(t *testing.T) {
	me, bob := fakechain.Account(), fakechain.Account()
	in, err := fakechain.Receive(me, keys.SubaddressIndex{}, 5e12)
	if err != nil {
		t.Fatal(err)
	}
	to, _ := address.FromAccount(protocol.Stagenet, bob, keys.SubaddressIndex{})
	payload, _ := json.Marshal(map[string]any{
		"keys": me,
		"request": builder.TransferRequest{
			Network: protocol.Stagenet, Inputs: []builder.Input{in},
			Destinations: []builder.Destination{{Address: to.String(), Amount: 1e12}},
			FeePerByte:   20000, FeeQuantizationMask: 10000, MaxFee: 1e10,
		},
	})
	for _, withKeys := range []bool{false, true} {
		var out bytes.Buffer
		if err := run(bytes.NewReader(payload), &out, "", withKeys); err != nil {
			t.Fatal(err)
		}
		var res builder.Signed
		if err := json.Unmarshal(out.Bytes(), &res); err != nil {
			t.Fatal(err)
		}
		if len(res.TxHex) == 0 || len(res.TxHash) != 64 {
			t.Fatalf("bad output %s", out.String())
		}
		if hasKey := res.TxKey != (keys.SecretKey{}); hasKey != withKeys {
			t.Fatalf("with-tx-keys=%v but tx key present=%v", withKeys, hasKey)
		}
	}
}
