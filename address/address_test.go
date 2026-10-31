package address

import (
	"encoding/hex"
	"errors"
	"testing"

	"github.com/sina-haseli/monergo/address/base58"
	"github.com/sina-haseli/monergo/internal/testvectors"
	"github.com/sina-haseli/monergo/keys"
	"github.com/sina-haseli/monergo/protocol"
)

func secret(t *testing.T, s string) keys.SecretKey {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		t.Fatalf("bad key %q", s)
	}
	return keys.SecretKey(b)
}

// TestWalletFixtures derives every address the official wallet reported, and parses
// each one back.
func TestWalletFixtures(t *testing.T) {
	f := testvectors.LoadWalletFixtures(t)
	n := 0
	for netName, wallets := range f.Networks {
		net, err := protocol.ParseNetwork(netName)
		if err != nil {
			t.Fatal(err)
		}
		for _, w := range wallets {
			acct := keys.AccountKeys{Spend: secret(t, w.SpendKey), View: secret(t, w.ViewKey)}
			for _, want := range w.Addresses {
				idx := keys.SubaddressIndex{Major: want.Major, Minor: want.Minor}
				a, err := FromAccount(net, acct, idx)
				if err != nil {
					t.Fatal(err)
				}
				if got := a.String(); got != want.Address {
					t.Errorf("%s %v: got %s, want %s", netName, idx, got, want.Address)
				}
				parsed, err := Parse(want.Address, net)
				if err != nil {
					t.Fatalf("%s %v: Parse: %v", netName, idx, err)
				}
				if parsed != a {
					t.Errorf("%s %v: Parse = %+v, want %+v", netName, idx, parsed, a)
				}
				if wantKind := map[bool]Kind{true: Standard, false: Subaddress}[idx.IsZero()]; parsed.Kind != wantKind {
					t.Errorf("%s %v: kind %v", netName, idx, parsed.Kind)
				}
				n++
			}
			pid, _ := hex.DecodeString(w.Integrated.PaymentID)
			primary, _ := FromAccount(net, acct, keys.SubaddressIndex{})
			integ, err := primary.WithPaymentID([8]byte(pid))
			if err != nil {
				t.Fatal(err)
			}
			if got := integ.String(); got != w.Integrated.Address {
				t.Errorf("%s integrated: got %s, want %s", netName, got, w.Integrated.Address)
			}
			parsed, err := Parse(w.Integrated.Address, net)
			if err != nil || parsed != integ || parsed.Kind != Integrated {
				t.Errorf("%s integrated: Parse = %+v, %v", netName, parsed, err)
			}
			n++
		}
	}
	t.Logf("checked %d addresses from monero-wallet-rpc v%d", n, f.WalletRPCVersion)
}

func TestParseRejectsWrongNetwork(t *testing.T) {
	f := testvectors.LoadWalletFixtures(t)
	mainAddr := f.Networks["mainnet"][0].Addresses[0].Address
	if _, err := Parse(mainAddr, protocol.Stagenet); !errors.Is(err, ErrWrongNetwork) {
		t.Fatalf("err = %v", err)
	}
	a, err := ParseAny(mainAddr)
	if err != nil || a.Network != protocol.Mainnet {
		t.Fatalf("ParseAny = %+v, %v", a, err)
	}
}

// Ported from monero tests/unit_tests/base58.cpp: the get_account_address_* tests.
var testSerializedKeys, _ = hex.DecodeString(
	"f724bc5c6cfbb9d97602c300423a2f28641874513a035778a0c1778d833201e9" +
		"220939689edf1abd5bc1d031f73ecd6c993add66d6808870456afeb8e7eeb68d")

const testKeysAddrStr = "4AzKEX4gXdJdNeM6dfiBFL7kqund3HYGvMBF3ttsNd9SfzgYB6L7ep1Yg1osYJzLdaKAYSLVh6e6jKnAuzj3bw1oGy9kXCb"

func TestUpstreamGetAccountAddress(t *testing.T) {
	a := Address{Network: protocol.Mainnet, Kind: Standard,
		Spend: keys.PublicKey(testSerializedKeys[:32]), View: keys.PublicKey(testSerializedKeys[32:])}
	if a.String() != testKeysAddrStr {
		t.Fatalf("works_correctly: got %s", a.String())
	}
	got, err := Parse(testKeysAddrStr, protocol.Mainnet)
	if err != nil || got != a {
		t.Fatalf("handles_valid_address: %+v %v", got, err)
	}
	bad := []byte(testKeysAddrStr)
	bad[0] = '0'
	if _, err := Parse(string(bad), protocol.Mainnet); err == nil {
		t.Error("fails_on_invalid_address_format")
	}
	if _, err := Parse(base58.EncodeAddr(0, testSerializedKeys), protocol.Mainnet); err == nil {
		t.Error("fails_on_invalid_address_prefix")
	}
	if _, err := Parse(base58.EncodeAddr(18, testSerializedKeys[1:]), protocol.Mainnet); err == nil {
		t.Error("fails_on_invalid_address_content")
	}
	spendBad := append([]byte{}, testSerializedKeys...)
	spendBad[0] = 0
	if _, err := Parse(base58.EncodeAddr(18, spendBad), protocol.Mainnet); err == nil {
		t.Error("fails_on_invalid_address_spend_key")
	}
	viewBad := append([]byte{}, testSerializedKeys...)
	viewBad[63] = 1
	if _, err := Parse(base58.EncodeAddr(18, viewBad), protocol.Mainnet); err == nil {
		t.Error("fails_on_invalid_address_view_key")
	}
}

// check_address rejects the identity and keys with a torsion component.
func TestParseRejectsIdentityAndTorsion(t *testing.T) {
	var ident [32]byte
	ident[0] = 1
	torsion, _ := hex.DecodeString("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05")
	good := testSerializedKeys[32:]
	for name, spend := range map[string][]byte{"identity": ident[:], "torsion": torsion} {
		data := append(append([]byte{}, spend...), good...)
		if _, err := Parse(base58.EncodeAddr(18, data), protocol.Mainnet); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestParseRejectsTrailingBytes(t *testing.T) {
	data := append(append([]byte{}, testSerializedKeys...), 0)
	if _, err := Parse(base58.EncodeAddr(18, data), protocol.Mainnet); err == nil {
		t.Fatal("accepted 65-byte standard address")
	}
}

func TestWithPaymentIDOnlyFromStandard(t *testing.T) {
	a := Address{Network: protocol.Mainnet, Kind: Subaddress}
	if _, err := a.WithPaymentID([8]byte{}); err == nil {
		t.Fatal("integrated subaddress allowed")
	}
}

func FuzzParse(f *testing.F) {
	f.Add(testKeysAddrStr)
	f.Fuzz(func(t *testing.T, s string) {
		a, err := ParseAny(s)
		if err != nil {
			return
		}
		if a.String() != s {
			t.Fatalf("%q does not re-encode", s)
		}
	})
}
