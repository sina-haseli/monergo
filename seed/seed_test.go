package seed

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/sina-haseli/monergo/internal/testvectors"
	"github.com/sina-haseli/monergo/keys"
)

// TestWalletFixtures round-trips every seed the official wallet restored: the words
// decode to the wallet's spend key, the derived view key matches, and encoding the
// spend key gives back the wallet's mnemonic.
func TestWalletFixtures(t *testing.T) {
	f := testvectors.LoadWalletFixtures(t)
	n := 0
	for net, wallets := range f.Networks {
		for _, w := range wallets {
			raw, err := Decode(w.Seed)
			if err != nil {
				t.Fatalf("%s: Decode: %v", net, err)
			}
			acct := keys.AccountFromRecoveryKey(raw)
			if hex.EncodeToString(acct.Spend[:]) != w.SpendKey {
				t.Errorf("%s: spend key %x, want %s", net, acct.Spend, w.SpendKey)
			}
			if hex.EncodeToString(acct.View[:]) != w.ViewKey {
				t.Errorf("%s: view key %x, want %s", net, acct.View, w.ViewKey)
			}
			words, err := Encode(acct.Spend)
			if err != nil {
				t.Fatal(err)
			}
			if words != w.Mnemonic {
				t.Errorf("%s: Encode = %q, want %q", net, words, w.Mnemonic)
			}
			n++
		}
	}
	t.Logf("round-tripped %d wallet seeds", n)
}

func fixtureSeed(t *testing.T) (string, [32]byte) {
	f := testvectors.LoadWalletFixtures(t)
	w := f.Networks["mainnet"][0]
	b, _ := hex.DecodeString(w.SpendKey)
	return w.Seed, [32]byte(b)
}

// Upstream matches words by their unique prefix (3 for English), case-insensitively,
// when the seed has a checksum word.
func TestPrefixAndCase(t *testing.T) {
	seed, want := fixtureSeed(t)
	words := strings.Fields(seed)
	for i := range words {
		words[i] = strings.ToUpper(words[i][:3]) + "zzz"
	}
	got, err := Decode("  " + strings.Join(words, " \t\n ") + "\r\n")
	if err != nil || got != want {
		t.Fatalf("prefix/upper-case seed: %x, %v", got, err)
	}
}

// A 24-word seed has no checksum; upstream then requires exact words.
func TestTwentyFourWords(t *testing.T) {
	seed, want := fixtureSeed(t)
	words := strings.Fields(seed)
	got, err := Decode(strings.Join(words[:24], " "))
	if err != nil || got != want {
		t.Fatalf("24 words: %x, %v", got, err)
	}
	words[0] = words[0][:3]
	if _, err := Decode(strings.Join(words[:24], " ")); err == nil {
		t.Fatal("24-word seed accepted a prefix")
	}
}

func TestRejects(t *testing.T) {
	seed, _ := fixtureSeed(t)
	words := strings.Fields(seed)

	bad := append([]string{}, words...)
	bad[24] = "abbey"
	if bad[24][:3] == words[24][:3] {
		t.Fatal("test setup: pick another checksum word")
	}
	if _, err := Decode(strings.Join(bad, " ")); !errors.Is(err, ErrChecksum) {
		t.Errorf("bad checksum: err = %v", err)
	}

	unknown := append([]string{}, words...)
	unknown[3] = "qqqq"
	if _, err := Decode(strings.Join(unknown, " ")); !errors.Is(err, ErrUnknownWord) {
		t.Errorf("unknown word: err = %v", err)
	}

	for _, n := range []int{0, 12, 13, 23, 26} {
		if _, err := Decode(strings.Join(append(words, words...)[:n], " ")); !errors.Is(err, ErrWordCount) {
			t.Errorf("%d words: err = %v", n, err)
		}
	}
}

func FuzzRoundTrip(f *testing.F) {
	f.Add(make([]byte, 32))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) != 32 {
			return
		}
		key := [32]byte(b)
		words, err := Encode(keys.SecretKey(key))
		if err != nil {
			t.Fatal(err)
		}
		got, err := Decode(words)
		if err != nil || got != key {
			t.Fatalf("round trip %x: %x, %v", key, got, err)
		}
	})
}

func FuzzDecode(f *testing.F) {
	f.Add("velvet lymph giddy")
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = Decode(s)
	})
}
