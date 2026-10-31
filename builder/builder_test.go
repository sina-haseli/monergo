package builder

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	mrand "math/rand/v2"
	"testing"

	"filippo.io/edwards25519"
	"github.com/sina-haseli/monergo/address"
	"github.com/sina-haseli/monergo/keys"
	"github.com/sina-haseli/monergo/primitives"
	"github.com/sina-haseli/monergo/protocol"
	"github.com/sina-haseli/monergo/ringct"
	"github.com/sina-haseli/monergo/scan"
	"github.com/sina-haseli/monergo/tx"
)

func randAccount(t testing.TB) keys.AccountKeys {
	s, err := primitives.RandomScalar(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return keys.AccountFromRecoveryKey([32]byte(s.Bytes()))
}

func randKey(t testing.TB) keys.PublicKey {
	s, _ := primitives.RandomScalar(rand.Reader)
	return keys.PublicKey(new(edwards25519.Point).ScalarBaseMult(s).Bytes())
}

// receive creates an Input spending a fresh output of amount sent to acct at idx,
// built the way a sender would, with 15 random decoys.
func receive(t testing.TB, acct keys.AccountKeys, idx keys.SubaddressIndex, amount uint64, coinbase bool) Input {
	t.Helper()
	D, C, err := acct.SubaddressPublicKeys(idx)
	if err != nil {
		t.Fatal(err)
	}
	rs, _ := primitives.RandomScalar(rand.Reader)
	r := keys.SecretKey(rs.Bytes())
	txPub, _ := r.PublicKey()
	if !idx.IsZero() {
		txPub = keys.PublicKey(new(edwards25519.Point).ScalarMult(rs, mustPoint(t, D)).Bytes())
	}
	outIndex := uint64(mrand.IntN(3))
	der, err := keys.GenerateKeyDerivation(C, r)
	if err != nil {
		t.Fatal(err)
	}
	outKey, err := keys.DerivePublicKey(der, outIndex, D)
	if err != nil {
		t.Fatal(err)
	}
	var commitment ringct.Key
	if coinbase {
		commitment = ringct.ZeroCommit(amount)
	} else {
		ak := keys.DerivationToScalar(der, outIndex)
		commitment = ringct.Key(ringct.Commit(amount, ringct.GenCommitmentMask(ringct.Key(ak.Bytes()))).Bytes())
	}
	in := Input{
		TxPubKey: txPub, OutputIndex: outIndex, OutputKey: outKey, Amount: amount,
		Coinbase: coinbase, Subaddress: idx, RealIndex: mrand.IntN(16),
	}
	g := uint64(1000 + mrand.IntN(1000000))
	for j := 0; j < 16; j++ {
		g += 1 + uint64(mrand.IntN(5000))
		m := RingMember{GlobalIndex: g, Key: randKey(t), Commitment: randKey(t)}
		if j == in.RealIndex {
			m.Key, m.Commitment = outKey, commitment
		}
		in.Ring = append(in.Ring, m)
	}
	return in
}

func mustPoint(t testing.TB, k keys.PublicKey) *edwards25519.Point {
	p, err := primitives.DecodePoint(k)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func addr(t testing.TB, acct keys.AccountKeys, idx keys.SubaddressIndex) string {
	a, err := address.FromAccount(protocol.Stagenet, acct, idx)
	if err != nil {
		t.Fatal(err)
	}
	return a.String()
}

func baseRequest(inputs []Input, dests []Destination) TransferRequest {
	return TransferRequest{
		Network: protocol.Stagenet, Inputs: inputs, Destinations: dests,
		FeePerByte: 20000, FeeQuantizationMask: 10000, MaxFee: 1e10,
	}
}

type found struct {
	amount uint64
	idx    keys.SubaddressIndex
}

// scanAs returns every output of signed tx that acct owns, decrypting amounts and
// checking each commitment.
func scanAs(t testing.TB, acct keys.AccountKeys, parsed *tx.Transaction) []found {
	t.Helper()
	table, err := scan.NewSubaddressTable(acct, 3, 10)
	if err != nil {
		t.Fatal(err)
	}
	fields, err := tx.ParseExtra(parsed.Extra)
	if err != nil {
		t.Fatal(err)
	}
	txPub, ok := tx.TxPubKey(fields)
	if !ok {
		t.Fatal("no tx pubkey")
	}
	var add []keys.PublicKey
	for _, k := range tx.AdditionalPubKeys(fields) {
		add = append(add, keys.PublicKey(k))
	}
	var out []found
	for i, o := range parsed.Outputs {
		tag := keys.ViewTag(o.ViewTag)
		opened, err := scan.Open(acct, table, scan.Output{
			TxPubKey: keys.PublicKey(txPub), AdditionalTxPubKeys: add,
			OutputIndex: uint64(i), OutputKey: o.Key, ViewTag: &tag,
		})
		if errors.Is(err, scan.ErrNotOwned) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		amount := ringct.DecryptAmount(parsed.RCT.EcdhAmounts[i], opened.AmountKey)
		if ringct.Key(ringct.Commit(amount, opened.Mask()).Bytes()) != parsed.RCT.OutPk[i] {
			t.Fatalf("output %d: decrypted amount does not open its commitment", i)
		}
		out = append(out, found{amount, opened.Subaddress})
	}
	return out
}

func signAndParse(t testing.TB, acct keys.AccountKeys, req TransferRequest) (*Signed, *tx.Transaction) {
	t.Helper()
	s, err := SignWithRand(rand.Reader, acct, req)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := hex.DecodeString(s.TxHex)
	parsed, err := tx.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return s, parsed
}

func TestSendToStandardWithChange(t *testing.T) {
	me, bob := randAccount(t), randAccount(t)
	ins := []Input{receive(t, me, keys.SubaddressIndex{}, 5e12, false), receive(t, me, keys.SubaddressIndex{Minor: 3}, 2e12, false)}
	req := baseRequest(ins, []Destination{{addr(t, bob, keys.SubaddressIndex{}), 3e12}})
	s, parsed := signAndParse(t, me, req)

	if len(parsed.Outputs) != 2 || len(parsed.Inputs) != 2 {
		t.Fatalf("shape %d in / %d out", len(parsed.Inputs), len(parsed.Outputs))
	}
	if s.Fee == 0 || s.Fee%10000 != 0 || s.Fee != parsed.RCT.Fee {
		t.Fatalf("fee %d (tx %d)", s.Fee, parsed.RCT.Fee)
	}
	if need, _ := feeFromWeight(20000, s.Weight, 10000); need != s.Fee {
		t.Fatalf("fee %d, weight %d needs %d", s.Fee, s.Weight, need)
	}
	if got := scanAs(t, bob, parsed); len(got) != 1 || got[0].amount != 3e12 {
		t.Fatalf("bob sees %+v", got)
	}
	got := scanAs(t, me, parsed)
	if len(got) != 1 || got[0].amount != 4e12-s.Fee || got[0].idx != (keys.SubaddressIndex{}) || s.Change != got[0].amount {
		t.Fatalf("change %+v, fee %d", got, s.Fee)
	}
	// Standard destination + change: no additional keys, a dummy encrypted payment ID.
	fields, _ := tx.ParseExtra(parsed.Extra)
	if tx.AdditionalPubKeys(fields) != nil {
		t.Fatal("unexpected additional keys")
	}
	if _, ok := tx.EncryptedPaymentID(fields); !ok {
		t.Fatal("missing dummy encrypted payment ID")
	}
	// Inputs sorted by key image, descending.
	if bytes.Compare(parsed.Inputs[0].KeyImage[:], parsed.Inputs[1].KeyImage[:]) <= 0 {
		t.Fatal("inputs not sorted")
	}
	// The returned key images are the inputs' key images.
	if s.KeyImages[0] != parsed.Inputs[0].KeyImage {
		t.Fatal("key images")
	}
}

func TestSendToSubaddresses(t *testing.T) {
	me, bob, carol := randAccount(t), randAccount(t), randAccount(t)
	ins := []Input{receive(t, me, keys.SubaddressIndex{}, 9e12, false)}

	// Single subaddress destination: R = r·D, no additional keys.
	req := baseRequest(ins, []Destination{{addr(t, bob, keys.SubaddressIndex{Minor: 2}), 1e12}})
	_, parsed := signAndParse(t, me, req)
	fields, _ := tx.ParseExtra(parsed.Extra)
	if tx.AdditionalPubKeys(fields) != nil {
		t.Fatal("single subaddress destination must not use additional keys")
	}
	if got := scanAs(t, bob, parsed); len(got) != 1 || got[0].amount != 1e12 || got[0].idx.Minor != 2 {
		t.Fatalf("bob sees %+v", got)
	}

	// Subaddress + standard destinations: one additional key per output.
	req = baseRequest(ins, []Destination{
		{addr(t, bob, keys.SubaddressIndex{Major: 1, Minor: 1}), 1e12},
		{addr(t, carol, keys.SubaddressIndex{}), 2e12},
	})
	s, parsed := signAndParse(t, me, req)
	fields, _ = tx.ParseExtra(parsed.Extra)
	if n := len(tx.AdditionalPubKeys(fields)); n != len(parsed.Outputs) || n != 3 {
		t.Fatalf("%d additional keys for %d outputs", n, len(parsed.Outputs))
	}
	if len(s.AdditionalTxKeys) != 3 {
		t.Fatalf("%d additional tx keys returned", len(s.AdditionalTxKeys))
	}
	if got := scanAs(t, bob, parsed); len(got) != 1 || got[0].amount != 1e12 {
		t.Fatalf("bob sees %+v", got)
	}
	if got := scanAs(t, carol, parsed); len(got) != 1 || got[0].amount != 2e12 {
		t.Fatalf("carol sees %+v", got)
	}
	if got := scanAs(t, me, parsed); len(got) != 1 || got[0].amount != 6e12-s.Fee {
		t.Fatalf("change %+v", got)
	}
	// Three outputs: no dummy payment ID.
	if _, ok := tx.EncryptedPaymentID(fields); ok {
		t.Fatal("unexpected payment ID nonce with 3 outputs")
	}
}

func TestIntegratedAddressPaymentID(t *testing.T) {
	me, bob := randAccount(t), randAccount(t)
	ins := []Input{receive(t, me, keys.SubaddressIndex{}, 9e12, false)}
	primary, _ := address.FromAccount(protocol.Stagenet, bob, keys.SubaddressIndex{})
	pid := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	integ, _ := primary.WithPaymentID(pid)
	_, parsed := signAndParse(t, me, baseRequest(ins, []Destination{{integ.String(), 1e12}}))
	fields, _ := tx.ParseExtra(parsed.Extra)
	enc, ok := tx.EncryptedPaymentID(fields)
	if !ok {
		t.Fatal("no encrypted payment ID")
	}
	// Bob decrypts with 8·b·R (encrypt_payment_id is an XOR).
	txPub, _ := tx.TxPubKey(fields)
	dec, err := encryptPaymentID(enc, keys.PublicKey(txPub), bob.View)
	if err != nil || dec != pid {
		t.Fatalf("decrypted %x, want %x", dec, pid)
	}
	if got := scanAs(t, bob, parsed); len(got) != 1 || got[0].amount != 1e12 {
		t.Fatalf("bob sees %+v", got)
	}
}

// Spending everything to one destination adds a 0-amount output to a random
// address, as wallet2 does, so the transaction still has 2 outputs.
func TestExactAmountAddsDummyOutput(t *testing.T) {
	me, bob := randAccount(t), randAccount(t)
	in := receive(t, me, keys.SubaddressIndex{}, 2e12, false)
	req := baseRequest([]Input{in}, []Destination{{addr(t, bob, keys.SubaddressIndex{}), 1e12}})
	probe, _ := signAndParse(t, me, req)
	// Resend exactly amount - fee.
	req.Destinations[0].Amount = 2e12 - probe.Fee
	s, parsed := signAndParse(t, me, req)
	if s.Fee != probe.Fee || s.Change != 0 {
		t.Fatalf("fee %d (probe %d), change %d", s.Fee, probe.Fee, s.Change)
	}
	if len(parsed.Outputs) != 2 {
		t.Fatalf("%d outputs", len(parsed.Outputs))
	}
	if got := scanAs(t, me, parsed); len(got) != 0 {
		t.Fatalf("sender owns the dummy output: %+v", got)
	}
	if got := scanAs(t, bob, parsed); len(got) != 1 || got[0].amount != 2e12-s.Fee {
		t.Fatalf("bob sees %+v", got)
	}
}

func TestCoinbaseInputAndChangeSubaddress(t *testing.T) {
	me, bob := randAccount(t), randAccount(t)
	ins := []Input{receive(t, me, keys.SubaddressIndex{}, 6e11, true)}
	req := baseRequest(ins, []Destination{{addr(t, bob, keys.SubaddressIndex{}), 1e11}})
	idx := keys.SubaddressIndex{Minor: 7}
	req.ChangeSubaddress = &idx
	s, parsed := signAndParse(t, me, req)
	if got := scanAs(t, me, parsed); len(got) != 1 || got[0].idx != idx || got[0].amount != 5e11-s.Fee {
		t.Fatalf("change %+v", got)
	}
}

func TestSixteenOutputs(t *testing.T) {
	me := randAccount(t)
	ins := []Input{receive(t, me, keys.SubaddressIndex{}, 1e13, false)}
	var dests []Destination
	for i := 0; i < 15; i++ {
		dests = append(dests, Destination{addr(t, randAccount(t), keys.SubaddressIndex{}), 1e9})
	}
	_, parsed := signAndParse(t, me, baseRequest(ins, dests))
	if len(parsed.Outputs) != 16 {
		t.Fatalf("%d outputs", len(parsed.Outputs))
	}
	dests = append(dests, Destination{addr(t, randAccount(t), keys.SubaddressIndex{}), 1e9})
	if _, err := SignWithRand(rand.Reader, me, baseRequest(ins, dests)); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("17 outputs: err = %v", err)
	}
}

func TestRejections(t *testing.T) {
	me, bob := randAccount(t), randAccount(t)
	good := receive(t, me, keys.SubaddressIndex{}, 5e12, false)
	dest := []Destination{{addr(t, bob, keys.SubaddressIndex{}), 1e12}}
	clone := func(in Input) Input {
		in.Ring = append([]RingMember{}, in.Ring...)
		return in
	}
	cases := []struct {
		name string
		mut  func(r *TransferRequest)
		want error
	}{
		{"foreign output", func(r *TransferRequest) {
			r.Inputs[0] = receive(t, bob, keys.SubaddressIndex{}, 5e12, false)
		}, ErrInputNotOwned},
		{"wrong amount", func(r *TransferRequest) { r.Inputs[0].Amount++ }, ErrInputNotOwned},
		{"wrong subaddress", func(r *TransferRequest) { r.Inputs[0].Subaddress.Minor = 1 }, ErrInputNotOwned},
		{"coinbase flag on rct output", func(r *TransferRequest) { r.Inputs[0].Coinbase = true }, ErrInputNotOwned},
		{"real index elsewhere", func(r *TransferRequest) { r.Inputs[0].RealIndex = (r.Inputs[0].RealIndex + 1) % 16 }, ErrInputNotOwned},
		{"ring of 15", func(r *TransferRequest) { r.Inputs[0].Ring = r.Inputs[0].Ring[:15] }, ErrInvalidRequest},
		{"unsorted ring", func(r *TransferRequest) {
			r.Inputs[0].Ring[0].GlobalIndex, r.Inputs[0].Ring[1].GlobalIndex = r.Inputs[0].Ring[1].GlobalIndex, r.Inputs[0].Ring[0].GlobalIndex
		}, ErrInvalidRequest},
		{"duplicate input", func(r *TransferRequest) { r.Inputs = append(r.Inputs, clone(r.Inputs[0])) }, ErrInvalidRequest},
		{"zero destination amount", func(r *TransferRequest) { r.Destinations[0].Amount = 0 }, ErrInvalidRequest},
		{"amount overflow", func(r *TransferRequest) {
			r.Destinations = append(r.Destinations, Destination{r.Destinations[0].Address, ^uint64(0)})
		}, ErrInvalidRequest},
		{"insufficient funds", func(r *TransferRequest) { r.Destinations[0].Amount = 5e12 }, ErrInsufficientFunds},
		{"fee above cap", func(r *TransferRequest) { r.MaxFee = 1 }, ErrFeeTooHigh},
		{"wrong network", func(r *TransferRequest) { r.Network = protocol.Mainnet }, ErrInvalidRequest},
		{"unsupported hard fork", func(r *TransferRequest) { r.HardFork = 17 }, ErrInvalidRequest},
		{"no fee rate", func(r *TransferRequest) { r.FeePerByte = 0 }, ErrInvalidRequest},
		{"inputs from two accounts", func(r *TransferRequest) {
			r.Inputs = append(r.Inputs, receive(t, me, keys.SubaddressIndex{Major: 1}, 1e12, false))
		}, ErrInvalidRequest},
	}
	for _, c := range cases {
		req := baseRequest([]Input{clone(good)}, append([]Destination{}, dest...))
		c.mut(&req)
		if _, err := SignWithRand(rand.Reader, me, req); !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
		}
	}
}

// The request round-trips through JSON (the Vault plugin interface).
func TestRequestJSON(t *testing.T) {
	me, bob := randAccount(t), randAccount(t)
	req := baseRequest([]Input{receive(t, me, keys.SubaddressIndex{Minor: 1}, 5e12, false)},
		[]Destination{{addr(t, bob, keys.SubaddressIndex{}), 1e12}})
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	var back TransferRequest
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Sign(me, back); err != nil {
		t.Fatal(err)
	}
}

func BenchmarkSign1in2out(b *testing.B) {
	me, bob := randAccount(b), randAccount(b)
	req := baseRequest([]Input{receive(b, me, keys.SubaddressIndex{}, 5e12, false)},
		[]Destination{{addr(b, bob, keys.SubaddressIndex{}), 1e12}})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := Sign(me, req); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSign4in16out(b *testing.B) {
	me := randAccount(b)
	var ins []Input
	for i := 0; i < 4; i++ {
		ins = append(ins, receive(b, me, keys.SubaddressIndex{}, 5e12, false))
	}
	var dests []Destination
	for i := 0; i < 15; i++ {
		dests = append(dests, Destination{addr(b, randAccount(b), keys.SubaddressIndex{}), 1e9})
	}
	req := baseRequest(ins, dests)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := Sign(me, req); err != nil {
			b.Fatal(err)
		}
	}
}

// TestExtraLayoutMatchesWallet2: the tx_extra layouts are the ones real wallet2
// transactions use (see the chain fixtures): two outputs give pubkey + 9-byte
// encrypted payment ID nonce (44 bytes), more give pubkey [+ additional keys].
func TestExtraLayoutMatchesWallet2(t *testing.T) {
	me := randAccount(t)
	ins := []Input{receive(t, me, keys.SubaddressIndex{}, 9e12, false)}
	_, p := signAndParse(t, me, baseRequest(ins, []Destination{{addr(t, randAccount(t), keys.SubaddressIndex{}), 1e12}}))
	if len(p.Extra) != 44 || p.Extra[0] != tx.ExtraTagPubKey || p.Extra[33] != tx.ExtraTagNonce || p.Extra[34] != 9 || p.Extra[35] != tx.ExtraNonceEncryptedPaymentID {
		t.Fatalf("2-output extra layout: %x", p.Extra)
	}
	_, p = signAndParse(t, me, baseRequest(ins, []Destination{
		{addr(t, randAccount(t), keys.SubaddressIndex{Minor: 1}), 1e12},
		{addr(t, randAccount(t), keys.SubaddressIndex{}), 1e12},
	}))
	if len(p.Extra) != 33+2+32*3 || p.Extra[33] != tx.ExtraTagAdditionalPubKeys {
		t.Fatalf("3-output subaddress extra layout: %d bytes", len(p.Extra))
	}
	_, p = signAndParse(t, me, baseRequest(ins, []Destination{
		{addr(t, randAccount(t), keys.SubaddressIndex{}), 1e12},
		{addr(t, randAccount(t), keys.SubaddressIndex{}), 1e12},
	}))
	if len(p.Extra) != 33 {
		t.Fatalf("3-output standard extra layout: %d bytes", len(p.Extra))
	}
}
