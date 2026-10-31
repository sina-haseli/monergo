package builder

import (
	"encoding/hex"
	"fmt"
	"sort"
	"testing"

	"github.com/sina-haseli/monergo/address"
	"github.com/sina-haseli/monergo/internal/oxidecheck"
	"github.com/sina-haseli/monergo/internal/testvectors"
	"github.com/sina-haseli/monergo/keys"
	"github.com/sina-haseli/monergo/protocol"
)

type wantOut struct {
	amount       uint64
	major, minor uint32
	paymentID    string // hex, "" for none, anyPID for "present, any value"
}

// anyPID: the sender sees the payment ID encrypted to the recipient's view key, so
// decrypting it with the sender's own key gives arbitrary bytes (as in wallet2).
const anyPID = "*"

type scanCase struct {
	name  string
	acct  keys.AccountKeys
	txHex string
	want  []wantOut
}

func minerTxHex(t *testing.T) string {
	for _, f := range testvectors.LoadChainFixtures(t) {
		if f.Name == "stagenet_coinbase" {
			return f.Hex
		}
	}
	t.Fatal("no coinbase fixture")
	return ""
}

func viewPairScan(acct keys.AccountKeys, txHex, miner string) oxidecheck.Scan {
	spend, _ := acct.Spend.PublicKey()
	s := oxidecheck.Scan{TxHex: txHex, MinerTxHex: miner, SpendPub: spend.String(), ViewSec: hex.EncodeToString(acct.View[:])}
	for major := uint32(0); major < 3; major++ {
		for minor := uint32(0); minor < 10; minor++ {
			s.Subaddresses = append(s.Subaddresses, [2]uint32{major, minor})
		}
	}
	return s
}

// TestOxideWalletScansBuiltTransactions: monero-oxide's wallet Scanner, an independent
// implementation of output detection, finds exactly the outputs we meant for each
// recipient (and the sender's change), with the right amounts, subaddresses and
// payment IDs. This checks output keys, view tags, tx/additional keys, amount
// encryption and payment ID encryption.
func TestOxideWalletScansBuiltTransactions(t *testing.T) {
	miner := minerTxHex(t)
	me, bob, carol := randAccount(t), randAccount(t), randAccount(t)
	var cases []scanCase
	sign := func(req TransferRequest) *Signed {
		s, err := SignWithRand(randReader(), me, req)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	fund := func(n int) []Input {
		var ins []Input
		for i := 0; i < n; i++ {
			ins = append(ins, receive(t, me, keys.SubaddressIndex{Minor: uint32(i)}, 4e12, false))
		}
		return ins
	}

	// Standard destination + change (dummy encrypted payment ID of zeros).
	s := sign(baseRequest(fund(1), []Destination{{addr(t, bob, keys.SubaddressIndex{}), 1e12}}))
	cases = append(cases,
		scanCase{"std: bob", bob, s.TxHex, []wantOut{{1e12, 0, 0, "0000000000000000"}}},
		scanCase{"std: change", me, s.TxHex, []wantOut{{s.Change, 0, 0, anyPID}}},
	)

	// Integrated address.
	primary, _ := address.FromAccount(protocol.Stagenet, bob, keys.SubaddressIndex{})
	integ, _ := primary.WithPaymentID([8]byte{0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4})
	s = sign(baseRequest(fund(2), []Destination{{integ.String(), 2e12}}))
	cases = append(cases,
		scanCase{"integrated: bob", bob, s.TxHex, []wantOut{{2e12, 0, 0, "deadbeef01020304"}}},
		scanCase{"integrated: change", me, s.TxHex, []wantOut{{s.Change, 0, 0, anyPID}}},
	)

	// Single subaddress destination (R = r·D), change to a subaddress.
	req := baseRequest(fund(1), []Destination{{addr(t, bob, keys.SubaddressIndex{Major: 2, Minor: 5}), 1e12}})
	ch := keys.SubaddressIndex{Minor: 9}
	req.ChangeSubaddress = &ch
	s = sign(req)
	cases = append(cases,
		scanCase{"subaddress: bob", bob, s.TxHex, []wantOut{{1e12, 2, 5, "0000000000000000"}}},
		scanCase{"subaddress: change", me, s.TxHex, []wantOut{{s.Change, 0, 9, anyPID}}},
	)

	// Subaddress + standard: additional tx keys.
	s = sign(baseRequest(fund(3), []Destination{
		{addr(t, bob, keys.SubaddressIndex{Minor: 1}), 1e12},
		{addr(t, carol, keys.SubaddressIndex{}), 2e12},
		{addr(t, carol, keys.SubaddressIndex{Major: 1, Minor: 3}), 3e11},
	}))
	cases = append(cases,
		scanCase{"additional: bob", bob, s.TxHex, []wantOut{{1e12, 0, 1, ""}}},
		scanCase{"additional: carol", carol, s.TxHex, []wantOut{{3e11, 1, 3, ""}, {2e12, 0, 0, ""}}},
		scanCase{"additional: change", me, s.TxHex, []wantOut{{s.Change, 0, 0, ""}}},
	)

	// Exact amount: dummy 0-amount output that nobody owns.
	in := receive(t, me, keys.SubaddressIndex{}, 2e12, false)
	probe := sign(baseRequest([]Input{in}, []Destination{{addr(t, bob, keys.SubaddressIndex{}), 1e12}}))
	s = sign(baseRequest([]Input{in}, []Destination{{addr(t, bob, keys.SubaddressIndex{}), 2e12 - probe.Fee}}))
	cases = append(cases,
		scanCase{"exact: bob", bob, s.TxHex, []wantOut{{2e12 - probe.Fee, 0, 0, "0000000000000000"}}},
		scanCase{"exact: sender owns nothing", me, s.TxHex, nil},
	)

	// 15 destinations + change.
	var dests []Destination
	var bobWant []wantOut
	for i := 0; i < 15; i++ {
		idx := keys.SubaddressIndex{Minor: uint32(i % 4)}
		dests = append(dests, Destination{addr(t, bob, idx), uint64(1e9 + i)})
		bobWant = append(bobWant, wantOut{uint64(1e9 + i), 0, idx.Minor, ""})
	}
	s = sign(baseRequest(fund(1), dests))
	cases = append(cases, scanCase{"16 outputs: bob", bob, s.TxHex, bobWant})

	var scans []oxidecheck.Scan
	for _, c := range cases {
		scans = append(scans, viewPairScan(c.acct, c.txHex, miner))
	}
	for i, res := range oxidecheck.RunScans(t, scans) {
		c := cases[i]
		if res.Error != "" {
			t.Fatalf("%s: oxide scan error: %s", c.name, res.Error)
		}
		var got []wantOut
		for j, o := range res.Outputs {
			pid := o.PaymentID
			if j < len(c.want) && c.want[0].paymentID == anyPID && len(pid) == 16 {
				pid = anyPID
			}
			got = append(got, wantOut{o.Amount, o.Major, o.Minor, pid})
		}
		norm := func(w []wantOut) string {
			s := make([]string, len(w))
			for i, o := range w {
				s[i] = fmt.Sprintf("%d@%d/%d#%s", o.amount, o.major, o.minor, o.paymentID)
			}
			sort.Strings(s)
			return fmt.Sprint(s)
		}
		if norm(got) != norm(c.want) {
			t.Errorf("%s: oxide wallet found %s, want %s", c.name, norm(got), norm(c.want))
		} else {
			t.Logf("%s: oxide wallet agrees: %s", c.name, norm(got))
		}
	}
}
