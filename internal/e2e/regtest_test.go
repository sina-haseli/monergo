// Package e2e runs monergo against the official Monero daemon and wallet on a
// private regtest chain: coins are mined locally, so no funds are involved.
//
// Every transaction is built and signed by monergo, accepted (or rejected) by
// monerod's consensus code, mined, and then checked from the official wallet's
// side: the recipient sees the amount (and payment ID), and the sender's wallet
// sees the spend and its change.
//
// The test is skipped unless MONERGO_MONEROD and MONERGO_WALLET_RPC name the
// monerod and monero-wallet-rpc binaries (v0.18.5.4 or newer). See
// docs/regtest-e2e.md.
package e2e

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/sina-haseli/monergo/builder"
	"github.com/sina-haseli/monergo/internal/prepare"
	"github.com/sina-haseli/monergo/keys"
	"github.com/sina-haseli/monergo/protocol"
)

const xmr = 1_000_000_000_000

var rpc prepare.Client

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

func start(t *testing.T, name string, bin string, args ...string) {
	t.Helper()
	dir := os.Getenv("MONERGO_E2E_LOGDIR") // keep the logs after the test
	if dir == "" {
		dir = t.TempDir()
	}
	logf, err := os.Create(filepath.Join(dir, name+".log")) //nolint:gosec // test log in a developer-chosen directory
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, args...) //nolint:gosec // test-only, binaries named by the developer
	cmd.Stdout, cmd.Stderr = logf, logf
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		_ = logf.Close()
		if t.Failed() {
			if b, err := os.ReadFile(logf.Name()); err == nil && len(b) > 0 { //nolint:gosec // reads back the log written above
				if len(b) > 4000 {
					b = b[len(b)-4000:]
				}
				t.Logf("%s log tail:\n%s", name, b)
			}
		}
	})
}

// daemonLogLevel is monerod's --log-level, 0 unless MONERGO_E2E_DAEMON_LOG says
// otherwise (for example "1" or "0,txpool:DEBUG").
func daemonLogLevel() string {
	if l := os.Getenv("MONERGO_E2E_DAEMON_LOG"); l != "" {
		return l
	}
	return "0"
}

func waitFor(t *testing.T, base, method string) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for {
		err := rpc.RPC(base, method, nil, nil)
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s did not come up: %v", base, err)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

type node struct {
	t      *testing.T
	daemon string
}

func (n node) mine(blocks int, to string) {
	n.t.Helper()
	var r struct {
		Height uint64 `json:"height"`
	}
	if err := rpc.RPC(n.daemon, "generateblocks", map[string]any{"amount_of_blocks": blocks, "wallet_address": to}, &r); err != nil {
		n.t.Fatal(err)
	}
}

// submit sends a signed tx and fails the test unless the daemon accepts it.
func (n node) submit(txHex string) {
	n.t.Helper()
	var r map[string]any
	if err := rpc.Post(n.daemon+"/send_raw_transaction", map[string]any{"tx_as_hex": txHex, "do_not_relay": false}, &r); err != nil {
		n.t.Fatal(err)
	}
	if r["status"] != "OK" {
		n.t.Fatalf("daemon rejected the transaction: %v", r)
	}
}

// mineTx mines blocks until txid is in one. monerod keeps a locally submitted
// tx out of block templates while it is in the Dandelion++ stem phase (an
// offline daemon has no peers to stem to); the embargo timer, about 39 s on
// average, then fluffs it.
func (n node) mineTx(txid, to string) {
	n.t.Helper()
	deadline := time.Now().Add(5 * time.Minute)
	for {
		n.mine(1, to)
		var r struct {
			Txs []struct {
				InPool bool `json:"in_pool"`
			} `json:"txs"`
		}
		if err := rpc.Post(n.daemon+"/get_transactions", map[string]any{"txs_hashes": []string{txid}}, &r); err != nil {
			n.t.Fatal(err)
		}
		if len(r.Txs) != 1 {
			n.t.Fatalf("tx %s is neither in the pool nor in a block", txid)
		}
		if !r.Txs[0].InPool {
			return
		}
		if time.Now().After(deadline) {
			n.t.Fatalf("tx %s was not mined within 5 minutes", txid)
		}
		time.Sleep(2 * time.Second)
	}
}

type wallet struct {
	t    *testing.T
	name string
	url  string
	keys builder.PrivateKeys
	addr string
}

func newWallet(t *testing.T, bin, daemon, name string) *wallet {
	t.Helper()
	port := freePort(t)
	dir := t.TempDir()
	start(t, name+"-wallet-rpc", bin,
		"--daemon-address", daemon[len("http://"):], "--trusted-daemon",
		"--wallet-dir", dir, "--rpc-bind-ip", "127.0.0.1", "--rpc-bind-port", strconv.Itoa(port),
		"--disable-rpc-login", "--non-interactive", "--allow-mismatched-daemon-version", "--shared-ringdb-dir", filepath.Join(dir, "ringdb"),
		"--log-level", "0")
	w := &wallet{t: t, name: name, url: "http://127.0.0.1:" + strconv.Itoa(port)}
	waitFor(t, w.url, "get_version")
	w.call("create_wallet", map[string]any{"filename": name, "language": "English"}, nil)
	var a struct {
		Address string `json:"address"`
	}
	w.call("get_address", map[string]any{"account_index": 0}, &a)
	w.addr = a.Address
	w.keys.Spend = w.key("spend_key")
	w.keys.View = w.key("view_key")
	return w
}

func (w *wallet) call(method string, params, result any) {
	w.t.Helper()
	if err := rpc.RPC(w.url, method, params, result); err != nil {
		w.t.Fatalf("%s %s: %v", w.name, method, err)
	}
}

func (w *wallet) key(kind string) keys.SecretKey {
	w.t.Helper()
	var r struct {
		Key string `json:"key"`
	}
	w.call("query_key", map[string]any{"key_type": kind}, &r)
	b, err := hex.DecodeString(r.Key)
	if err != nil || len(b) != 32 {
		w.t.Fatalf("query_key %s: %q", kind, r.Key)
	}
	return keys.SecretKey(b)
}

func (w *wallet) refresh() { w.call("refresh", nil, nil) }

func (w *wallet) subaddress() (string, keys.SubaddressIndex) {
	var r struct {
		Address      string `json:"address"`
		AddressIndex uint32 `json:"address_index"`
	}
	w.call("create_address", map[string]any{"account_index": 0}, &r)
	return r.Address, keys.SubaddressIndex{Major: 0, Minor: r.AddressIndex}
}

func (w *wallet) unlocked() uint64 {
	var r struct {
		Unlocked uint64 `json:"unlocked_balance"`
	}
	w.call("get_balance", map[string]any{"account_index": 0}, &r)
	return r.Unlocked
}

type walletTransfer struct {
	Type         string               `json:"type"`
	Amount       uint64               `json:"amount"`
	Fee          uint64               `json:"fee"`
	PaymentID    string               `json:"payment_id"`
	SubaddrIndex keys.SubaddressIndex `json:"subaddr_index"`
	Destinations []struct {
		Amount  uint64 `json:"amount"`
		Address string `json:"address"`
	} `json:"destinations"`
}

// received returns the incoming transfers of txid, one per receiving subaddress.
func (w *wallet) transfers(txid string) []walletTransfer {
	w.t.Helper()
	var r struct {
		Transfers []walletTransfer `json:"transfers"`
	}
	w.call("get_transfer_by_txid", map[string]any{"txid": txid}, &r)
	return r.Transfers
}

// request prepares a transfer from w's wallet-rpc and the daemon.
func (w *wallet) request(n node, dests []builder.Destination) builder.TransferRequest {
	w.t.Helper()
	req, err := prepare.Request(prepare.Options{
		Wallet: w.url, Daemon: n.daemon, Network: protocol.Mainnet, // regtest uses mainnet prefixes
		Destinations: dests, Priority: 1, MaxFee: xmr / 10,
	})
	if err != nil {
		w.t.Fatal(err)
	}
	return req
}

// signReq signs req with monergo using the keys exported from w.
func (w *wallet) signReq(req builder.TransferRequest) *builder.Signed {
	w.t.Helper()
	s, err := builder.SignWithRand(nil, w.keys, req)
	if err != nil {
		w.t.Fatal(err)
	}
	return s
}

func (w *wallet) sign(n node, dests []builder.Destination) *builder.Signed {
	w.t.Helper()
	return w.signReq(w.request(n, dests))
}

func TestRegtestEndToEnd(t *testing.T) {
	monerod, walletRPC := os.Getenv("MONERGO_MONEROD"), os.Getenv("MONERGO_WALLET_RPC")
	if monerod == "" || walletRPC == "" {
		t.Skip("set MONERGO_MONEROD and MONERGO_WALLET_RPC to run against the official daemon")
	}
	rpcPort := freePort(t)
	start(t, "monerod", monerod,
		"--regtest", "--offline", "--fixed-difficulty", "1", "--data-dir", t.TempDir(),
		"--rpc-bind-ip", "127.0.0.1", "--rpc-bind-port", strconv.Itoa(rpcPort),
		"--p2p-bind-port", strconv.Itoa(freePort(t)), "--zmq-rpc-bind-port", strconv.Itoa(freePort(t)),
		"--non-interactive", "--no-igd", "--disable-dns-checkpoints", "--check-updates", "disabled",
		"--log-level", daemonLogLevel())
	n := node{t: t, daemon: "http://127.0.0.1:" + strconv.Itoa(rpcPort)}
	waitFor(t, n.daemon, "get_info")
	var hf struct {
		Version uint8 `json:"version"`
	}
	if err := rpc.RPC(n.daemon, "hard_fork_info", nil, &hf); err != nil {
		t.Fatal(err)
	}
	if hf.Version != protocol.CurrentHardFork {
		t.Fatalf("regtest is at hard fork %d, monergo builds for %d", hf.Version, protocol.CurrentHardFork)
	}

	alice := newWallet(t, walletRPC, n.daemon, "alice")
	bob := newWallet(t, walletRPC, n.daemon, "bob")
	defer alice.keys.Wipe()
	defer bob.keys.Wipe()

	// 300 coinbase outputs for alice, unlocked after 60 blocks.
	n.mine(300, alice.addr)
	alice.refresh()

	// confirm mines the tx and checks both wallets' view of it.
	// The steps depend on each other (each spends what earlier ones received),
	// so they run in order and the first failure stops the test.
	var name string
	step := func(s string, f func()) {
		name = s
		t.Log("step:", s)
		f()
	}

	// confirm mines the tx and checks the daemon's and both wallets' view of it.
	confirm := func(from, to *wallet, s *builder.Signed, want map[keys.SubaddressIndex]uint64, pid string) {
		t.Helper()
		n.submit(s.TxHex)
		n.mineTx(s.TxHash, alice.addr)
		from.refresh()
		to.refresh()
		got := map[keys.SubaddressIndex]uint64{}
		for _, tr := range to.transfers(s.TxHash) {
			if tr.Type != "in" {
				t.Fatalf("%s: recipient sees a %q transfer", name, tr.Type)
			}
			if pid != "" && tr.PaymentID != pid {
				t.Fatalf("%s: payment ID %q, want %q", name, tr.PaymentID, pid)
			}
			got[tr.SubaddrIndex] += tr.Amount
		}
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("%s: recipient received %v, want %v", name, got, want)
		}
		out := from.transfers(s.TxHash)
		if len(out) != 1 || out[0].Type != "out" || out[0].Fee != s.Fee {
			t.Fatalf("%s: sender sees %+v, want one out transfer with fee %d", name, out, s.Fee)
		}
		var sent uint64
		for _, w := range want {
			sent += w
		}
		if out[0].Amount != sent {
			t.Fatalf("%s: sender wallet says it sent %d, want %d (change %d)", name, out[0].Amount, sent, s.Change)
		}
		t.Logf("%s: tx %s fee %d weight %d inputs %d change %d", name, s.TxHash, s.Fee, s.Weight, len(s.KeyImages), s.Change)
	}

	main := keys.SubaddressIndex{}
	sub1Addr, sub1 := bob.subaddress()
	sub2Addr, sub2 := bob.subaddress()

	step("standard address, coinbase input", func() {
		s := alice.sign(n, []builder.Destination{{Address: bob.addr, Amount: 1 * xmr}})
		confirm(alice, bob, s, map[keys.SubaddressIndex]uint64{main: 1 * xmr}, "")
	})

	step("subaddress", func() {
		s := alice.sign(n, []builder.Destination{{Address: sub1Addr, Amount: 2 * xmr}})
		confirm(alice, bob, s, map[keys.SubaddressIndex]uint64{sub1: 2 * xmr}, "")
	})

	step("integrated address", func() {
		var r struct {
			Integrated string `json:"integrated_address"`
		}
		const pid = "1122334455667788"
		bob.call("make_integrated_address", map[string]any{"payment_id": pid}, &r)
		s := alice.sign(n, []builder.Destination{{Address: r.Integrated, Amount: xmr / 2}})
		confirm(alice, bob, s, map[keys.SubaddressIndex]uint64{main: xmr / 2}, pid)
	})

	step("mixed destinations, additional tx keys", func() {
		s := alice.sign(n, []builder.Destination{
			{Address: bob.addr, Amount: 3 * xmr / 10},
			{Address: sub1Addr, Amount: 4 * xmr / 10},
			{Address: sub2Addr, Amount: 6 * xmr / 10},
		})
		if len(s.AdditionalTxKeys) == 0 {
			t.Fatalf("%s: expected additional tx keys", name)
		}
		confirm(alice, bob, s, map[keys.SubaddressIndex]uint64{main: 3 * xmr / 10, sub1: 4 * xmr / 10, sub2: 6 * xmr / 10}, "")
	})

	step("16 outputs", func() {
		var dests []builder.Destination
		want := map[keys.SubaddressIndex]uint64{}
		for i := 0; i < protocol.MaxOutputs-1; i++ {
			a, idx := bob.subaddress()
			amt := uint64(i+1) * xmr / 100
			dests = append(dests, builder.Destination{Address: a, Amount: amt})
			want[idx] = amt
		}
		s := alice.sign(n, dests)
		confirm(alice, bob, s, want, "")
	})

	step("spend received outputs from several subaddresses", func() {
		n.mine(10, alice.addr) // unlock bob's outputs
		bob.refresh()
		s := bob.sign(n, []builder.Destination{{Address: alice.addr, Amount: 3*xmr + xmr/2}})
		if len(s.KeyImages) < 3 {
			t.Fatalf("%s: expected at least 3 inputs, got %d", name, len(s.KeyImages))
		}
		confirm(bob, alice, s, map[keys.SubaddressIndex]uint64{main: 3*xmr + xmr/2}, "")
	})

	var sweep *builder.Signed
	var sweepReq builder.TransferRequest
	step("sweep: zero change, dummy output", func() {
		n.mine(10, alice.addr)
		bob.refresh()
		all := bob.unlocked()
		// Select every unlocked output, learn the fee with a probe that has
		// change, then send everything minus that fee. The fee does not change:
		// the dummy output takes the change output's place.
		req := bob.request(n, []builder.Destination{{Address: alice.addr, Amount: all - xmr/10}})
		var in uint64
		for _, i := range req.Inputs {
			in += i.Amount
		}
		if in != all {
			t.Fatalf("%s: selected %d of %d", name, in, all)
		}
		req.Destinations[0].Amount = in / 2
		probe := bob.signReq(req)
		req.Destinations[0].Amount = in - probe.Fee
		sweep = bob.signReq(req)
		sweepReq = req
		if sweep.Change != 0 || sweep.Fee != probe.Fee {
			t.Fatalf("%s: change %d fee %d (probe fee %d)", name, sweep.Change, sweep.Fee, probe.Fee)
		}
		confirm(bob, alice, sweep, map[keys.SubaddressIndex]uint64{main: in - probe.Fee}, "")
		n.mine(10, alice.addr)
		bob.refresh()
		if u := bob.unlocked(); u != 0 {
			t.Fatalf("%s: bob still has %d unlocked after the sweep", name, u)
		}
	})

	step("double spend is rejected", func() {
		// A different transaction spending the same (now spent) outputs.
		sweepReq.Destinations[0].Amount /= 2
		again := bob.signReq(sweepReq)
		if again.TxHash == sweep.TxHash || again.KeyImages[0] != sweep.KeyImages[0] {
			t.Fatalf("%s: expected a different tx with the same key images", name)
		}
		var r map[string]any
		if err := rpc.Post(n.daemon+"/send_raw_transaction", map[string]any{"tx_as_hex": again.TxHex}, &r); err != nil {
			t.Fatal(err)
		}
		if r["status"] == "OK" || r["double_spend"] != true {
			t.Fatalf("%s: daemon accepted a double spend: %v", name, r)
		}
	})
}
