// Command xmr-prepare assembles a builder.TransferRequest from a running
// monero-wallet-rpc (for the wallet's spendable outputs) and a daemon (for
// transactions, decoys, rings and fees). It never sees private keys.
//
// The output is an xmr-sign payload without keys, to be signed with
// `xmr-sign -keys keys.json`. See docs/stagenet-e2e.md.
//
// Unaudited. Do not use with real funds until independently audited.
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"sort"
	"time"

	"github.com/sina-haseli/monergo/builder"
	"github.com/sina-haseli/monergo/decoy"
	"github.com/sina-haseli/monergo/keys"
	"github.com/sina-haseli/monergo/protocol"
	"github.com/sina-haseli/monergo/tx"
)

var client = &http.Client{Timeout: 120 * time.Second}

func post(url string, body, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	resp, err := client.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: HTTP %s", url, resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func rpc(base, method string, params, result any) error {
	var resp struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := post(base+"/json_rpc", map[string]any{"jsonrpc": "2.0", "id": "0", "method": method, "params": params}, &resp); err != nil {
		return err
	}
	if resp.Error != nil {
		return fmt.Errorf("%s: %s", method, resp.Error.Message)
	}
	return json.Unmarshal(resp.Result, result)
}

type transfer struct {
	Amount       uint64               `json:"amount"`
	GlobalIndex  uint64               `json:"global_index"`
	PubKey       string               `json:"pubkey"`
	TxHash       string               `json:"tx_hash"`
	SubaddrIndex keys.SubaddressIndex `json:"subaddr_index"`
	Unlocked     bool                 `json:"unlocked"`
	Spent        bool                 `json:"spent"`
	Frozen       bool                 `json:"frozen"`
}

type outEntry struct {
	Key      string `json:"key"`
	Mask     string `json:"mask"`
	Unlocked bool   `json:"unlocked"`
}

func hex32(s string) ([32]byte, error) {
	var k [32]byte
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return k, fmt.Errorf("bad 32-byte hex %q", s)
	}
	copy(k[:], b)
	return k, nil
}

func main() {
	wallet := flag.String("wallet", "http://127.0.0.1:38083", "monero-wallet-rpc URL (wallet opened, --stagenet)")
	daemon := flag.String("daemon", "http://127.0.0.1:38081", "monerod URL")
	network := flag.String("network", "stagenet", "mainnet, testnet or stagenet")
	to := flag.String("to", "", "destination address")
	amount := flag.Uint64("amount", 0, "amount in atomic units")
	account := flag.Uint("account", 0, "wallet account to spend from")
	priority := flag.Int("priority", 1, "fee priority 1..4 (index into get_fee_estimate fees)")
	maxFee := flag.Uint64("max-fee", 1_000_000_000, "refuse to sign above this fee (atomic units)")
	flag.Parse()
	if err := run(*wallet, *daemon, *network, *to, *amount, uint32(*account), *priority, *maxFee); err != nil {
		fmt.Fprintln(os.Stderr, "xmr-prepare:", err)
		os.Exit(1)
	}
}

func run(wallet, daemon, network, to string, amount uint64, account uint32, priority int, maxFee uint64) error {
	if to == "" || amount == 0 {
		return errors.New("-to and -amount are required")
	}
	net, err := protocol.ParseNetwork(network)
	if err != nil {
		return err
	}
	rules, err := protocol.RulesFor(protocol.CurrentHardFork)
	if err != nil {
		return err
	}

	// Spendable outputs, largest first, until amount + a fee margin is covered.
	var inc struct {
		Transfers []transfer `json:"transfers"`
	}
	if err := rpc(wallet, "incoming_transfers", map[string]any{"transfer_type": "available", "account_index": account}, &inc); err != nil {
		return err
	}
	sort.Slice(inc.Transfers, func(i, j int) bool { return inc.Transfers[i].Amount > inc.Transfers[j].Amount })
	var picked []transfer
	var total uint64
	for _, t := range inc.Transfers {
		if t.Spent || t.Frozen || !t.Unlocked {
			continue
		}
		picked = append(picked, t)
		total += t.Amount
		if total >= amount+maxFee {
			break
		}
	}
	if total < amount {
		return fmt.Errorf("wallet has %d unlocked, need %d", total, amount)
	}

	// Output distribution for decoy selection.
	var dist struct {
		Distributions []struct {
			Distribution []uint64 `json:"distribution"`
		} `json:"distributions"`
	}
	if err := rpc(daemon, "get_output_distribution", map[string]any{"amounts": []uint64{0}, "cumulative": true, "from_height": 0, "binary": false}, &dist); err != nil {
		return err
	}
	if len(dist.Distributions) != 1 {
		return errors.New("no output distribution")
	}
	rctOffsets := dist.Distributions[0].Distribution

	req := builder.TransferRequest{
		Network:      net,
		Destinations: []builder.Destination{{Address: to, Amount: amount}},
		MaxFee:       maxFee,
	}
	for _, t := range picked {
		in, err := prepareInput(daemon, t, rctOffsets, rules.RingSize)
		if err != nil {
			return fmt.Errorf("output %s: %w", t.PubKey, err)
		}
		req.Inputs = append(req.Inputs, in)
	}

	var fee struct {
		Fees             []uint64 `json:"fees"`
		Fee              uint64   `json:"fee"`
		QuantizationMask uint64   `json:"quantization_mask"`
	}
	if err := rpc(daemon, "get_fee_estimate", map[string]any{}, &fee); err != nil {
		return err
	}
	req.FeePerByte = fee.Fee
	if priority >= 1 && priority <= len(fee.Fees) {
		req.FeePerByte = fee.Fees[priority-1]
	}
	req.FeeQuantizationMask = fee.QuantizationMask

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(map[string]any{"request": req})
}

func prepareInput(daemon string, t transfer, rctOffsets []uint64, ringSize int) (builder.Input, error) {
	var txs struct {
		Txs []struct {
			AsHex       string `json:"as_hex"`
			PrunedHex   string `json:"pruned_as_hex"`
			PrunableHex string `json:"prunable_as_hex"`
		} `json:"txs"`
		Status string `json:"status"`
	}
	if err := post(daemon+"/get_transactions", map[string]any{"txs_hashes": []string{t.TxHash}, "decode_as_json": false, "prune": false}, &txs); err != nil {
		return builder.Input{}, err
	}
	if len(txs.Txs) != 1 {
		return builder.Input{}, fmt.Errorf("tx %s not found (%s)", t.TxHash, txs.Status)
	}
	h := txs.Txs[0].AsHex
	if h == "" {
		h = txs.Txs[0].PrunedHex + txs.Txs[0].PrunableHex
	}
	raw, err := hex.DecodeString(h)
	if err != nil {
		return builder.Input{}, err
	}
	src, err := tx.Parse(raw)
	if err != nil {
		return builder.Input{}, err
	}
	outKey, err := hex32(t.PubKey)
	if err != nil {
		return builder.Input{}, err
	}
	in := builder.Input{OutputKey: outKey, Amount: t.Amount, Subaddress: t.SubaddrIndex, Coinbase: src.IsCoinbase()}
	found := false
	for i, o := range src.Outputs {
		if o.Key == outKey {
			in.OutputIndex, found = uint64(i), true
		}
	}
	if !found {
		return builder.Input{}, errors.New("output key not in its transaction")
	}
	fields, _ := tx.ParseExtra(src.Extra) // wallets tolerate partial extra
	pub, ok := tx.TxPubKey(fields)
	if !ok {
		return builder.Input{}, errors.New("no tx public key")
	}
	in.TxPubKey = pub
	for _, k := range tx.AdditionalPubKeys(fields) {
		in.AdditionalTxPubKeys = append(in.AdditionalTxPubKeys, k)
	}

	// Decoys: retry until every member is unlocked.
	for attempt := 0; attempt < 10; attempt++ {
		ring, pos, err := decoy.Select(nil, rctOffsets, t.GlobalIndex, ringSize)
		if err != nil {
			return builder.Input{}, err
		}
		var req []map[string]uint64
		for _, g := range ring {
			req = append(req, map[string]uint64{"amount": 0, "index": g})
		}
		var outs struct {
			Outs   []outEntry `json:"outs"`
			Status string     `json:"status"`
		}
		if err := post(daemon+"/get_outs", map[string]any{"outputs": req, "get_txid": false}, &outs); err != nil {
			return builder.Input{}, err
		}
		if len(outs.Outs) != len(ring) {
			return builder.Input{}, fmt.Errorf("get_outs: %s", outs.Status)
		}
		ok := true
		in.Ring = in.Ring[:0]
		for i, o := range outs.Outs {
			if !o.Unlocked {
				ok = false
				break
			}
			k, err := hex32(o.Key)
			if err != nil {
				return builder.Input{}, err
			}
			m, err := hex32(o.Mask)
			if err != nil {
				return builder.Input{}, err
			}
			in.Ring = append(in.Ring, builder.RingMember{GlobalIndex: ring[i], Key: k, Commitment: m})
		}
		if ok {
			in.RealIndex = pos
			if in.Ring[pos].Key != outKey {
				return builder.Input{}, errors.New("daemon's output at the real index is not ours")
			}
			return in, nil
		}
	}
	return builder.Input{}, errors.New("could not find enough unlocked decoys")
}
