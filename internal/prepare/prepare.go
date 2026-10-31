// Package prepare assembles a builder.TransferRequest from a running
// monero-wallet-rpc (for the wallet's spendable outputs) and a daemon (for
// transactions, decoys, rings and fees). It never sees private keys.
//
// It backs tools/xmr-prepare and the regtest end-to-end test.
//
// Unaudited. Do not use with real funds until independently audited.
package prepare

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/sina-haseli/monergo/builder"
	"github.com/sina-haseli/monergo/decoy"
	"github.com/sina-haseli/monergo/keys"
	"github.com/sina-haseli/monergo/protocol"
	"github.com/sina-haseli/monergo/tx"
)

// Options says what to spend and where to send it.
type Options struct {
	Wallet       string // monero-wallet-rpc base URL, wallet already open
	Daemon       string // monerod base URL
	Network      protocol.Network
	Destinations []builder.Destination
	Account      uint32 // wallet account to spend from
	Priority     int    // 1..4, index into get_fee_estimate fees; 0 uses the base fee
	MaxFee       uint64 // refuse to sign above this fee
	Client       *http.Client
}

// Client is a minimal JSON client for monerod and monero-wallet-rpc.
type Client struct{ HTTP *http.Client }

// Post sends body as JSON to url and decodes the response into out.
func (c Client) Post(url string, body, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 120 * time.Second}
	}
	resp, err := hc.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: HTTP %s", url, resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// RPC calls a JSON-RPC 2.0 method at base/json_rpc.
func (c Client) RPC(base, method string, params, result any) error {
	if params == nil {
		params = struct{}{}
	}
	var resp struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := c.Post(base+"/json_rpc", map[string]any{"jsonrpc": "2.0", "id": "0", "method": method, "params": params}, &resp); err != nil {
		return err
	}
	if resp.Error != nil {
		return fmt.Errorf("%s: %s", method, resp.Error.Message)
	}
	if result == nil {
		return nil
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

// Request builds the transfer request. Inputs are the wallet's unlocked outputs,
// largest first, until the destinations plus MaxFee are covered (or all of them).
func Request(o Options) (builder.TransferRequest, error) {
	c := Client{HTTP: o.Client}
	if len(o.Destinations) == 0 {
		return builder.TransferRequest{}, errors.New("prepare: no destinations")
	}
	var amount uint64
	for _, d := range o.Destinations {
		if d.Amount == 0 || amount+d.Amount < amount {
			return builder.TransferRequest{}, errors.New("prepare: bad destination amount")
		}
		amount += d.Amount
	}
	rules, err := protocol.RulesFor(protocol.CurrentHardFork)
	if err != nil {
		return builder.TransferRequest{}, err
	}
	// Testnet usually forks first (FCMP++); a tx built for v16 would be rejected.
	var hf struct {
		Version uint8 `json:"version"`
	}
	if err := c.RPC(o.Daemon, "hard_fork_info", nil, &hf); err != nil {
		return builder.TransferRequest{}, err
	}
	if hf.Version != protocol.CurrentHardFork {
		return builder.TransferRequest{}, fmt.Errorf("prepare: daemon is at hard fork v%d, monergo builds v%d transactions", hf.Version, protocol.CurrentHardFork)
	}

	var inc struct {
		Transfers []transfer `json:"transfers"`
	}
	if err := c.RPC(o.Wallet, "incoming_transfers", map[string]any{"transfer_type": "available", "account_index": o.Account}, &inc); err != nil {
		return builder.TransferRequest{}, err
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
		if total >= amount+o.MaxFee {
			break
		}
	}
	if total < amount {
		return builder.TransferRequest{}, fmt.Errorf("prepare: wallet has %d unlocked, need %d", total, amount)
	}

	var dist struct {
		Distributions []struct {
			Distribution []uint64 `json:"distribution"`
		} `json:"distributions"`
	}
	if err := c.RPC(o.Daemon, "get_output_distribution", map[string]any{"amounts": []uint64{0}, "cumulative": true, "from_height": 0, "binary": false}, &dist); err != nil {
		return builder.TransferRequest{}, err
	}
	if len(dist.Distributions) != 1 {
		return builder.TransferRequest{}, errors.New("prepare: no output distribution")
	}
	rctOffsets := dist.Distributions[0].Distribution

	req := builder.TransferRequest{
		Network:      o.Network,
		Destinations: o.Destinations,
		MaxFee:       o.MaxFee,
	}
	for _, t := range picked {
		in, err := input(c, o.Daemon, t, rctOffsets, rules.RingSize)
		if err != nil {
			return builder.TransferRequest{}, fmt.Errorf("prepare: output %s: %w", t.PubKey, err)
		}
		req.Inputs = append(req.Inputs, in)
	}

	var fee struct {
		Fees             []uint64 `json:"fees"`
		Fee              uint64   `json:"fee"`
		QuantizationMask uint64   `json:"quantization_mask"`
	}
	if err := c.RPC(o.Daemon, "get_fee_estimate", nil, &fee); err != nil {
		return builder.TransferRequest{}, err
	}
	req.FeePerByte = fee.Fee
	if o.Priority >= 1 && o.Priority <= len(fee.Fees) {
		req.FeePerByte = fee.Fees[o.Priority-1]
	}
	req.FeeQuantizationMask = fee.QuantizationMask
	return req, nil
}

func input(c Client, daemon string, t transfer, rctOffsets []uint64, ringSize int) (builder.Input, error) {
	var txs struct {
		Txs []struct {
			AsHex       string `json:"as_hex"`
			PrunedHex   string `json:"pruned_as_hex"`
			PrunableHex string `json:"prunable_as_hex"`
		} `json:"txs"`
		Status string `json:"status"`
	}
	if err := c.Post(daemon+"/get_transactions", map[string]any{"txs_hashes": []string{t.TxHash}, "decode_as_json": false, "prune": false}, &txs); err != nil {
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

	// Decoys: redraw any member the daemon reports as locked (for example a
	// recent coinbase output), as wallet2::get_outs does.
	locked := map[uint64]bool{}
	for attempt := 0; attempt < 50; attempt++ {
		ring, pos, err := decoy.SelectExcluding(nil, rctOffsets, t.GlobalIndex, ringSize, locked)
		if err != nil {
			return builder.Input{}, err
		}
		req := make([]map[string]uint64, 0, len(ring))
		for _, g := range ring {
			req = append(req, map[string]uint64{"amount": 0, "index": g})
		}
		var outs struct {
			Outs   []outEntry `json:"outs"`
			Status string     `json:"status"`
		}
		if err := c.Post(daemon+"/get_outs", map[string]any{"outputs": req, "get_txid": false}, &outs); err != nil {
			return builder.Input{}, err
		}
		if len(outs.Outs) != len(ring) {
			return builder.Input{}, fmt.Errorf("get_outs: %s", outs.Status)
		}
		in.Ring = in.Ring[:0]
		for i, o := range outs.Outs {
			if !o.Unlocked {
				if i == pos {
					return builder.Input{}, errors.New("daemon reports our output as locked")
				}
				locked[ring[i]] = true
				continue
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
		if len(in.Ring) == len(ring) {
			in.RealIndex = pos
			if in.Ring[pos].Key != outKey {
				return builder.Input{}, errors.New("daemon's output at the real index is not ours")
			}
			return in, nil
		}
	}
	return builder.Input{}, errors.New("could not find enough unlocked decoys")
}
