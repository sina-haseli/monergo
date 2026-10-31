// Command xmr-prepare assembles a builder.TransferRequest from a running
// monero-wallet-rpc (for the wallet's spendable outputs) and a daemon (for
// transactions, decoys, rings and fees). It never sees private keys.
//
// The output is an xmr-sign payload without keys, to be signed with
// `xmr-sign -keys keys.json`. See docs/testnet-e2e.md.
//
// Unaudited. Do not use with real funds until independently audited.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/sina-haseli/monergo/builder"
	"github.com/sina-haseli/monergo/internal/prepare"
	"github.com/sina-haseli/monergo/protocol"
)

// destFlags collects repeated -to ADDRESS[:AMOUNT] flags.
type destFlags []string

func (d *destFlags) String() string     { return strings.Join(*d, ",") }
func (d *destFlags) Set(v string) error { *d = append(*d, v); return nil }

func main() {
	var to destFlags
	wallet := flag.String("wallet", "http://127.0.0.1:38083", "monero-wallet-rpc URL (wallet opened)")
	daemon := flag.String("daemon", "http://127.0.0.1:38081", "monerod URL")
	network := flag.String("network", "stagenet", "mainnet, testnet or stagenet (regtest uses mainnet)")
	flag.Var(&to, "to", "destination ADDRESS, or ADDRESS:AMOUNT; repeat for several destinations")
	amount := flag.Uint64("amount", 0, "amount in atomic units, for a single -to without :AMOUNT")
	account := flag.Uint("account", 0, "wallet account to spend from")
	priority := flag.Int("priority", 1, "fee priority 1..4 (index into get_fee_estimate fees)")
	maxFee := flag.Uint64("max-fee", 1_000_000_000, "refuse to sign above this fee (atomic units)")
	flag.Parse()
	if err := run(*wallet, *daemon, *network, to, *amount, uint32(*account), *priority, *maxFee); err != nil {
		fmt.Fprintln(os.Stderr, "xmr-prepare:", err)
		os.Exit(1)
	}
}

func destinations(to []string, amount uint64) ([]builder.Destination, error) {
	if len(to) == 0 {
		return nil, errors.New("-to is required")
	}
	var out []builder.Destination
	for _, t := range to {
		addr, amt, ok := strings.Cut(t, ":")
		var a uint64
		switch {
		case ok:
			var err error
			if a, err = strconv.ParseUint(amt, 10, 64); err != nil {
				return nil, fmt.Errorf("-to %s: %w", t, err)
			}
		case len(to) == 1:
			a = amount
		default:
			return nil, fmt.Errorf("-to %s: use ADDRESS:AMOUNT with several destinations", t)
		}
		if a == 0 {
			return nil, fmt.Errorf("-to %s: amount is required", t)
		}
		out = append(out, builder.Destination{Address: addr, Amount: a})
	}
	return out, nil
}

func run(wallet, daemon, network string, to []string, amount uint64, account uint32, priority int, maxFee uint64) error {
	net, err := protocol.ParseNetwork(network)
	if err != nil {
		return err
	}
	dests, err := destinations(to, amount)
	if err != nil {
		return err
	}
	req, err := prepare.Request(prepare.Options{
		Wallet: wallet, Daemon: daemon, Network: net, Destinations: dests,
		Account: account, Priority: priority, MaxFee: maxFee,
	})
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(map[string]any{"request": req})
}
