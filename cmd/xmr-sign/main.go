// Command xmr-sign signs a Monero transfer offline, for manual testing.
//
// It reads a JSON payload on stdin:
//
//	{"keys": {"Spend": "<hex>", "View": "<hex>"}, "request": <builder.TransferRequest>}
//
// and writes the signed transaction as JSON on stdout (tx_hex, tx_hash, fee,
// weight, key_images, change; the tx keys only with -with-tx-keys). With -keys
// FILE the keys are read from FILE instead of the payload. It never touches the
// network.
//
// Unaudited. Do not use with real funds until independently audited.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/sina-haseli/monergo/builder"
)

type payload struct {
	Keys    *builder.PrivateKeys    `json:"keys,omitempty"`
	Request builder.TransferRequest `json:"request"`
}

func main() {
	keysFile := flag.String("keys", "", "read {\"Spend\":..,\"View\":..} from this file instead of the payload")
	withTxKeys := flag.Bool("with-tx-keys", false, "include the tx private keys in the output (needed for payment proofs)")
	flag.Parse()
	if err := run(os.Stdin, os.Stdout, *keysFile, *withTxKeys); err != nil {
		fmt.Fprintln(os.Stderr, "xmr-sign:", err)
		os.Exit(1)
	}
}

func run(in io.Reader, out io.Writer, keysFile string, withTxKeys bool) error {
	var p payload
	dec := json.NewDecoder(in)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return fmt.Errorf("payload: %w", err)
	}
	if keysFile != "" {
		b, err := os.ReadFile(keysFile)
		if err != nil {
			return err
		}
		var k builder.PrivateKeys
		if err := json.Unmarshal(b, &k); err != nil {
			return fmt.Errorf("keys file: %w", err)
		}
		clear(b)
		p.Keys = &k
	}
	if p.Keys == nil {
		return fmt.Errorf("no keys: pass them in the payload or with -keys")
	}
	defer p.Keys.Wipe()
	signed, err := builder.SignWithRand(randReader, *p.Keys, p.Request)
	if err != nil {
		return err
	}
	defer signed.Wipe()
	res := *signed
	if !withTxKeys {
		res.TxKey = [32]byte{}
		res.AdditionalTxKeys = nil
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(res)
}
