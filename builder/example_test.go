package builder_test

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/sina-haseli/monergo/builder"
)

// A signing request as a Vault plugin would receive it. Rings come from the
// daemon's /get_outs (see package decoy and tools/xmr-prepare). Keys are hex.
func ExampleSign() {
	payload := `{
	  "network": "stagenet",
	  "inputs": [{
	    "tx_pub_key": "…", "output_index": 1, "output_key": "…", "amount": 5000000000000,
	    "subaddress": {"major": 0, "minor": 0},
	    "ring": [{"global_index": 123, "key": "…", "commitment": "…"}],
	    "real_index": 0
	  }],
	  "destinations": [{"address": "5…", "amount": 1000000000000}],
	  "fee_per_byte": 20000, "fee_quantization_mask": 10000, "max_fee": 100000000
	}`
	var req builder.TransferRequest
	err := json.NewDecoder(strings.NewReader(payload)).Decode(&req)
	fmt.Println(err != nil) // the placeholders above are not valid hex

	var keys builder.PrivateKeys // from your secret store
	if _, _, err := builder.Sign(keys, req); err != nil {
		fmt.Println("refused:", err != nil)
	}
	// Output:
	// true
	// refused: true
}
