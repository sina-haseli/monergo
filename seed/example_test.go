package seed_test

import (
	"fmt"

	"github.com/sina-haseli/monergo/address"
	"github.com/sina-haseli/monergo/keys"
	"github.com/sina-haseli/monergo/protocol"
	"github.com/sina-haseli/monergo/seed"
)

// Restore a wallet from its 25-word seed and derive its addresses. This is Monero's
// public functional-test seed; never send funds to it.
func ExampleDecode() {
	recovery, err := seed.Decode("velvet lymph giddy number token physics poetry unquoted nibs useful sabotage limits benches lifestyle eden nitrogen anvil fewest avoid batch vials washing fences goat unquoted")
	if err != nil {
		panic(err)
	}
	acct := keys.AccountFromRecoveryKey(recovery)
	defer acct.Wipe()

	primary, _ := address.FromAccount(protocol.Mainnet, acct, keys.SubaddressIndex{})
	sub, _ := address.FromAccount(protocol.Mainnet, acct, keys.SubaddressIndex{Major: 0, Minor: 1})
	fmt.Println(primary)
	fmt.Println(sub)
	// Output:
	// 42ey1afDFnn4886T7196doS9GPMzexD9gXpsZJDwVjeRVdFCSoHnv7KPbBeGpzJBzHRCAs9UxqeoyFQMYbqSWYTfJJQAWDm
	// 84QRUYawRNrU3NN1VpFRndSukeyEb3Xpv8qZjjsoJZnTYpDYceuUTpog13D7qPxpviS7J29bSgSkR11hFFoXWk2yNdsR9WF
}
