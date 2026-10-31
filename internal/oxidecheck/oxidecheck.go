// Package oxidecheck runs the dev-only tools/oxide-check harness, which verifies
// transactions with monero-oxide, an independent Rust implementation. Tests that
// use it are skipped when the harness binary is not built.
package oxidecheck

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// Tx is one transaction to check, with the ring members (key, commitment) of each
// input.
type Tx struct {
	Hex   string        `json:"hex"`
	Rings [][][2]string `json:"rings"`
}

// Result is monero-oxide's view of one transaction.
type Result struct {
	Parsed            bool   `json:"parsed"`
	ReserializedEqual bool   `json:"reserialized_equal"`
	Hash              string `json:"hash"`
	SignatureHash     string `json:"signature_hash"`
	Weight            int    `json:"weight"`
	CLSAGs            []bool `json:"clsags"`
	RangeProof        bool   `json:"range_proof"`
	Error             string `json:"error"`
}

// NewTx builds a request from raw bytes and rings of (key, mask) pairs.
func NewTx(raw []byte, rings [][][2][32]byte) Tx {
	t := Tx{Hex: hex.EncodeToString(raw), Rings: make([][][2]string, len(rings))}
	for i, ring := range rings {
		for _, m := range ring {
			t.Rings[i] = append(t.Rings[i], [2]string{hex.EncodeToString(m[0][:]), hex.EncodeToString(m[1][:])})
		}
	}
	return t
}

func binary() string {
	if p := os.Getenv("MONERGO_OXIDE_CHECK"); p != "" {
		return p
	}
	_, file, _, _ := runtime.Caller(0)
	name := "oxide-check"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return filepath.Join(filepath.Dir(file), "..", "..", "tools", "oxide-check", "target", "release", name)
}

// Run checks txs with monero-oxide, skipping the test if the harness is not built
// (cd tools/oxide-check && cargo build --release).
func Run(t testing.TB, txs []Tx) []Result {
	t.Helper()
	bin := binary()
	if _, err := os.Stat(bin); err != nil {
		t.Skipf("monero-oxide harness not built (%s); see tools/oxide-check/README.md", bin)
	}
	req, err := json.Marshal(map[string]any{"txs": txs})
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin) //nolint:gosec // dev-only harness at a fixed path or $MONERGO_OXIDE_CHECK
	cmd.Stdin = bytes.NewReader(req)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("oxide-check: %v: %s", err, stderr.String())
	}
	var res []Result
	if err := json.Unmarshal(out, &res); err != nil {
		t.Fatalf("oxide-check output: %v", err)
	}
	if len(res) != len(txs) {
		t.Fatalf("oxide-check returned %d results for %d txs", len(res), len(txs))
	}
	return res
}
