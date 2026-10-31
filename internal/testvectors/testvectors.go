// Package testvectors loads upstream Monero test vectors committed under data/.
// It is imported only from tests. See README.md for the provenance of each file.
package testvectors

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// CryptoTestsSHA256 is the SHA-256 of the uncompressed tests/crypto/tests.txt at
// monero-project/monero@3fd0f88c20f559839cafb20911cb13cb45eba7bd.
const CryptoTestsSHA256 = "98cf75c9c4bb48dc10d6e93b4b54767cfa32e66955c5ac4b8349eb627a603c18"

//go:embed data/tests.txt.gz
var cryptoTestsGz []byte

// Vector is one line of tests/crypto/tests.txt.
type Vector struct {
	Line int
	Type string
	Args []string
}

// Implemented lists every vector type we run, with the package whose tests run it.
var Implemented = map[string]string{
	"check_scalar":               "primitives",
	"hash_to_scalar":             "primitives",
	"check_key":                  "primitives",
	"hash_to_point":              "primitives",
	"biased_hash_to_ec":          "primitives",
	"check_ge_p3_identity":       "primitives",
	"secret_key_to_public_key":   "keys",
	"generate_key_derivation":    "keys",
	"derive_public_key":          "keys",
	"derive_secret_key":          "keys",
	"generate_key_image":         "keys",
	"derive_view_tag":            "keys",
	"derive_key_image_generator": "keys",
}

// Skipped lists every vector type deliberately not run, with the reason.
// See docs/PLAN.md §0 and open questions Q1/Q2.
var Skipped = map[string]string{
	"random_scalar":           "depends on the upstream test harness's deterministic RNG",
	"generate_keys":           "depends on the upstream test harness's deterministic RNG",
	"generate_signature":      "pre-RingCT Schnorr signature; not needed by the signer (and RNG-dependent)",
	"check_signature":         "pre-RingCT Schnorr signature; not needed by the signer",
	"generate_ring_signature": "pre-RingCT ring signature; not needed by the signer (and RNG-dependent)",
	"check_ring_signature":    "pre-RingCT ring signature; not needed by the signer",
	"point_to_wei_x_y":        "FCMP++ only",
}

// PartiallySkipped documents vectors of an implemented type that are filtered out.
var PartiallySkipped = map[string]string{
	"derive_key_image_generator": "biased=false (unbiased_hash_to_ec) needs BLAKE2b; deferred until FCMP++ (Q1)",
	"check_ge_p3_identity":       "only the 'good' result is checked; the 'bad' one tests a ref10 limb-representation bug",
}

var (
	once    sync.Once
	vectors []Vector
	loadErr error
)

// CryptoTests returns every vector in tests/crypto/tests.txt, after checking the
// embedded file against CryptoTestsSHA256.
func CryptoTests() ([]Vector, error) {
	once.Do(func() { vectors, loadErr = load() })
	return vectors, loadErr
}

func load() ([]Vector, error) {
	zr, err := gzip.NewReader(bytes.NewReader(cryptoTestsGz))
	if err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(zr)
	if err != nil {
		return nil, err
	}
	if sum := sha256.Sum256(raw); hex.EncodeToString(sum[:]) != CryptoTestsSHA256 {
		return nil, fmt.Errorf("tests.txt sha256 mismatch: %x", sum)
	}
	var out []Vector
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for line := 1; sc.Scan(); line++ {
		text := sc.Text()
		if text == "" {
			continue
		}
		f := strings.Split(text, " ")
		out = append(out, Vector{Line: line, Type: f[0], Args: f[1:]})
	}
	return out, sc.Err()
}

// Run calls fn for every vector of type typ as a subtest named by line number. It
// fails if the type is not registered in Implemented or has no vectors, and logs
// how many vectors ran.
func Run(t *testing.T, typ string, fn func(t *testing.T, v Vector)) {
	t.Helper()
	if _, ok := Implemented[typ]; !ok {
		t.Fatalf("vector type %q is not registered in testvectors.Implemented", typ)
	}
	all, err := CryptoTests()
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, v := range all {
		if v.Type != typ {
			continue
		}
		n++
		t.Run(fmt.Sprintf("line%d", v.Line), func(t *testing.T) { fn(t, v) })
	}
	if n == 0 {
		t.Fatalf("no vectors of type %q", typ)
	}
	t.Logf("%s: %d vectors", typ, n)
}

// Arg returns argument i, failing the test if it is missing.
func (v Vector) Arg(t *testing.T, i int) string {
	t.Helper()
	if i >= len(v.Args) {
		t.Fatalf("line %d: want argument %d, have %d", v.Line, i, len(v.Args))
	}
	return v.Args[i]
}

// Hex returns argument i decoded from hex. As in upstream tests/io.h
// (get(std::istream&, std::vector<char>&)), the literal "x" is the empty string.
func (v Vector) Hex(t *testing.T, i int) []byte {
	t.Helper()
	s := v.Arg(t, i)
	if s == "x" {
		return []byte{}
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("line %d arg %d: %v", v.Line, i, err)
	}
	return b
}

// Hex32 returns argument i decoded from 64 hex characters.
func (v Vector) Hex32(t *testing.T, i int) [32]byte {
	t.Helper()
	b := v.Hex(t, i)
	if len(b) != 32 {
		t.Fatalf("line %d arg %d: want 32 bytes, got %d", v.Line, i, len(b))
	}
	return [32]byte(b)
}

// Bool returns argument i parsed as "true" or "false".
func (v Vector) Bool(t *testing.T, i int) bool {
	t.Helper()
	switch s := v.Arg(t, i); s {
	case "true":
		return true
	case "false":
		return false
	default:
		t.Fatalf("line %d arg %d: not a bool: %q", v.Line, i, s)
		return false
	}
}

// Uint returns argument i parsed as a decimal uint64.
func (v Vector) Uint(t *testing.T, i int) uint64 {
	t.Helper()
	n, err := strconv.ParseUint(v.Arg(t, i), 10, 64)
	if err != nil {
		t.Fatalf("line %d arg %d: %v", v.Line, i, err)
	}
	return n
}
