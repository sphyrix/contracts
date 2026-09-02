package auth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestMintProducesTheADR027Format pins the wire format. It is a platform-wide
// convention (ADR 027 Decision 1) and a stored hash outlives any one release,
// so this is a contract, not an implementation detail.
func TestMintProducesTheADR027Format(t *testing.T) {
	minted, err := Mint("email")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	const wantPrefix = "sphx_email_"
	if !strings.HasPrefix(minted, wantPrefix) {
		t.Fatalf("minted token does not start with %q", wantPrefix)
	}
	secret := strings.TrimPrefix(minted, wantPrefix)
	if got, want := len(secret), 43; got != want {
		t.Errorf("the secret is %d characters, want %d (32 bytes of unpadded base64url)", got, want)
	}
	raw, err := base64.RawURLEncoding.DecodeString(secret)
	if err != nil {
		t.Fatalf("the secret is not unpadded base64url: %v", err)
	}
	if got := len(raw); got != SecretBytes {
		t.Errorf("the secret decodes to %d bytes, want %d", got, SecretBytes)
	}

	service, ok := ServiceOf(minted)
	if !ok || service != "email" {
		t.Errorf("ServiceOf(a minted token) = %q, %v; want \"email\", true", service, ok)
	}
}

// TestMintUsesCryptoRandOnly is the STRUCTURAL half of "32 bytes of
// crypto-random entropy": it reads this package's own source and fails if the
// entropy behind [Mint] is anything but crypto/rand.
//
// It is here because the statistical half below cannot catch every
// substitution: a seeded PRNG produces output that passes every distribution
// check while being wholly predictable to anyone who can guess the seed. The
// only defence against that is pinning the source, so this test pins it.
func TestMintUsesCryptoRandOnly(t *testing.T) {
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading the package directory: %v", err)
	}

	var mintChecked bool
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(".", name), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}

		// 1. No weak randomness anywhere in the shipped package, however it is
		//    reached — an import is the only way in.
		cryptoRandAlias := ""
		for _, imported := range file.Imports {
			path := strings.Trim(imported.Path.Value, `"`)
			if path == "math/rand" || path == "math/rand/v2" {
				t.Errorf("%s imports %q: minting must draw from crypto/rand only (ADR 027 Decision 1)", name, path)
			}
			if path == "crypto/rand" {
				cryptoRandAlias = "rand"
				if imported.Name != nil {
					cryptoRandAlias = imported.Name.Name
				}
			}
		}

		// 2. Mint's one call site hands `mint` crypto/rand's Read and nothing
		//    else.
		ast.Inspect(file, func(node ast.Node) bool {
			decl, ok := node.(*ast.FuncDecl)
			if !ok || decl.Recv != nil || decl.Name.Name != "Mint" {
				return true
			}
			mintChecked = true
			if cryptoRandAlias == "" {
				t.Fatalf("%s declares Mint but does not import crypto/rand", name)
			}
			var sources []string
			ast.Inspect(decl.Body, func(inner ast.Node) bool {
				call, ok := inner.(*ast.CallExpr)
				if !ok {
					return true
				}
				ident, ok := call.Fun.(*ast.Ident)
				if !ok || ident.Name != "mint" || len(call.Args) != 2 {
					return true
				}
				sources = append(sources, exprString(fset, call.Args[1]))
				return true
			})
			want := cryptoRandAlias + ".Read"
			if len(sources) != 1 || sources[0] != want {
				t.Errorf("Mint's entropy sources are %v, want exactly [%s]", sources, want)
			}
			return false
		})
	}
	if !mintChecked {
		t.Fatal("no Mint declaration was found — this test checked nothing")
	}
}

func exprString(fset *token.FileSet, expr ast.Expr) string {
	var b strings.Builder
	if err := printer.Fprint(&b, fset, expr); err != nil {
		return fmt.Sprintf("<unprintable: %v>", err)
	}
	return b.String()
}

// TestMintDrawsFullEntropy is the STATISTICAL half, and it proves its own
// assertions can fail: the same checks are run against crypto/rand (which must
// pass) and against three degenerate sources (each of which must fail). A
// check that cannot fail is the defect this repo sees most, so it is not
// enough to run it against the good source alone.
//
// A seeded PRNG is NOT in this table, because these checks would pass it —
// TestMintUsesCryptoRandOnly is what catches that substitution.
func TestMintDrawsFullEntropy(t *testing.T) {
	zeros := func(b []byte) (int, error) {
		for i := range b {
			b[i] = 0
		}
		return len(b), nil
	}
	constant := func(b []byte) (int, error) {
		for i := range b {
			b[i] = 0xab
		}
		return len(b), nil
	}
	var n byte
	counter := func(b []byte) (int, error) {
		for i := range b {
			b[i] = 0
		}
		b[len(b)-1] = n
		n++
		return len(b), nil
	}
	// The three sources above are all caught by the uniqueness check alone, so
	// on their own they never exercise the bit-distribution band below them —
	// the band would be a check with no proof it can fire. This fourth source
	// is UNIQUE on every draw (a 32-bit counter, so no repeat inside a sample)
	// and still structurally biased: 224 of the 256 bits are always zero. Only
	// the band catches it.
	var wide uint32
	biasedButUnique := func(b []byte) (int, error) {
		for i := range b {
			b[i] = 0
		}
		binary.BigEndian.PutUint32(b[:4], wide)
		wide++
		return len(b), nil
	}

	if failures := entropyFailures(t, rand.Read); len(failures) != 0 {
		t.Errorf("crypto/rand failed the entropy checks: %s", strings.Join(failures, "; "))
	}
	for name, source := range map[string]func([]byte) (int, error){
		"all zeros":               zeros,
		"one constant":            constant,
		"a counter":               counter,
		"unique but 32 bits wide": biasedButUnique,
	} {
		if failures := entropyFailures(t, source); len(failures) == 0 {
			t.Errorf("%s passed the entropy checks — the checks cannot fail and prove nothing", name)
		}
	}

	// And specifically: the fourth source must be caught by the BAND, not by
	// one of the cheaper checks. Without this, opening the band to accept
	// everything would still leave the table above green.
	failures := entropyFailures(t, biasedButUnique)
	var bandFired bool
	for _, failure := range failures {
		if strings.Contains(failure, "is set in") {
			bandFired = true
		}
		if strings.Contains(failure, "same secret") {
			t.Errorf("the 32-bit source repeated a secret; it no longer isolates the distribution band: %s", failure)
		}
	}
	if !bandFired {
		t.Errorf("the bit-distribution band never fired — it is a check with no proof it can fail (failures were %v)", failures)
	}
}

// entropyFailures mints a sample from read and returns everything about it
// that a 32-byte crypto-random secret would not do.
func entropyFailures(t *testing.T, read func([]byte) (int, error)) []string {
	t.Helper()

	const samples = 512
	secrets := make([][]byte, 0, samples)
	seen := make(map[string]bool, samples)
	var failures []string

	for range samples {
		minted, err := mint("email", read)
		if err != nil {
			return append(failures, fmt.Sprintf("minting failed: %v", err))
		}
		raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(minted, "sphx_email_"))
		if err != nil {
			return append(failures, fmt.Sprintf("the secret is not base64url: %v", err))
		}
		if len(raw) != SecretBytes {
			failures = append(failures, fmt.Sprintf("the secret is %d bytes, want %d", len(raw), SecretBytes))
			return failures
		}
		if seen[string(raw)] {
			failures = append(failures, "two mints produced the same secret")
			return failures
		}
		seen[string(raw)] = true
		secrets = append(secrets, raw)
	}

	// Every one of the 256 bits must vary. The band has to be wide enough that
	// a genuinely random draw never trips it: over 512 samples one standard
	// deviation is 11.3 counts, so a 40-60% band sits only 4.5σ out and fails
	// spuriously about once in 800 runs across 256 bits — a flake this suite
	// would eventually hit. 30-70% is 9σ (p < 1e-15 per run) and still catches
	// everything this check is for, because a bit that is structurally 0 or 1
	// — the high bits of a counter, every bit of a constant — sits at exactly
	// 0% or 100%, not near the boundary.
	const (
		lowerBound = 0.30
		upperBound = 0.70
	)
	for bit := range SecretBytes * 8 {
		set := 0
		for _, secret := range secrets {
			if secret[bit/8]&(1<<(bit%8)) != 0 {
				set++
			}
		}
		ratio := float64(set) / float64(len(secrets))
		if ratio < lowerBound || ratio > upperBound {
			failures = append(failures, fmt.Sprintf("bit %d is set in %.0f%% of secrets", bit, ratio*100))
		}
	}
	return failures
}

// TestHashIsSHA256Hex pins the at-rest form against a vector computed outside
// this program (`printf %s '<token>' | sha256sum`). Recomputing it here with
// crypto/sha256 would assert only that sha256 equals itself; a stored hash
// outlives releases, so the constant is the point.
func TestHashIsSHA256Hex(t *testing.T) {
	const (
		token = "sphx_email_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		want  = "0ebb7977f02d59a77d5c0500b7df482e9698c2e7d293df6cbb25c8a7bcbe1acd"
	)
	if got := Hash(token); got != want {
		t.Errorf("Hash(a known token) = %q, want %q", got, want)
	}
	if got, want := len(Hash(token)), HashHexLen; got != want {
		t.Errorf("Hash returned %d characters, want HashHexLen = %d", got, want)
	}
	if got, want := Hash(""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"; got != want {
		t.Errorf("Hash(\"\") = %q, want %q", got, want)
	}
	if strings.Contains(Hash(token), "sphx") {
		t.Error("the hash contains the token's prefix — it is not a hash")
	}
}

// TestHashNeverEchoesTheToken: the at-rest form must share no run of the
// plaintext, so that grepping a database dump for `sphx_` finds nothing.
func TestHashNeverEchoesTheToken(t *testing.T) {
	minted, err := Mint("email")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	hash := Hash(minted)
	secret := strings.TrimPrefix(minted, "sphx_email_")
	for size := 6; size <= len(secret); size++ {
		for start := 0; start+size <= len(secret); start++ {
			if strings.Contains(hash, secret[start:start+size]) {
				t.Fatalf("the hash contains a %d-character run of the token's secret", size)
			}
		}
	}
}

func TestServiceOfRejectsAnythingButAWellFormedToken(t *testing.T) {
	good, err := Mint("email")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	secret := strings.TrimPrefix(good, "sphx_email_")

	for name, tc := range map[string]struct {
		token       string
		wantService string
		wantOK      bool
	}{
		"a minted token":        {good, "email", true},
		"another service":       {"sphx_billing_" + secret, "billing", true},
		"a hyphenated service":  {"sphx_email-relay_" + secret, "email-relay", true},
		"empty":                 {"", "", false},
		"no prefix":             {"email_" + secret, "", false},
		"a lookalike prefix":    {"sphx-email_" + secret, "", false},
		"the wrong prefix":      {"ghp_email_" + secret, "", false},
		"prefix only":           {"sphx_", "", false},
		"no separator":          {"sphx_email" + secret, "", false},
		"an empty service":      {"sphx__" + secret, "", false},
		"an uppercase service":  {"sphx_Email_" + secret, "", false},
		"a service with a dot":  {"sphx_email.v1_" + secret, "", false},
		"a trailing hyphen":     {"sphx_email-_" + secret, "", false},
		"a short secret":        {"sphx_email_" + secret[:len(secret)-1], "", false},
		"a long secret":         {"sphx_email_" + secret + "A", "", false},
		"a padded secret":       {"sphx_email_" + base64.URLEncoding.EncodeToString(make([]byte, SecretBytes)), "", false},
		"a non-base64 secret":   {"sphx_email_" + strings.Repeat("*", 43), "", false},
		"standard base64 chars": {"sphx_email_" + strings.Repeat("+", 43), "", false},
		"a trailing newline":    {good + "\n", "", false},
	} {
		service, ok := ServiceOf(tc.token)
		if ok != tc.wantOK || service != tc.wantService {
			t.Errorf("%s: ServiceOf = %q, %v; want %q, %v", name, service, ok, tc.wantService, tc.wantOK)
		}
	}
}

func TestMintRejectsServiceNamesThatWouldMakeTokensAmbiguous(t *testing.T) {
	for _, service := range []string{"", "_", "email_relay", "Email", "email.v1", "-email", "email-", "email relay", strings.Repeat("e", 64)} {
		if got, err := Mint(service); err == nil {
			t.Errorf("Mint(%q) succeeded and produced %q; want a rejected service name", service, got)
		} else if strings.Contains(err.Error(), "sphx_") {
			t.Errorf("Mint(%q) put a token in its error: %v", service, err)
		}
	}
	for _, service := range []string{"email", "e", "email-relay", "s3", "a-b-c", strings.Repeat("e", 63)} {
		if _, err := Mint(service); err != nil {
			t.Errorf("Mint(%q): %v", service, err)
		}
	}
}

// TestMintIsUniqueAcrossManyCalls is the property a caller relies on: two orgs
// never receive the same token.
func TestMintIsUniqueAcrossManyCalls(t *testing.T) {
	seen := make(map[string]bool, 4096)
	for range 4096 {
		minted, err := Mint("email")
		if err != nil {
			t.Fatalf("Mint: %v", err)
		}
		if seen[minted] {
			t.Fatal("Mint returned a token it had already returned")
		}
		seen[minted] = true
	}
}
