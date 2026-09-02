package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

const (
	// Prefix begins every sphyrix M2M token (ADR 027 Decision 1). It is not
	// decoration: it is what makes a leaked token greppable in a log, a
	// repository or a CI artefact, so secret scanners can be pointed at a
	// literal string. Changing it would blind every scanner already looking
	// for it.
	Prefix = "sphx_"

	// SecretBytes is the entropy behind every token: 32 bytes — 256 bits —
	// drawn from crypto/rand. This number is why unsalted SHA-256 is the
	// correct at-rest form (ADR 027 Decision 2): there is no dictionary to
	// precompute against 256 random bits.
	SecretBytes = 32

	// HashHexLen is the length of [Hash]'s output: SHA-256, lowercase hex.
	HashHexLen = 2 * sha256.Size

	// maxServiceLen bounds the `<service>` segment, which is DNS-label shaped.
	//
	// The segment is the service's PLATFORM name — the `<service>` of
	// `kv/data/<org>/platform/<service>/token` and of the mount
	// `/var/run/sphyrix/<org>/platform/<service>/` (ADR 027 Decisions 4 and 5).
	// For the first consumer that is `email`, not the repository or workload
	// name `email-service`: a token minted as `sphx_email-service_…` would not
	// match the `platform/email/` path its own delivery is rendered for.
	maxServiceLen = 63

	// separator ends the `<service>` segment. Service names may not contain
	// it, so the split is unambiguous.
	separator = "_"
)

// secretEncodedLen is how many characters [SecretBytes] occupies in unpadded
// base64url: 43.
var secretEncodedLen = base64.RawURLEncoding.EncodedLen(SecretBytes)

// Mint returns a new token for service: `sphx_<service>_` + [SecretBytes] of
// crypto/rand, base64url-encoded without padding (ADR 027 Decision 1).
//
// The verifying service mints on first sight of an org's declared config,
// writes the plaintext to Vault FIRST and stores [Hash]'s output second (ADR
// 027 Decision 3), and never reads a token VALUE back out of Vault.
//
// "Never reads Vault back" is qualified to values as of the 2026-09-02 ruling:
// on an armed KV v2 mount the mint reads `kv/metadata/...` for the check-and-set
// VERSION (see [TokenPathVersion] and [CASWriter]). That is the same
// values-versus-metadata line that made the ADR 027 Decision 4 amendment
// acceptable — the version is not the secret. No path in this package or in a
// service following it reads a token value back.
//
// The plaintext returned here is
// the only copy this process will ever hold: do not log it, do not put it in
// an error, and drop it as soon as it has been written.
//
// The error is a rejected service name or a failure of the system entropy
// source; it never carries the token.
func Mint(service string) (string, error) {
	return mint(service, rand.Read)
}

// mint is [Mint] with the entropy source as a parameter, so a test can drive
// the same code with a deliberately non-random source and prove that the
// entropy assertions can actually fail. It is unexported on purpose: no
// consumer may substitute the source, and TestMintUsesCryptoRandOnly pins the
// one call site to crypto/rand.
func mint(service string, read func([]byte) (int, error)) (string, error) {
	if err := validateService(service); err != nil {
		return "", err
	}
	secret := make([]byte, SecretBytes)
	if _, err := read(secret); err != nil {
		return "", fmt.Errorf("auth: drawing %d bytes of entropy: %w", SecretBytes, err)
	}
	return Prefix + service + separator + base64.RawURLEncoding.EncodeToString(secret), nil
}

// Hash returns the at-rest form of a token: SHA-256 of the exact bytes the
// caller presented, lowercase hex, [HashHexLen] characters.
//
// This is the value a verifying service stores and the key it looks up by
// (design 001 §9.5's `tokens.sha256`). It is a stable part of the platform
// contract — a stored hash outlives any one release, so the algorithm and the
// encoding may not change without a migration.
//
// There is no constant-time comparison here because there is no comparison:
// [Interceptor] hands this to a [TokenStore] as an INDEXED LOOKUP KEY (ADR 027
// Decision 2). A store implementation that instead scans rows comparing hashes
// has reintroduced the timing question this design removes.
func Hash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// ServiceOf returns the `<service>` segment of a well-formed token and reports
// whether the token is well formed at all: the `sphx_` prefix, a valid service
// name, and exactly [SecretBytes] of base64url after it.
//
// It is a SHAPE check, not authentication — it proves nothing about whether
// any org holds the token. It exists so [Interceptor] can refuse a token that
// cannot possibly be one of ours without spending a store lookup on it, and so
// a store implementation can shard by service.
func ServiceOf(token string) (string, bool) {
	rest, ok := strings.CutPrefix(token, Prefix)
	if !ok {
		return "", false
	}
	service, secret, ok := strings.Cut(rest, separator)
	if !ok {
		return "", false
	}
	if validateService(service) != nil {
		return "", false
	}
	if len(secret) != secretEncodedLen {
		return "", false
	}
	if _, err := base64.RawURLEncoding.DecodeString(secret); err != nil {
		return "", false
	}
	return service, true
}

// validateService accepts a DNS-label-shaped service name: lowercase
// alphanumerics and interior hyphens. Underscores are excluded because the
// token format uses one as the separator, so allowing them would make
// `sphx_<service>_<secret>` ambiguous.
func validateService(service string) error {
	if service == "" {
		return errors.New("auth: the service name is empty")
	}
	if len(service) > maxServiceLen {
		return fmt.Errorf("auth: the service name is %d characters, at most %d are allowed", len(service), maxServiceLen)
	}
	for i := 0; i < len(service); i++ {
		c := service[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '-' && i > 0 && i < len(service)-1:
		default:
			return fmt.Errorf("auth: %q is not a valid service name: lowercase letters, digits and interior hyphens only", service)
		}
	}
	return nil
}
