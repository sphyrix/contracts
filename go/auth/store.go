package auth

import (
	"context"
	"errors"
)

// ErrTokenNotFound is what a [TokenStore] returns when no org holds a token
// with the given hash. It is the ONLY error that means "the caller's token is
// bad"; every other error means the store could not answer, which is this
// service's problem and not the caller's, and is reported as `UNAVAILABLE`
// rather than `UNAUTHENTICATED`.
var ErrTokenNotFound = errors.New("auth: no org holds that token")

// TokenStore is the verifying service's index of live tokens — design 001
// §9.5's `tokens` table, behind an interface so this package depends on no
// database.
//
// It is deliberately one method taking one hash. There is no "look up this
// token" and no "compare these two": the plaintext never leaves
// [Interceptor], and a store that grew a plaintext-taking method would be
// carrying the secret into the persistence layer, which ADR 027 Decision 2
// exists to prevent.
type TokenStore interface {
	// LookupTokenHash returns the identity that holds the token whose SHA-256
	// is sha256Hex — lowercase hex, [HashHexLen] characters, exactly what
	// [Hash] returns.
	//
	// Implementations must:
	//
	//   - look sha256Hex up as an INDEXED KEY, not scan and compare. A scan
	//     reintroduces the timing question the hash-lookup design removes, and
	//     turns every request into a table scan.
	//   - return [ErrTokenNotFound], wrapped or bare, for "no such token", and
	//     return it for a hash that is malformed too — an unrecognisable key
	//     is an unknown key, not a store failure.
	//   - never put the hash, and certainly never a token, into a returned
	//     error. [Interceptor] logs store errors.
	//   - be safe for concurrent use.
	LookupTokenHash(ctx context.Context, sha256Hex string) (Identity, error)
}
