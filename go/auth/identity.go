package auth

import (
	"context"
)

// Identity is everything a handler learns about its caller: the org the
// presented token belongs to.
//
// The token is deliberately NOT here, in any form. A context is read by every
// handler, every middleware and every logging helper in a process; a token
// placed in one would reach a log the first time somebody logged the context's
// contents. What reaches a handler is the org, which is not a secret.
type Identity struct {
	// Org is the tenant the token belongs to — the unit of billing, quota and
	// configuration (ADR 027 Context). Never empty on an Identity that came
	// from [Interceptor].
	Org string

	// TokenVersion is the `token_version` the PRESENTED token was minted at —
	// design 001 §9.5's `tokens.version`, carried so a handler can record
	// which version authenticated a request.
	//
	// It is not necessarily AppliedTokenVersion: during ADR 020's rotation
	// window a consumer that has not cut over yet authenticates with the
	// previous version, and that is the mechanism working, not a fault.
	TokenVersion int32

	// AppliedTokenVersion is the org's applied `token_version` — design 001
	// §9.5's `orgs.token_version`, ADR 020's single control for rotation and
	// revocation.
	//
	// A [TokenStore] MUST set it: [Interceptor] refuses the request outright
	// if it is below [FirstTokenVersion], because a store that does not report
	// the applied version is a store against which the accepted set cannot be
	// checked, and treating that as "accept anything" would silently turn
	// revocation off.
	AppliedTokenVersion int32
}

// contextKey is unexported, so nothing outside this package can plant an
// Identity in a context that did not come through [Interceptor].
type contextKey struct{}

// NewContext returns ctx carrying identity. [Interceptor] calls it; it is
// exported for tests and for a service that authenticates some other way (an
// in-cluster mesh caller with SPIFFE identity, say — ADR 001) and wants its
// handlers to read the same shape.
func NewContext(ctx context.Context, identity Identity) context.Context {
	return context.WithValue(ctx, contextKey{}, identity)
}

// FromContext returns the authenticated caller's identity. ok is false on a
// request that was not authenticated by [Interceptor] — an exempt procedure,
// or a context that never went through it.
func FromContext(ctx context.Context) (Identity, bool) {
	identity, ok := ctx.Value(contextKey{}).(Identity)
	return identity, ok
}

// OrgFromContext is [FromContext] for the common case: the caller's org, or ""
// and false when the request was not authenticated.
func OrgFromContext(ctx context.Context) (string, bool) {
	identity, ok := FromContext(ctx)
	if !ok {
		return "", false
	}
	return identity.Org, true
}

// AuthorizeOrg is ADR 027 Decision 6's second half, and the only correct way to
// answer "may this caller touch this row?".
//
// [Interceptor] establishes WHO is calling; it cannot know what they own, so
// ownership is checked where the resource is loaded. Pass the org that owns
// the resource — the `org` column of the row just read, the org that declared
// the sender being used. The result is nil when the caller owns it,
// `PERMISSION_DENIED` when a valid caller asked for something else's, and
// `UNAUTHENTICATED` when there is no authenticated caller at all.
//
// Call it with the org read from the RESOURCE, never with the org read from
// the request: comparing the caller's org to itself always succeeds and is the
// shape this function exists to prevent.
//
// The returned errors are contentless. A caller learns that it may not have
// the resource, never whether the resource exists.
func AuthorizeOrg(ctx context.Context, resourceOrg string) error {
	identity, ok := FromContext(ctx)
	if !ok {
		return errUnauthenticated()
	}
	// An unowned resource belongs to nobody, so it belongs to no caller
	// either; identity.Org is never empty, but neither half is trusted to be
	// non-empty here, because "" == "" must never authorize anything.
	if identity.Org == "" || resourceOrg == "" || identity.Org != resourceOrg {
		return errPermissionDenied()
	}
	return nil
}
