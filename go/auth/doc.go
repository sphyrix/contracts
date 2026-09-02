// Package auth is the sphyrix platform's shared machine-to-machine (M2M)
// bearer-token middleware: the one implementation of ADR 027 that every
// sphyrix-hosted service and every caller — on the platform or off it —
// imports, so the convention is copied rather than the mechanism reinvented.
//
// It ships in github.com/sphyrix/contracts, the same module as the generated
// protobuf/Connect stubs, because a caller needs the middleware with the stubs
// (design 001 §10).
//
// # The token
//
// A token is `sphx_<service>_` + 32 bytes of crypto/rand, base64url-encoded
// without padding (ADR 027 Decision 1): `sphx_email_` followed by 43 base64url
// characters. [Mint] is the only way to make one.
//
// No example token is written out in this documentation, deliberately: a
// shape-valid literal in the package every tenant reads would match the very
// scanners the prefix exists to feed. This package's tests hold exactly one
// such literal — 43 identical characters, pinning a stored-hash vector that has
// to be exact — and that is the only place one belongs.
//
// The `sphx_` prefix exists for SECRET SCANNING: it makes a leaked token
// greppable in a log, a repository or a CI artefact, and the `<service>`
// segment — the service's platform name, `email` rather than `email-service` —
// names the service that can verify it.
//
// # Obligations on every caller of this package
//
//   - NEVER LOG THE TOKEN. Not at debug, not in an error, not in a trace
//     attribute, not in a panic. Nothing in this package logs, formats or
//     wraps a token or its hash into any message, and a [TokenStore]
//     implementation must not either.
//   - NEVER LOG THE `authorization` HEADER. Design 001 §9.4 makes this an
//     obligation on the gateway's access logs and on OpenTelemetry HTTP
//     attributes: both must drop `authorization` outright. A header allow-list
//     or redaction rule that a future refactor can silently lose is not enough.
//   - Store only the hash. The plaintext exists in memory during minting and
//     at rest only in Vault (ADR 027 Decision 2); a verifying service persists
//     [Hash]'s output and nothing else.
//   - Serve tokens over TLS only. Bearer semantics mean possession is access.
//
// # Verification is a lookup, not a comparison
//
// [Interceptor] hashes the presented token with SHA-256 and hands the hash to
// a [TokenStore], which looks it up by that hash as an indexed key. It never
// sees, compares or stores plaintext. Unsalted SHA-256 is sufficient — and
// bcrypt-class hashing unnecessary — precisely because the token is 256 random
// bits: there is no dictionary to precompute (ADR 027 Decision 2).
//
// # Server side
//
//	interceptor, err := auth.NewInterceptor("email", store)
//	// ...
//	mux.Handle(emailv1connect.NewEmailServiceHandler(svc,
//	    connect.WithInterceptors(interceptor)))
//
// An absent, malformed, wrong-prefix, foreign-service or unknown token is one
// answer — `UNAUTHENTICATED`, with no detail that would tell a prober which it
// was. A handler that has an authenticated caller and is asked for another
// org's resource answers `PERMISSION_DENIED`; [AuthorizeOrg] is that check.
// [FromContext] reads the org the interceptor established.
//
// # Client side
//
//	client := emailv1connect.NewEmailServiceClient(http.DefaultClient,
//	    "https://email.dev.sphyrix.cloud",
//	    connect.WithInterceptors(auth.NewClientInterceptor(
//	        auth.TokenFromFile("/var/run/sphyrix/becoming-the-hunter/platform/email/token"))))
//
// [TokenFromFile] RE-READS the mounted file on change, within a bounded
// interval. This is not an optimisation to skip: the token is re-minted on
// every dev/test `up` and after a Postgres-only prod restore (design 001 §10,
// §13), so a consumer that caches it for the process lifetime breaks after
// every cycle and stays broken until it is restarted.
//
// # Rotation and revocation
//
// ADR 020: rotation AND revocation both ride on one control, and that control
// is `token_version`. It is PLATFORM-WIDE — the single control for every
// platform M2M token of this class (ADR 027) — so a second sphyrix service
// copies this convention rather than inventing a `revoked` flag, an expiry, or
// any other second source of truth about whether a token is live.
//
// The version is ORG-AUTHORED: `[email].token_version` in the org's own tenant
// platform repo, an optional integer of at least 1, defaulting to 1. Rotation
// is self-service — an org rotates on its own schedule, with no custodian PR —
// and 1 is a baseline, not a constant: an org that has rotated is at 2 or more.
//
// Three properties, in the order they happen:
//
//   - Bump, then MINT BESIDE. Raising the version mints the new token
//     alongside the current one and both authenticate, so there is never a
//     window in which a consumer holds no valid token.
//   - The consumer CUTS OVER on its own schedule, by whichever delivery path
//     it has: the VSO-refreshed mount on-platform ([TokenFromFile]), a rerun
//     of the devtools delivery command off-platform (ADR 019).
//   - The FOLLOWING bump REVOKES. Bumping to N mints N beside N-1; bumping to
//     N+1 mints N+1 and retires N-1. At most [LiveVersions] are ever live.
//
// So ONE BUMP MINTS AND DOES NOT REVOKE. Revoking a token takes TWO COMMITS —
// the first mints its replacement, the second one kills it — and the numbered
// procedure is in this module's README under "Revoking a token: two commits".
// It is written down as a procedure because somebody reaching for it in an
// incident will assume the single obvious edit revokes, and it mints.
//
// Verification is therefore against an ACCEPTED SET of `token_version`s rather
// than against a single value. [AcceptedVersions] and [VersionAccepted] are
// that set, [Interceptor] enforces it on every request, and [RetiredBy] is the
// other half — what a bump takes away. A [TokenStore] must report both
// [Identity.TokenVersion] and [Identity.AppliedTokenVersion], because without
// the applied version there is no set to check against.
//
// This package therefore spans two things: the bearer middleware a caller uses
// on every request, and the ruled token LIFECYCLE a verifying service runs on a
// bump. It still holds no Vault client and must never acquire one — the
// lifecycle half is expressed as interfaces and a retry loop, and the Vault
// call itself belongs to the service.
//
// Writing the new token is a check-and-set: #488 arms the KV v2 mount, so a
// mint reads the current version from `kv/metadata/+/platform/<service>/*`
// (the version, never the value — the ADR 027 Decision 4 amendment of
// 2026-09-02) and writes with that `cas`, retrying after a fresh read if the
// path moved. [CASWriter] is that procedure and [TokenPathVersion] is the
// version source.
//
// [BumpGuard] is ADR 020's guardrail. Two bumps closer together than consumers
// can pick the new token up would retire a version somebody is still holding,
// so the minimum interval and the evidence-of-use check belong in the tooling
// rather than in an operator's head.
//
// The interval is never waivable. The evidence half is, through
// [EvidencePolicy] — ADR 020 asks for "a minimum interval, OR a check that the
// new version is in use", and a service that does not record last use would
// otherwise find revocation unreachable. [EvidenceRequired] is the zero value
// and every unrecognised value is strict too; [EvidenceOptional] is the one
// opt-out, and it is a service-level setting rather than a per-incident knob.
package auth
