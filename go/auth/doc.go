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
// characters. No example token is written out anywhere in this repository, and
// none should be — a shape-valid literal in the package every tenant reads
// would match the very scanners the next paragraph exists to feed. [Mint] is
// the only way to make one. The `sphx_` prefix exists for SECRET SCANNING: it
// makes a
// leaked token greppable in a log, a repository or a CI artefact, and the
// `<service>` segment — the service's platform name, `email` rather than
// `email-service` — names the service that can verify it.
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
// # Rotation
//
// v1 has none, by decision (design 001 D-19). [Identity.TokenVersion] carries
// ADR 027 Decision 8's `token_version` — constant 1 in v1 — so ADR 020 can add
// rotation and revocation additively rather than by changing this package's
// exported surface.
package auth
