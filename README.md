# sphyrix/contracts

The **public API contract** for every sphyrix-hosted service: every protobuf schema lives here,
together with the committed, generated Go SDK that every caller — on the platform or off it —
imports. There is deliberately no per-service proto — shared messages are defined once and are
the *same Go types* in every consumer, so services never convert between duplicate copies (which
would also trip protobuf's global registry with duplicate-registration panics).

This repo is **public**: tenants and off-platform callers must be able to `go get` it with **no
credentials** — no `GOPRIVATE`, no `GO_MODULES_TOKEN`, no git auth of any kind. That is the one
deliberate difference from its sibling contract repo,
[`huntful-contracts`](https://github.com/BecomingTheHunter/huntful-contracts) (private, tenant of
a different platform), which this repo otherwise mirrors structurally. See
[Differences from `huntful-contracts`](#differences-from-huntful-contracts) below.

GitHub plays the schema-registry role:

| Registry concern | How it's served |
|---|---|
| Schema source of truth | `proto/` in this repo |
| Versions | git tags (`vX.Y.Z`) |
| Generated SDK distribution | committed `gen/go/` via Go modules |
| Breaking-change enforcement | `buf breaking` in CI |
| "SDK matches schema" guarantee | CI regenerates and fails on any diff |

## Packages

| Package | Contents | Go import path |
|---|---|---|
| `hello.v1` | `SayHello` — a v0 smoke test proving the contract pipeline (buf lint → buf breaking → proto-gen → committed SDK → build) end to end before the first real sphyrix-hosted-service package lands. | `gen/go/hello/v1` |
| `email.v1` | `EmailService` (`SendEmail`, `GetMessage`) — the `email-service` API (design 001 §9.2). Postal's per-message token is deliberately not exposed. | `gen/go/email/v1` |

Alongside the generated stubs the module ships one hand-written package:

| Package | Contents | Go import path |
|---|---|---|
| `auth` | The platform's shared machine-to-machine bearer middleware (ADR 027): server interceptor, client interceptor, `TokenFromFile`, the token format itself, and `token_version` rotation/revocation (ADR 020) — the accepted-set verifier and the bump guardrail. It lives here rather than in a library of its own because every sphyrix service and every caller needs it *with* the stubs. | `go/auth` |

## Consuming (Go)

No credentials, no `GOPRIVATE`, no git config — this repo is public:

```sh
go get github.com/sphyrix/contracts@latest
```

```go
import (
    hellov1 "github.com/sphyrix/contracts/gen/go/hello/v1"
    "github.com/sphyrix/contracts/gen/go/hello/v1/hellov1connect"

    emailv1 "github.com/sphyrix/contracts/gen/go/email/v1"
    "github.com/sphyrix/contracts/gen/go/email/v1/emailv1connect"

    sphyrixauth "github.com/sphyrix/contracts/go/auth"
)
```

## M2M authentication (`go/auth`)

Every sphyrix-hosted service authenticates north-south callers with one convention
([ADR 027](https://github.com/sphyrix/infrastructure/blob/main/docs/adr/027-platform-m2m-token-convention.md)),
and `go/auth` is its only implementation — copy the convention, never the mechanism.

A token is **`sphx_<service>_` + 32 bytes of `crypto/rand`, base64url without padding**. The
`sphx_` prefix is there for **secret scanning**: it makes a leaked token greppable in a log, a
repository or a CI artefact, and the `<service>` segment names the service that can verify it.

Three rules bind everyone who touches one:

1. **Never log the token** — not at debug, not in an error, not as a trace attribute. Nothing in
   `go/auth` logs, formats or wraps a token or its hash into any message.
2. **Never log the `authorization` header.** Gateway access logs and OpenTelemetry HTTP
   attributes must drop it outright (design 001 §9.4).
3. **Store only the hash.** A verifying service persists `auth.Hash(token)` — SHA-256, lowercase
   hex — and looks it up as an *indexed key*. Verification is a lookup, never a comparison;
   unsalted SHA-256 is right precisely because the token is 256 random bits, which is also why
   bcrypt-class hashing buys nothing here.

### Calling a sphyrix service

```go
client := emailv1connect.NewEmailServiceClient(http.DefaultClient,
    "https://email.dev.sphyrix.cloud",
    connect.WithInterceptors(sphyrixauth.NewClientInterceptor(
        sphyrixauth.TokenFromFile("/var/run/sphyrix/becoming-the-hunter/platform/email/token"))))
```

`TokenFromFile` **re-reads the mounted file on change**, within `DefaultRefreshInterval`. That is
not an optimisation to skip: the token is re-minted on every dev/test `up` and after a
Postgres-only prod restore, so a consumer that caches it for the process lifetime breaks after
every cycle and stays broken until somebody restarts it. Off-platform callers, which receive the
token once into a CI secret store (ADR 019), use `sphyrixauth.StaticToken` instead.

### Serving one

```go
interceptor, err := sphyrixauth.NewInterceptor("email", store) // store implements auth.TokenStore
// ...
mux.Handle(emailv1connect.NewEmailServiceHandler(svc, connect.WithInterceptors(interceptor)))
```

`LookupTokenHash` must return **both** versions on the `Identity` it yields —
`TokenVersion` (what the found row was minted at) and `AppliedTokenVersion` (the org's applied
`token_version`). The interceptor checks the first against the accepted set derived from the
second, and answers `INTERNAL` if either is missing: a store that cannot be version-checked must
not be mistaken for one that accepts anything.

An absent, malformed, wrong-prefix, foreign-service or unknown token is one answer —
`UNAUTHENTICATED`, with nothing that tells a prober which it was. A handler that has an
authenticated caller and is asked for another org's resource answers `PERMISSION_DENIED`;
`auth.AuthorizeOrg(ctx, resourceOrg)` is that check, and it takes the org read from the
**resource**, never from the request. `auth.FromContext` reads the org the interceptor
established.

### Rotating and revoking a token

Rotation and revocation both ride on **one control**, and that control is `token_version`
([ADR 020](https://github.com/sphyrix/infrastructure/blob/main/docs/adr/020-m2m-token-rotation-and-revocation.md)).
It is **platform-wide**: `token_version` is the single control for **every** platform M2M token of
this class ([ADR 027](https://github.com/sphyrix/infrastructure/blob/main/docs/adr/027-platform-m2m-token-convention.md)),
so a second sphyrix service copies this convention rather than inventing a `revoked` flag, an
expiry, or any other second source of truth about whether a token is live. ADR 020 considered and
rejected a `revoked = true` field for exactly that reason: a second control saying what a second
bump already says is a second thing to keep consistent.

The version is **org-authored** — `[email].token_version` in the org's own tenant platform repo, an
optional integer ≥ 1 defaulting to `1`. Rotation is self-service: an org rotates on its own
schedule, with no custodian PR. (`1` is a *baseline*, not a constant — an org that has rotated is
at `2` or more.)

Raising it **mints the new token beside the current one**, and both authenticate. The verifier
therefore checks an **accepted set** — `auth.AcceptedVersions` / `auth.VersionAccepted`, enforced by
the interceptor on every request — which holds at most `auth.LiveVersions` (2) versions: `N` and
`N-1`. `N-2` is refused. So there is never a window in which a consumer holds no valid token, and
the consumer cuts over on its own schedule via whichever delivery path it has.

#### Revoking a token: two commits

> **One bump mints; it does not revoke.** Raising `token_version` by one adds the new version
> *beside* the old one — the old token keeps working. The intuitive single edit is a **rotation**,
> not a revocation, and reaching for it in an incident leaves the compromised token live. Revoking
> takes **two commits**.

To retire a token that is live at version `N` (a leak, a compromise, an offboarded consumer):

1. **Bump `[email].token_version` from `N` to `N+1`** in the org's tenant platform repo, and merge.
   The service mints version `N+1` **beside** `N`. Both authenticate. **Nothing is revoked yet** —
   the accepted set is now `{N, N+1}`.
2. **Deliver `N+1` to every consumer.** On-platform consumers need no action: VSO refreshes the
   mounted `VaultStaticSecret` (`refreshAfter: 1m`) and `auth.TokenFromFile` re-reads it. For every
   **off-platform** consumer, rerun the devtools delivery command
   ([ADR 019](https://github.com/sphyrix/infrastructure/blob/main/docs/adr/019-off-platform-m2m-token-delivery.md))
   — its run record is the only inventory of who holds what. Skipping this step is what step 4
   breaks.
3. **Wait out the interval, and confirm `N+1` is actually in use.** At least
   `auth.DefaultMinBumpInterval` (15 minutes) must have passed since step 1.
   `auth.BumpGuard.CheckBump` enforces that and refuses step 4 until it holds, naming which check
   failed; there is no way to spell "no interval".

   **When nobody will ever use `N+1`:** the evidence half is waivable, via
   `BumpGuard.Evidence = auth.EvidenceOptional` — the interval alone then gates step 4. That is ADR
   020's *"a minimum interval, **or** a check that the new version is in use"*, and it is the right
   setting when the consumer has been offboarded, has not gone live yet, or sends too infrequently
   to authenticate inside any sane window; otherwise the guardrail would block the only revocation
   path there is. Rely on the ADR 019 delivery run record for who actually holds what — it is
   evidence `go/auth` cannot see.

   **This is a service-level setting, not something you flip mid-incident.** It is decided once by
   the verifying service, from whether that service records last use at all; an operator working
   through this procedure has no way to set a Go struct field, and no control surface for a
   per-org waiver exists in v1. A service that does not track last use **must** set
   `EvidenceOptional`, or its only revocation path is unreachable in production. If step 4 is
   refused for want of evidence and the service is configured strict, that is a service
   configuration bug — escalate it, do not work around it.
4. **Bump `token_version` from `N+1` to `N+2`** and merge. This mints `N+2` and **retires `N`** —
   the accepted set becomes `{N+1, N+2}`, and the compromised token stops authenticating. *This*
   commit is the revocation.

Exposure is therefore bounded by how fast the two commits are made, not by an instant kill — the
accepted trade for zero-downtime rotation through one control (ADR 020, Consequences). There is no
custodian-side override in v1: sphyrix cannot revoke an org's token without that org committing the
bumps.

The guardrail in step 3 exists because bumping twice faster than consumers can pick the new token up
retires a version somebody is still using. It belongs in the tooling, not in an operator's head:

```go
guard := sphyrixauth.BumpGuard{} // DefaultMinBumpInterval, real clock, evidence required
err := guard.CheckBump(sphyrixauth.RotationState{
    Applied:           applied,    // orgs.token_version
    AppliedAt:         appliedAt,  // tokens.created_at for that version
    AppliedLastUsedAt: lastUsedAt, // see below — NOT a column design 001 §9.5 has
}, declared)                       // the org's newly declared token_version
```

`Applied` and `AppliedAt` come straight out of design 001 §9.5. **`AppliedLastUsedAt` does not** —
there is no last-used column on `orgs` or `tokens`, and Story 11.2 does not add one. Recording it
costs a write on the authentication path, so it is a deliberate choice: a service that does not
track it leaves the field zero and sets `Evidence: auth.EvidenceOptional`.

A refusal never reaches the org — the bump is already merged in the org's own repo — so the service
must surface a held bump where an operator will see it (`orgs.last_error`, `email_org_ready{org}`).
Otherwise an incident responder merges step 4, sees the repo say `N+2`, and believes the compromised
token is dead while the service is still at `N+1` with `N` live.

A refusal means **hold the whole bump** — mint nothing and retire nothing — and report the reason.
Applying the mint while deferring the retirement would put three versions in flight and break the
at-most-two invariant.

> **Anchor — do not rename the heading.** `docs/runbooks/email-onboarding.md` in
> `sphyrix/infrastructure` (Story 12.3) links to the procedure above as
> `https://github.com/sphyrix/contracts/blob/main/README.md#revoking-a-token-two-commits`. GitHub
> derives that anchor from the heading text "Revoking a token: two commits", so editing the heading
> silently breaks the runbook's link. `TestTheReadmeDocumentsTheTwoCommitRevocation` pins it.

#### Writing the new token to Vault (`cas`)

[#488](https://github.com/sphyrix/infrastructure/issues/488) arms the KV v2 mount with
`cas_required=true`, and mint-beside **overwrites** `kv/data/<org>/platform/<service>/token` — so
the write must carry `cas` = the secret's current version.

> **ADR 027 Decision 4 amendment (human ruling, 2026-09-02).** Decision 4 originally granted the
> verifying service `create`/`update` on `kv/data/+/platform/<service>/*` with *"no `read`, `delete`
> or `kv/metadata` grant"*, which left it unable to learn the number it is required to send. It now
> also gets **`read` on `kv/metadata/+/platform/<service>/*`, and only there** — that path yields
> the **version, never the value**, so token values stay unreadable across orgs and the narrow
> cross-tenant write path is otherwise unchanged. #488 records the same ruling as ADR 024
> Amendment 4.

The bump is therefore: **metadata read → write with `cas=<current version>`**, and on a refusal,
re-read and try again, bounded. `auth.CASWriter` is that procedure:

```go
err := sphyrixauth.CASWriter{Version: metadataReader}.Write(ctx, org,
    func(ctx context.Context, cas int) error {
        // write kv/data/<org>/platform/<service>/token with this cas;
        // return auth.ErrCASRefused when Vault rejects it
    })
```

The re-read is the whole point: retrying with the same `cas` cannot succeed, because the version is
exactly what was wrong. Only `ErrCASRefused` is retried — any other write error fails the mint at
once, since retrying an error whose cause is unknown is how a bounded loop becomes an unbounded one.

A refused `cas` means the path moved between the read and the write. Under ADR 027 Decision 5 that
is normally the **tenant itself**, which holds `tenant-rw` on its own path. After
`auth.DefaultCASAttempts` (3) the mint gives up with `auth.ErrCASExhausted` and **nothing is
written** — report that loudly, on the same channel as a held bump (`orgs.last_error`,
`email_org_ready{org}`). It means something is rewriting an org's token path repeatedly, and a mint
that gave up quietly would leave the org with no new token and nobody looking.

The version source stays behind `auth.TokenPathVersion`:

```go
type TokenPathVersion interface {
    CurrentVersion(ctx context.Context, org string) (int, error)
}
```

The **metadata read is the ruled and supported implementation**; the seam is kept because a service
that tracks the version itself satisfies the same contract, but a service that invents another
source is off the platform convention. `go/auth` holds no Vault client and must never acquire one —
hence `ctx`, an org and an `int`. An error from `CurrentVersion` **fails the mint**: never guess a
`cas`. A wrong one is refused by Vault, which is the safe direction — nothing is written, no hash
row is stored, and the next resync retries, exactly as ADR 027 Decision 3's Vault-first ordering
provides for.

## Editing the contract

Tooling runs through `sphyrix/devtools` (host needs Docker + `just`):

```sh
just proto-lint       # buf lint
just proto-breaking   # buf breaking vs main — the compatibility gate
just proto-gen        # regenerate gen/go (commit the result)
just build            # prove the generated SDK compiles
just test             # module tests (the descriptor assertions and go/auth)
just lint             # golangci-lint over the module
```

Rules:

- **Generated code is committed.** After any `proto/` change, run
  `just proto-gen` and commit `gen/` in the same PR — CI fails on drift.
- **Never break the contract.** `buf breaking` (FILE level) gates every PR;
  additive evolution only. New majors go in a new package (`hello.v2`), not
  in-place edits.
- **Tag to release.** Consumers pin tags (`vX.Y.Z`); a merged PR is not
  consumable until tagged. See [`docs/RELEASING.md`](docs/RELEASING.md) for the exact
  procedure.

## Layout

```
proto/hello/v1/hello.proto        # schema source of truth
proto/email/v1/email.proto        # schema source of truth
gen/go/hello/v1/                  # generated: protobuf types
gen/go/hello/v1/hellov1connect/   # generated: connect-go handlers/clients
gen/go/email/v1/                  # generated: protobuf types
gen/go/email/v1/emailv1connect/   # generated: connect-go handlers/clients
go/auth/                          # hand-written: the M2M bearer middleware (ADR 027)
contractcheck/                    # cross-package descriptor assertions (e.g. no Postal secrets)
docs/                             # design docs (000-, 001-, ...)
```

Plugins (`protoc-gen-go`, `protoc-gen-connect-go`) run via `go run` pinned by
`go.mod` — nothing to install, identical output everywhere.

## Differences from `huntful-contracts`

This repo is a structural mirror of `huntful-contracts` (design 001 §10). Recorded differences:

| | `huntful-contracts` | `sphyrix/contracts` |
|---|---|---|
| Visibility | private (`GO_MODULES_TOKEN`/`GOPRIVATE` required) | **public** — no credentials required |
| Module | `github.com/BecomingTheHunter/huntful-contracts` | `github.com/sphyrix/contracts` |
| Packages | `hello.v1`, `iam.v1`, `user.v1`, … (10 domain packages) | `hello.v1`, `email.v1` (Story 9.2); further `<domain>.v1` packages land per sphyrix-hosted service in follow-on stories |
| Extra | — | `go/auth` — the M2M bearer middleware (ADR 027) |

Implementation-detail differences not called out in §10's table, justified here:

- **No lint exceptions.** `huntful-contracts`' `buf.yaml` excepts
  `RPC_REQUEST_STANDARD_NAME`/`RPC_RESPONSE_STANDARD_NAME` for legacy naming on its original
  `hello.v1` (`HelloRequest`/`HelloReply` predate `buf`'s standard-name lint rule). This repo is
  new with no such history, so its `hello.v1` uses buf-standard names
  (`SayHelloRequest`/`SayHelloResponse`) from the start and needs no exception.
- **No `breaking.ignore_only`.** `huntful-contracts`' one-off `FILE_SAME_GO_PACKAGE` ignore exists
  because that repo's GitHub org was renamed after `go_package` values were already tagged. This
  repo has no such history.
- **`buf.gen.yaml` has no `managed` block.** `huntful-contracts` uses managed mode to rewrite
  `go_package` for a vendored, upstream-authored proto (CloudEvents) and to pin one alias
  (`feature_flags.v1`) that diverges from managed mode's default derivation. This repo vendors no
  third-party proto and every file declares its own `go_package` explicitly, so managed mode has
  nothing to do yet — it will be added if a future package needs it.
- **No CloudEvents-pin CI step.** `huntful-contracts` vendors `cloudevents/spec`'s envelope proto
  and CI byte-diffs it against a pinned upstream commit. This repo vendors no third-party proto.
- **No "no nats.go" CI guard.** That guard exists in `huntful-contracts` because its `events/`
  sub-module (since moved to `huntful-go`) once risked leaking a NATS dependency into the main
  module. This repo has never had that sub-module.
- **No `docs/adr/`, `docs/tickets/`, `docs/runbooks/` yet.** `huntful-contracts` accumulated these
  over many stories; this repo has no internal architecture decisions, ticket-backlog docs, or
  runbooks of its own yet. Directories are added when they have real content — Epic 9's own
  backlog and design record live in the `sphyrix/infrastructure` repo (see
  [`docs/001-sphyrix-contracts.md`](docs/001-sphyrix-contracts.md)).
- **No `CHANGELOG.md` yet.** `huntful-contracts`' changelog starts at its `v0.3.0` tag; this repo
  has not tagged a release yet (Story 9.2 tags `v0.1.0`).
