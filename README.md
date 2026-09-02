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
| `auth` | The platform's shared machine-to-machine bearer middleware (ADR 027): server interceptor, client interceptor, `TokenFromFile`, and the token format itself. It lives here rather than in a library of its own because every sphyrix service and every caller needs it *with* the stubs. | `go/auth` |

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

An absent, malformed, wrong-prefix, foreign-service or unknown token is one answer —
`UNAUTHENTICATED`, with nothing that tells a prober which it was. A handler that has an
authenticated caller and is asked for another org's resource answers `PERMISSION_DENIED`;
`auth.AuthorizeOrg(ctx, resourceOrg)` is that check, and it takes the org read from the
**resource**, never from the request. `auth.FromContext` reads the org the interceptor
established.

Rotation and revocation are not in v1 by decision (design 001 D-19). `auth.Identity.TokenVersion`
carries ADR 027's `token_version` — constant `1` — so
[ADR 020](https://github.com/sphyrix/infrastructure/blob/main/docs/adr/020-m2m-token-rotation-and-revocation.md)
can add them without changing this package's exported surface.

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
