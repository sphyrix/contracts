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

`email.v1` (the `email-service` API, design 001 §9.2, ADR 027) and `go/auth` (the shared M2M
bearer middleware, ADR 027) land in follow-on stories (Epic 9, Stories 9.2–9.4) on top of this
scaffold.

## Consuming (Go)

No credentials, no `GOPRIVATE`, no git config — this repo is public:

```sh
go get github.com/sphyrix/contracts@latest
```

```go
import (
    hellov1 "github.com/sphyrix/contracts/gen/go/hello/v1"
    "github.com/sphyrix/contracts/gen/go/hello/v1/hellov1connect"
)
```

## Editing the contract

Tooling runs through `sphyrix/devtools` (host needs Docker + `just`):

```sh
just proto-lint       # buf lint
just proto-breaking   # buf breaking vs main — the compatibility gate
just proto-gen        # regenerate gen/go (commit the result)
just build            # prove the generated SDK compiles
just test             # module tests
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
gen/go/hello/v1/                  # generated: protobuf types
gen/go/hello/v1/hellov1connect/   # generated: connect-go handlers/clients
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
| Packages | `hello.v1`, `iam.v1`, `user.v1`, … (10 domain packages) | `hello.v1` only (this story); `email.v1` and further `<domain>.v1` packages land per sphyrix-hosted service in follow-on stories |
| Extra | — | `go/auth` — the M2M bearer middleware (ADR 027), lands in Story 9.3 |

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
