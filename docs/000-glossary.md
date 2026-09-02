# 000 — Glossary

> **Living document.** The single source of truth for this repo's project-specific terminology.
> Design docs link here on a term's first use instead of redefining it. Terms are alphabetical;
> add new ones in place.

No domain terms are defined here yet. `email.v1` (Story 9.2) introduces no repo-specific
terminology beyond what design 001 §9.2 and §2 already define — see
[`docs/001-sphyrix-contracts.md`](001-sphyrix-contracts.md). `go/auth` (Story 9.3) has landed and
introduces none either: token, hash, org and `token_version` are the platform's M2M convention,
defined in ADR 027 and in the `sphyrix/infrastructure` glossary, not here. Terms specific to a
future package are added as those packages land.

Platform-wide terms (org, tenant, addon, the M2M token convention, …) are defined in the
`sphyrix/infrastructure` repo's own glossary and design docs; this glossary only holds terms
specific to this contract repo's own packages and tooling.
