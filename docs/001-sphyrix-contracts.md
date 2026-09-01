# 001 — `sphyrix/contracts`

This repo's design record is not written here — it is
[design 001 — Sphyrix email platform](https://github.com/sphyrix/infrastructure/blob/main/docs/001-sphyrix-email-platform.md)
§10, in the `sphyrix/infrastructure` repo, plus:

- [ADR 027 — Platform machine-to-machine token convention](https://github.com/sphyrix/infrastructure/blob/main/docs/adr/027-platform-m2m-token-convention.md)
  — ground truth for the `go/auth` package and the token format/delivery convention it implements.
- [ADR 019 — Off-platform M2M token delivery](https://github.com/sphyrix/infrastructure/blob/main/docs/adr/019-off-platform-m2m-token-delivery.md)
- [ADR 020 — M2M token rotation and revocation](https://github.com/sphyrix/infrastructure/blob/main/docs/adr/020-m2m-token-rotation-and-revocation.md)
- The ticket backlog: `docs/tickets/001-sphyrix-email-platform-tickets.md` Epic 9, in the same repo.

`sphyrix/infrastructure` is where every sphyrix-hosted service, addon and platform component is
designed and ticketed — this repo is one of its cross-repo deliverables (`sphyrix/contracts`, §14
row 9). Read the linked design and ADRs for the *why*; this repo's own `README.md` and package
table are the *what*, kept current as packages land.

This repo's own `docs/NNN-*.md` numbering continues from here for anything that is genuinely this
repo's own design record (its tooling, its release process) rather than the platform's — none yet
exist beyond this pointer.
