# Releasing

This repo ships **one Go module**: the root module (protos + generated SDK). A merged PR is not
consumable by `go get` until it's tagged.

This is a human release action — no automation creates or pushes a tag. Do this from a clone with
push access to `main` and to tags on `origin`, after the release PR has merged and CI is green on
`main`.

## 1. Tag the release

```sh
git fetch origin
git checkout main && git reset --hard origin/main   # or: git checkout <merge-commit-sha>
just proto-lint && just proto-breaking && just build && just test   # last sanity pass before tagging

git tag -a vX.Y.Z -m "vX.Y.Z: <one-line summary>"
git push origin vX.Y.Z
```

Use the merge commit of the release PR (the commit `origin/main` points at right after it
merges) — not any commit from inside the PR's branch.

## 2. Verify it resolves from a clean environment with no credentials

This repo is **public** — the whole point of that (design 001 §10) is that `go get` works with
nothing configured: no `GOPRIVATE`, no `GO_MODULES_TOKEN`, no git auth.

```sh
WORKDIR=$(mktemp -d) && cd "$WORKDIR"
go mod init release-check
GOCACHE="$WORKDIR/cache" GOMODCACHE="$WORKDIR/modcache" GOFLAGS="" GOPRIVATE="" \
GIT_CONFIG_COUNT=0 GIT_TERMINAL_PROMPT=0 \
  go get github.com/sphyrix/contracts@vX.Y.Z
cd - && rm -rf "$WORKDIR"
```

The `go get` call must succeed and add the tagged version (not a pseudo-version) to `go.mod` —
with no auth env vars set and `GIT_TERMINAL_PROMPT=0` (so a credential prompt fails loudly instead
of hanging), proving the module is reachable by an off-platform, credential-less caller.
