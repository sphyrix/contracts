package auth

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

// Two words are used precisely throughout this file and must not be swapped.
//
//   - DECLARED is the org's own input: `[email].token_version` in its tenant
//     platform repo, an optional integer ≥ 1 defaulting to 1, carried through
//     the reconciler into the `EmailOrg` desired state (design 001 §8.1). The
//     org authors it and rotates on its own schedule, with no custodian PR —
//     ADR 020's note of 2026-09-02.
//   - APPLIED is what the verifying service has acted on: the version it has
//     minted a token for and retired the version before. It is `orgs.token_version`
//     in design 001 §9.5, and it is what [AcceptedVersions] is asked about.
//
// The two are equal in the steady state and differ only while [BumpGuard] is
// holding a declared bump back — which is the entire reason the guardrail can
// exist without ever stranding a consumer.

const (
	// FirstTokenVersion is where every org starts. `token_version` is an
	// integer ≥ 1, and an org that has never rotated is at 1.
	//
	// 1 is a BASELINE, not a constant: ADR 027 §8's original "constant 1 in
	// v1" was amended on 2026-09-02 once ADR 020 made the field org-authored,
	// so an org that HAS rotated is at 2 or more from v1 onwards. Code that
	// assumes 1 is the only value it will see is wrong.
	FirstTokenVersion int32 = 1

	// LiveVersions is how many `token_version`s authenticate at once once an
	// org has rotated at all: two, and never more (ADR 020 Decision 3).
	//
	// Two is the whole mechanism. One would mean a bump invalidates the token
	// its consumers are still holding — the window ADR 020 exists to remove.
	// Three would mean a compromised token survives two bumps, which is the
	// revocation this number makes real.
	LiveVersions = 2

	// DefaultMinBumpInterval is how long [BumpGuard] requires between the bump
	// that mints a version and the bump that retires the one before it, when a
	// caller does not set [BumpGuard.MinInterval].
	//
	// It is derived from how fast a consumer can pick a new token up, which is
	// what ADR 020's Consequences bound the safe interval by:
	//
	//   - ON-PLATFORM: VSO's `refreshAfter: 1m` on the rendered
	//     `VaultStaticSecret` (ADR 027 Decision 5), plus kubelet's projection
	//     of the updated Secret into the mounted volume, plus the consumer's
	//     own [DefaultRefreshInterval]. Two to three minutes, worst case.
	//   - OFF-PLATFORM: a human rerunning the ADR 019 devtools command for
	//     every off-platform consumer. Not boundable by any constant here.
	//
	// Fifteen minutes is roughly five times the on-platform bound and short
	// enough that an incident revocation is not obstructed for long. It
	// does NOT cover the off-platform path — nothing can — which is why
	// [BumpGuard] also requires evidence that the version being superseded has
	// actually been used, and why "rerun the delivery command for every
	// off-platform consumer" is a step of the procedure in this repo's README
	// rather than something the interval stands in for.
	DefaultMinBumpInterval = 15 * time.Minute
)

// The reasons [BumpGuard.CheckBump] refuses. Each names one thing, so a caller
// can tell "that is not a bump at all" from "that bump is not safe yet" and
// report the difference; the wrapped error carries the numbers.
var (
	// ErrNotABump means the declared version is not exactly one above the
	// applied version: it is equal to it, below it, or skips past it.
	ErrNotABump = errors.New("auth: the declared token_version is not one above the applied version")

	// ErrBumpTooSoon means too little time has passed since the applied
	// version was applied for the versions this bump would retire to be safe
	// to retire.
	ErrBumpTooSoon = errors.New("auth: the applied token_version is too recent for this bump to retire anything safely")

	// ErrVersionNotInUse means nothing has authenticated with the applied
	// version yet, so there is no evidence that any consumer has cut over to
	// it and the version this bump would retire may still be the only one
	// anybody holds.
	ErrVersionNotInUse = errors.New("auth: no request has authenticated with the applied token_version")

	// ErrInvalidRotationState means the [RotationState] itself is unusable —
	// an applied version below [FirstTokenVersion]. It is the caller's bug,
	// not a rotation that is merely unsafe.
	ErrInvalidRotationState = errors.New("auth: the rotation state is not usable")
)

// AcceptedVersions returns the `token_version`s whose tokens still
// authenticate while applied is the org's applied version — ADR 020's ACCEPTED
// SET — in ascending order.
//
// This is the "rather than a single value" of ADR 020: raising the version
// mints the new token BESIDE the current one, so both authenticate and there
// is never a window in which a consumer holds no valid token. The set is
// {applied-1, applied}, floored at [FirstTokenVersion] — so it is {1} for an
// org that has never rotated and exactly [LiveVersions] long for every org
// that has.
//
// A verifying service RETIRES on a bump by deleting every `tokens` row for the
// org below this set's first element (design 001 §9.5). That is the same rule
// [Interceptor] enforces per request through [VersionAccepted], read from the
// other end — which is why the two cannot drift.
//
// The per-request path calls [VersionAccepted], not this function: verifying
// one version is two comparisons and builds no slice. Use this one to compute
// a retirement floor or to report the live set, not on the hot path.
//
// An applied version below [FirstTokenVersion] is not a version at all and
// yields the empty set: nothing authenticates, which is the safe direction.
func AcceptedVersions(applied int32) []int32 {
	low, high, ok := acceptedRange(applied)
	if !ok {
		return nil
	}
	// Counted in int and filled by index, NOT `for v := low; v <= high; v++`.
	// That loop does not terminate when high is [math.MaxInt32]: the increment
	// wraps to the smallest int32, which is still <= high, and it appends
	// until the process dies. `token_version` is org-authored and the
	// reconciler validates it as "an integer >= 1" with no upper bound, so the
	// largest int32 is a value a tenant can declare in its own repo.
	//
	// The reachable path is RETIREMENT, not authentication: this function is
	// called by [RetiredBy] (and hence [BumpGuard.CheckBump]) and directly by
	// a service computing its retirement floor. The per-request path uses
	// [VersionAccepted] and never reaches here.
	//
	// high-low is at most LiveVersions-1 by construction, so the count cannot
	// overflow; the guard below makes the function total anyway, because a
	// negative count would panic inside `make` on the auth path.
	count := int(high) - int(low) + 1
	if count <= 0 {
		return nil
	}
	versions := make([]int32, count)
	for i := range versions {
		versions[i] = low + int32(i)
	}
	return versions
}

// VersionAccepted reports whether a token minted at tokenVersion still
// authenticates while applied is the org's applied `token_version`.
//
// It is [AcceptedVersions] as a predicate and is computed from the same
// bounds, so the set and the check can never disagree about a version. A
// version above applied is refused as firmly as one below the set: a token
// from a version this service has not applied is one it never minted.
func VersionAccepted(tokenVersion, applied int32) bool {
	low, high, ok := acceptedRange(applied)
	return ok && tokenVersion >= low && tokenVersion <= high
}

// RetiredBy returns the `token_version`s that stop authenticating when an org's
// applied version moves from applied to declared — the members of
// [AcceptedVersions] at applied that [AcceptedVersions] at declared no longer
// holds, in ascending order.
//
// This is ADR 020's revocation half, and it is why one bump is not a
// revocation: moving from 1 to 2 retires nothing (the set grows from {1} to
// {1, 2}), and only the FOLLOWING bump, 2 to 3, retires 1. A caller that wants
// a token gone bumps twice and applies both.
//
// The result is meaningful only for declared >= applied. Going backwards is
// not a retirement and this reports one — RetiredBy(3, 1) is {2, 3} — which is
// harmless because [BumpGuard.CheckBump] refuses a lowering before it asks.
func RetiredBy(applied, declared int32) []int32 {
	var retired []int32
	for _, version := range AcceptedVersions(applied) {
		if !VersionAccepted(version, declared) {
			retired = append(retired, version)
		}
	}
	return retired
}

// acceptedRange is the one place the accepted set's bounds are computed.
func acceptedRange(applied int32) (low, high int32, ok bool) {
	if applied < FirstTokenVersion {
		return 0, 0, false
	}
	low = applied - (LiveVersions - 1)
	if low < FirstTokenVersion {
		low = FirstTokenVersion
	}
	return low, applied, true
}

// RotationState is one org's rotation state as [BumpGuard] needs to see it.
//
// Applied and AppliedAt come straight out of design 001 §9.5:
// `orgs.token_version` and the `created_at` of the `tokens` row minted for it.
// AppliedLastUsedAt does NOT — §9.5 has no last-used column on either table,
// and Story 11.2 (#433) does not add one. A service that does not track it
// leaves it zero and sets [BumpGuard.Evidence] to [EvidenceOptional], which is
// ADR 020's "a minimum interval, OR a check that the new version is in use".
// Recording it is a deliberate choice with a cost — a write on the
// authentication path — not an assumed column.
type RotationState struct {
	// Applied is the org's currently applied `token_version` —
	// `orgs.token_version`. Not the declared one: while the guard is holding a
	// bump back, the declared value has moved on and this has not.
	Applied int32

	// AppliedAt is when Applied was applied — the `created_at` of the `tokens`
	// row minted for it. The zero time means the service does not know, which
	// the guard treats as "too soon" rather than as "long ago": an unknown
	// interval is not an elapsed one.
	AppliedAt time.Time

	// AppliedLastUsedAt is when a request last authenticated with a token at
	// Applied — the evidence that at least one consumer has actually cut over.
	// The zero time, or any time before AppliedAt, means no such request has
	// been seen and there is no evidence at all.
	//
	// It has no column in design 001 §9.5 (see the type's own doc). Leave it
	// zero and use [EvidenceOptional] if the service does not record it.
	//
	// One consumer's cut-over is not proof that EVERY consumer has cut over,
	// which is why it does not replace the interval under [EvidenceRequired].
	AppliedLastUsedAt time.Time
}

// EvidencePolicy says whether [BumpGuard] additionally requires evidence that
// the applied version is in use before it will allow a bump that retires
// anything.
//
// ADR 020's Consequences call for "a minimum interval, OR a check that the new
// version is in use". The interval is always enforced; this chooses whether
// the second check is enforced alongside it.
//
// [EvidenceOptional] is the ONLY value that waives anything. The zero value is
// strict, and so is every other value: a policy this package does not
// recognise must never come out lax.
type EvidencePolicy int

const (
	// EvidenceRequired is the default: a bump that retires something needs
	// both the elapsed interval AND a request seen at the applied version.
	// Correct whenever the service records [RotationState.AppliedLastUsedAt].
	EvidenceRequired EvidencePolicy = iota

	// EvidenceOptional drops the evidence half and relies on the interval
	// alone.
	//
	// This exists because evidence can be UNOBTAINABLE, and a guardrail that
	// cannot be satisfied is not a guardrail — it is an outage of the only
	// revocation path there is. The 2026-09-02 ruling gives sphyrix no
	// custodian-side override, so an org's two commits are the whole
	// mechanism, and requiring a request at the new version would block it
	// forever when the consumer is offboarded (the very case a revocation is
	// usually for), has not gone live yet, or sends monthly.
	//
	// WHO SETS IT, in v1: the verifying SERVICE, once, from whether it records
	// [RotationState.AppliedLastUsedAt] at all. It is not a per-incident knob —
	// an operator working through the revocation procedure cannot set a Go
	// struct field, and there is no control surface that would let them. A
	// per-org or per-incident waiver is a successor decision, and it needs
	// somewhere to be expressed before it can exist.
	//
	// So a service that does not track last use MUST set this, or the only
	// revocation path it has is unreachable in production — which is the same
	// hole as never having offered the waiver.
	//
	// The out-of-band evidence an operator actually holds is ADR 019's delivery
	// run record: the inventory of which off-platform consumer holds which
	// version, living outside any database this guard can read.
	//
	// It does NOT relax the interval. There is still no way to spell "no
	// interval".
	EvidenceOptional
)

// BumpGuard is ADR 020's guardrail: the check that belongs in the tooling
// rather than in an operator's head.
//
// ADR 020's Consequences: the safe interval between two bumps is bounded below
// by how fast consumers pick the new token up, so bumping twice faster than
// that revokes a version somebody is still using. This is where that is
// enforced. A caller runs [BumpGuard.CheckBump] before APPLYING a declared
// bump — before minting the new version and before retiring the old one — and
// on a refusal applies neither, leaving the accepted set exactly as it was and
// reporting the reason. Holding the whole bump rather than half of it is what
// keeps at most [LiveVersions] live at every point: applying the mint while
// deferring the retirement would put three versions in flight.
//
// The zero value is usable and enforces [DefaultMinBumpInterval] against
// [time.Now].
type BumpGuard struct {
	// MinInterval is how long must pass between applying a version and
	// applying the bump that retires the one before it. Zero or negative means
	// [DefaultMinBumpInterval]: there is deliberately no way to spell "no
	// interval", because that is the failure this type exists to prevent.
	MinInterval time.Duration

	// Evidence chooses whether a request must have been seen at the applied
	// version before a retiring bump is allowed. The zero value,
	// [EvidenceRequired], is the strict one; see [EvidenceOptional] for when
	// dropping it is correct rather than lax.
	Evidence EvidencePolicy

	// Now is the clock, for tests. Nil means [time.Now].
	Now func() time.Time
}

// CheckBump reports whether the org's newly declared `token_version` may be
// applied on top of state. It returns nil when it may, and otherwise an error
// naming the reason and wrapping one of [ErrNotABump], [ErrBumpTooSoon],
// [ErrVersionNotInUse] or [ErrInvalidRotationState].
//
// Three refusals, in order:
//
//   - Not a bump. declared must be exactly one above state.Applied. Equal is
//     nothing to do; below would retire the live token instead of rotating it;
//     and a SKIP — declaring 4 while 2 is applied — is two bumps with no
//     interval between them, which is precisely the thing being guarded
//     against, so it is refused rather than collapsed into one.
//   - Too soon. Less than [BumpGuard.MinInterval] has passed since
//     state.AppliedAt. Always enforced; there is no way to waive it.
//   - Not in use. Nothing has authenticated at state.Applied, so there is no
//     evidence any consumer has picked it up. Enforced only under
//     [EvidenceRequired] — see [EvidencePolicy], and read [EvidenceOptional]
//     before assuming the strict setting is always the safe one.
//
// The last two apply only to a bump that actually RETIRES something. A bump
// from [FirstTokenVersion] mints beside and retires nothing — the accepted set
// grows from {1} to {1, 2} — so there is no consumer to strand and it is
// always legal, however recent the org's first token is. The guard fires
// exactly when [RetiredBy] is non-empty, so the two can never disagree about
// which bumps are dangerous.
//
// CheckBump is NOT consulted for an org's FIRST mint. There is no applied
// version then, nothing can be retired, and an org that declares 3 on its very
// first day gets 3 — ADR 027's amendment has the reconciler materialise 1 only
// for orgs that have never rotated. Calling it with a zero Applied is a
// caller's bug and answers [ErrInvalidRotationState], not a rotation refusal.
//
// A refusal is not an error the ORG ever sees: the bump is already merged in
// the org's own repo (it is org-authored and self-service), so the service
// declines to APPLY it and must surface that where an operator is looking —
// `orgs.last_error` and `email_org_ready{org}` (design 001 §9.4, §9.5).
// Silence here is dangerous in exactly the case that matters: an incident
// responder merges the second commit, sees the repo say N+2, and believes the
// compromised token is dead while the service is still at N+1 with N live.
//
// When the bump IS applied, advance `orgs.token_version` in the SAME
// transaction as the insert of the new `tokens` row. Splitting them leaves a
// window where a consumer that has already picked the new token up — VSO plus
// [TokenFromFile] can be faster than the next resync — presents a version the
// accepted set does not yet hold and gets `UNAUTHENTICATED`, which is the
// window ADR 020 Decision 1 says never exists.
//
// Both version arguments are int32. `token_version` is validated upstream only
// as "an integer >= 1" and Python integers are unbounded, so a declared value
// that does not fit int32 is a SCHEMA error and must be rejected before it
// reaches here — never truncated into range.
//
// No error returned here carries a token or a hash; they carry versions and
// durations, which are not secrets.
func (g BumpGuard) CheckBump(state RotationState, declared int32) error {
	if state.Applied < FirstTokenVersion {
		return fmt.Errorf("auth: the applied token_version is %d, below the first version %d: %w",
			state.Applied, FirstTokenVersion, ErrInvalidRotationState)
	}

	// The largest int32 has nowhere to bump to, and this is checked EXPLICITLY
	// rather than left to the branch order below. `state.Applied+1` wraps to
	// the smallest int32 there, and a reader who reorders the switch — or a
	// caller who reaches the comparison another way — would silently get a
	// negative "next version" that compares equal to a declared MinInt32.
	// Overflow safety that depends on which branch runs first is not safety.
	if state.Applied == math.MaxInt32 {
		return fmt.Errorf("auth: the applied token_version is already the largest int32 (%d), so there is no version above it to bump to: %w",
			int32(math.MaxInt32), ErrNotABump)
	}

	switch {
	case declared == state.Applied:
		return fmt.Errorf("auth: token_version %d is already applied, so there is nothing to bump: %w",
			declared, ErrNotABump)
	case declared < state.Applied:
		return fmt.Errorf("auth: the declared token_version %d is below the applied version %d — lowering it would retire live tokens rather than rotate them: %w",
			declared, state.Applied, ErrNotABump)
	case declared != state.Applied+1:
		return fmt.Errorf("auth: the declared token_version %d skips past the applied version %d; each skipped version is a bump with no interval before it, and applying them together would retire %s while consumers may still be holding them — bump one version at a time: %w",
			declared, state.Applied, formatVersions(RetiredBy(state.Applied, declared)), ErrNotABump)
	}

	retired := RetiredBy(state.Applied, declared)
	if len(retired) == 0 {
		// Mint-beside only. Nothing stops authenticating, so nothing can be
		// stranded by applying this immediately.
		return nil
	}

	minInterval := g.minInterval()
	if state.AppliedAt.IsZero() {
		return fmt.Errorf("auth: token_version %d has no recorded application time, so the %s that must precede retiring %s cannot be shown to have passed: %w",
			state.Applied, minInterval, formatVersions(retired), ErrBumpTooSoon)
	}
	if elapsed := g.now().Sub(state.AppliedAt); elapsed < minInterval {
		return fmt.Errorf("auth: token_version %d was applied %s ago and at least %s must pass before bumping to %d retires %s — a consumer that has not picked %d up yet would be left with no valid token: %w",
			state.Applied, elapsed.Round(time.Second), minInterval, declared, formatVersions(retired), state.Applied, ErrBumpTooSoon)
	}

	// Compared against the OPT-OUT, not against the strict value: EvidencePolicy
	// is an exported named int with exported-field access, so an unmarshalled
	// config value, a cast, or a third constant added out of order can all
	// produce something that is neither constant. `== EvidenceRequired` would
	// have waived the check for every one of them — half of the only
	// revocation guardrail, silently disabled, in the lax direction.
	if g.Evidence != EvidenceOptional &&
		(state.AppliedLastUsedAt.IsZero() || state.AppliedLastUsedAt.Before(state.AppliedAt)) {
		return fmt.Errorf("auth: no request has authenticated with token_version %d since it was applied, so nothing shows a consumer has cut over to it and bumping to %d would retire %s: %w",
			state.Applied, declared, formatVersions(retired), ErrVersionNotInUse)
	}

	return nil
}

func (g BumpGuard) now() time.Time {
	if g.Now != nil {
		return g.Now()
	}
	return time.Now()
}

func (g BumpGuard) minInterval() time.Duration {
	if g.MinInterval <= 0 {
		return DefaultMinBumpInterval
	}
	return g.MinInterval
}

// formatVersions renders a version list for an error message: "1", "1 and 2",
// "1, 2 and 3". Empty renders as "nothing", so a message never reads "would
// retire  while ...".
func formatVersions(versions []int32) string {
	switch len(versions) {
	case 0:
		return "nothing"
	case 1:
		return "token_version " + strconv.Itoa(int(versions[0]))
	}
	rendered := make([]string, len(versions))
	for i, version := range versions {
		rendered[i] = strconv.Itoa(int(version))
	}
	return "token_versions " + strings.Join(rendered[:len(rendered)-1], ", ") + " and " + rendered[len(rendered)-1]
}

// TokenPathVersion supplies the check-and-set version that a mint must present
// when it writes an org's token to Vault.
//
// It exists because #488 arms the KV v2 mount with `cas_required=true`, and
// ADR 020's mint-beside is an OVERWRITE of
// `kv/data/<org>/platform/<service>/token`. A KV v2 write on an armed mount
// must carry `cas` equal to the secret's current version.
//
// # ADR 027 Decision 4 amendment (human ruling, 2026-09-02)
//
// Decision 4 originally granted the verifying service `create`/`update` on
// `kv/data/+/platform/<service>/*` with "no `read`, `delete` or `kv/metadata`
// grant" — which left the writer unable to learn the number it is required to
// send. AMENDED: the service also gets `read` on
// `kv/metadata/+/platform/<service>/*` — and ONLY there. That path yields the
// VERSION, never the value, so token values remain unreadable across orgs and
// the narrow cross-tenant write path is unchanged in every other respect.
// (#488 records the same ruling as ADR 024 Amendment 4.)
//
// The shipped implementation is therefore a METADATA READ. The interface stays
// pluggable because the seam is worth keeping — a service that tracks the
// version itself, or a future one-path-per-version layout, satisfies the same
// contract — but the ruled and supported source is the metadata read, and a
// service that invents another one is off the platform convention.
//
// This package has no Vault client and must never acquire one — the interface
// is deliberately expressed in ctx, an org and an int.
type TokenPathVersion interface {
	// CurrentVersion returns the KV v2 version currently stored at org's token
	// path, to be sent as `cas` on the next write. Zero means the secret does
	// not exist yet, which is what a first mint sends.
	//
	// An error must fail the mint. Do NOT fall back to a guess: a wrong `cas`
	// is refused by Vault, which is the safe direction — nothing is written,
	// no hash row is stored, and the next resync retries, exactly as ADR 027
	// Decision 3's Vault-first ordering already provides for. Sending no `cas`
	// at all is refused outright by an armed mount.
	CurrentVersion(ctx context.Context, org string) (int, error)
}

// DefaultCASAttempts is how many times [CASWriter] will read the version and
// try the write before giving up. Three: the conflict this retries is a tenant
// overwriting its own token path (ADR 027 Decision 5 gives the tenant
// `tenant-rw` there), which is rare and not adversarial. A loop that retried
// indefinitely would hide a path being rewritten continuously instead of
// reporting it.
const DefaultCASAttempts = 3

// ErrCASRefused is what a write function returns to say Vault rejected the
// check-and-set version — the secret moved between the metadata read and the
// write. It is the ONLY error [CASWriter] retries; anything else fails the
// mint immediately, because retrying an error whose cause is unknown is how a
// bounded loop becomes an unbounded one.
var ErrCASRefused = errors.New("auth: vault refused the check-and-set version")

// ErrCASExhausted means the token path kept moving underneath the mint until
// the attempt budget ran out. Nothing was written.
//
// Report it LOUDLY — `orgs.last_error` and `email_org_ready{org}`, the same
// channel as a held bump. It means something else is writing an org's token
// path repeatedly, which under ADR 027 Decision 5 is the tenant itself through
// `tenant-rw`, and a mint that silently gave up would leave the org with no
// new token and nobody looking.
var ErrCASExhausted = errors.New("auth: the token path kept moving under the mint")

// CASWriter is the ruled bump procedure: read the current version, write with
// that `cas`, and on a refusal re-read and try again, bounded.
//
// The re-read is the point. Retrying with the SAME cas cannot succeed — the
// version is exactly what was wrong — so a retry that does not read again is
// an infinite loop with extra steps.
type CASWriter struct {
	// Version is where the `cas` comes from: the metadata read, per the
	// 2026-09-02 ruling. Required.
	Version TokenPathVersion

	// Attempts bounds the read-write cycles. Zero or negative means
	// [DefaultCASAttempts]; there is no way to spell "unbounded".
	Attempts int
}

// Write performs one mint-beside write under check-and-set.
//
// write is handed the `cas` to present and must return [ErrCASRefused], wrapped
// or bare, when Vault rejects it. It must not log the token it is writing — the
// obligations in this package's documentation apply inside that closure like
// everywhere else.
//
// Errors: the version source's error (the mint fails; nothing is written), the
// write's own non-cas error unchanged, or [ErrCASExhausted]. On success the
// caller stores the hash SECOND, per ADR 027 Decision 3.
func (w CASWriter) Write(ctx context.Context, org string, write func(ctx context.Context, cas int) error) error {
	if w.Version == nil {
		return errors.New("auth: a TokenPathVersion is required")
	}
	if write == nil {
		return errors.New("auth: a write function is required")
	}

	attempts := w.Attempts
	if attempts <= 0 {
		attempts = DefaultCASAttempts
	}

	var refused error
	for attempt := 1; attempt <= attempts; attempt++ {
		// Checked every time round, so a cancelled context stops the loop
		// rather than spending the whole budget on a dead request.
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("auth: writing the token for %q: %w", org, err)
		}

		// A FRESH read each attempt: the previous cas is known-stale.
		cas, err := w.Version.CurrentVersion(ctx, org)
		if err != nil {
			return fmt.Errorf("auth: reading the token path version for %q: %w", org, err)
		}

		switch err := write(ctx, cas); {
		case err == nil:
			return nil
		case errors.Is(err, ErrCASRefused):
			refused = err
		default:
			return err
		}
	}

	return fmt.Errorf("auth: %d attempts to write the token for %q were all refused (last: %v): %w",
		attempts, org, refused, ErrCASExhausted)
}
