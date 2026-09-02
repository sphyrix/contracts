package auth

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/sphyrix/contracts/gen/go/hello/v1/hellov1connect"
)

// ACCEPTANCE: "The accepted-set verifier admits N and N-1 and rejects N-2; a
// test fails if the set collapses to a single value."
//
// The len check is the second half of that sentence and is not decoration: an
// implementation that returned {applied} would satisfy "admits N" and "rejects
// N-2" and would still have deleted ADR 020's zero-downtime property, so the
// test asserts the size of the set as well as its contents.
func TestTheAcceptedSetHoldsTwoVersionsAndRejectsTheOneBeforeThem(t *testing.T) {
	for applied := int32(2); applied <= 10; applied++ {
		want := []int32{applied - 1, applied}
		if got := AcceptedVersions(applied); !reflect.DeepEqual(got, want) {
			t.Errorf("AcceptedVersions(%d) = %v, want %v", applied, got, want)
		}
		if got := len(AcceptedVersions(applied)); got != LiveVersions {
			t.Errorf("AcceptedVersions(%d) holds %d version(s), want exactly %d — the set has collapsed and a rotation would strand every consumer that has not cut over",
				applied, got, LiveVersions)
		}
		if !VersionAccepted(applied, applied) {
			t.Errorf("token_version %d is not accepted at applied version %d — the current version must authenticate", applied, applied)
		}
		if !VersionAccepted(applied-1, applied) {
			t.Errorf("token_version %d is not accepted at applied version %d — the previous version must still authenticate (ADR 020: mint beside)", applied-1, applied)
		}
		if VersionAccepted(applied-2, applied) {
			t.Errorf("token_version %d is still accepted at applied version %d — the following bump must revoke it", applied-2, applied)
		}
		if VersionAccepted(applied+1, applied) {
			t.Errorf("token_version %d is accepted at applied version %d — a version this service has not applied is one it never minted", applied+1, applied)
		}
	}
}

// An org that has never rotated has exactly one version, and it is version 1.
// The floor is not a special case bolted on: it is what makes the FIRST bump a
// pure mint-beside, which is what [BumpGuard] lets through unconditionally.
func TestTheAcceptedSetIsFlooredAtTheFirstVersion(t *testing.T) {
	want := []int32{FirstTokenVersion}
	if got := AcceptedVersions(FirstTokenVersion); !reflect.DeepEqual(got, want) {
		t.Errorf("AcceptedVersions(%d) = %v, want %v", FirstTokenVersion, got, want)
	}
	if VersionAccepted(FirstTokenVersion-1, FirstTokenVersion) {
		t.Errorf("token_version %d is accepted — there is no version below %d", FirstTokenVersion-1, FirstTokenVersion)
	}
}

// A version below the first one is not a version. The set is empty and nothing
// authenticates against it: an unusable applied version must fail closed, never
// open.
func TestAnAppliedVersionBelowTheFirstAcceptsNothing(t *testing.T) {
	for _, applied := range []int32{0, -1, math.MinInt32} {
		if got := AcceptedVersions(applied); len(got) != 0 {
			t.Errorf("AcceptedVersions(%d) = %v, want the empty set", applied, got)
		}
		for _, tokenVersion := range []int32{-1, 0, 1, 2} {
			if VersionAccepted(tokenVersion, applied) {
				t.Errorf("token_version %d is accepted at applied version %d — an unusable applied version must accept nothing", tokenVersion, applied)
			}
		}
	}
}

// RetiredBy is the revocation half, and the property that matters is the one
// operators get wrong: the first bump retires NOTHING.
func TestOneBumpRetiresNothingAndTheFollowingBumpRetires(t *testing.T) {
	if got := RetiredBy(1, 2); len(got) != 0 {
		t.Errorf("bumping 1 -> 2 retired %v, want nothing — one bump mints beside and does not revoke", got)
	}
	for applied := int32(2); applied <= 10; applied++ {
		want := []int32{applied - 1}
		if got := RetiredBy(applied, applied+1); !reflect.DeepEqual(got, want) {
			t.Errorf("bumping %d -> %d retired %v, want %v", applied, applied+1, got, want)
		}
	}
	// Applying two bumps at once would retire two versions at a stroke — which
	// is why CheckBump refuses a skip rather than collapsing it.
	if got, want := RetiredBy(3, 5), []int32{2, 3}; !reflect.DeepEqual(got, want) {
		t.Errorf("bumping 3 -> 5 retired %v, want %v", got, want)
	}
}

// ACCEPTANCE: "A bump-to-N-then-N+1 sequence leaves exactly two live versions
// at every point — asserted across the whole sequence, not only at the end."
//
// The assertion runs through the REAL interceptor over a real Connect server:
// what is counted is how many tokens a caller can actually authenticate with,
// not what a helper says the set is. The expectation is written out
// independently of [AcceptedVersions] — {applied-1, applied}, spelled here —
// so the test cannot agree with a broken implementation by construction.
func TestARotationSequenceLeavesExactlyTwoLiveVersionsAtEveryPoint(t *testing.T) {
	const highest = 6

	h := newHarness(t, &helloHandler{})

	// One token per version, all present in the store at once: a store keeps
	// the row for every version it has ever minted until retirement deletes
	// it, and this test is about which of them still AUTHENTICATE.
	tokens := make(map[int32]string, highest)
	for version := int32(1); version <= highest; version++ {
		token, err := Mint("email")
		if err != nil {
			t.Fatalf("Mint: %v", err)
		}
		tokens[version] = token
	}

	for applied := int32(1); applied <= highest; applied++ {
		for version, token := range tokens {
			h.store.holdAt(token, "becoming-the-hunter", version, applied)
		}

		// Written out rather than derived: at applied version N the live set
		// is N and N-1, and at version 1 it is 1 alone.
		live := map[int32]bool{applied: true}
		if applied > FirstTokenVersion {
			live[applied-1] = true
		}

		authenticated := 0
		for version := int32(1); version <= highest; version++ {
			org, err := h.call(t, bearer(tokens[version]))
			switch {
			case live[version] && err != nil:
				t.Fatalf("applied=%d: token_version %d was refused (%v) — it must still authenticate", applied, version, connect.CodeOf(err))
			case live[version]:
				authenticated++
				if org != "becoming-the-hunter" {
					t.Errorf("applied=%d: token_version %d authenticated as %q", applied, version, org)
				}
			case err == nil:
				t.Fatalf("applied=%d: token_version %d authenticated — it is not in the live set and must be refused", applied, version)
			case connect.CodeOf(err) != connect.CodeUnauthenticated:
				t.Errorf("applied=%d: token_version %d gave %v, want %v", applied, version, connect.CodeOf(err), connect.CodeUnauthenticated)
			}
		}

		want := LiveVersions
		if applied == FirstTokenVersion {
			want = 1
		}
		if authenticated != want {
			t.Errorf("applied=%d: %d version(s) authenticated, want exactly %d", applied, authenticated, want)
		}
	}
}

// The other half of the sequence: applying each bump through [BumpGuard] and
// [RetiredBy] the way a verifying service will, and checking the invariant
// after every single step rather than at the end. This is the model that
// Story 11.3 (#434) implements against.
func TestApplyingASequenceOfBumpsKeepsAtMostTwoVersionsLive(t *testing.T) {
	guard := BumpGuard{MinInterval: time.Minute, Now: func() time.Time { return time.Unix(0, 0) }}

	applied := FirstTokenVersion
	minted := map[int32]bool{FirstTokenVersion: true}

	for declared := FirstTokenVersion + 1; declared <= 8; declared++ {
		state := RotationState{
			Applied: applied,
			// Long enough ago, and used since: the guardrail's own refusals
			// have their own tests; this one is about the applied sequence.
			AppliedAt:         time.Unix(0, 0).Add(-time.Hour),
			AppliedLastUsedAt: time.Unix(0, 0).Add(-time.Minute),
		}
		if err := guard.CheckBump(state, declared); err != nil {
			t.Fatalf("bumping %d -> %d was refused: %v", applied, declared, err)
		}

		// Apply: mint the new version, then retire what the bump retires.
		minted[declared] = true
		for _, version := range RetiredBy(applied, declared) {
			if !minted[version] {
				t.Fatalf("bumping %d -> %d retired version %d, which was never minted", applied, declared, version)
			}
			delete(minted, version)
		}
		applied = declared

		if len(minted) > LiveVersions {
			t.Fatalf("after applying %d, %d versions are live (%v) — at most %d may ever be", applied, len(minted), sortedVersions(minted), LiveVersions)
		}
		if len(minted) != LiveVersions {
			t.Fatalf("after applying %d, %d version(s) are live (%v) — the set has collapsed", applied, len(minted), sortedVersions(minted))
		}
		if !minted[applied] || !minted[applied-1] {
			t.Fatalf("after applying %d the live set is %v, want {%d, %d}", applied, sortedVersions(minted), applied-1, applied)
		}
		if minted[applied-2] {
			t.Fatalf("after applying %d version %d is still live — the following bump must revoke it", applied, applied-2)
		}
	}
}

func sortedVersions(set map[int32]bool) []int32 {
	var versions []int32
	for version, live := range set {
		if live {
			versions = append(versions, version)
		}
	}
	for i := 1; i < len(versions); i++ {
		for j := i; j > 0 && versions[j] < versions[j-1]; j-- {
			versions[j], versions[j-1] = versions[j-1], versions[j]
		}
	}
	return versions
}

// ACCEPTANCE (refusal half): "The guardrail refuses a second bump inside the
// minimum interval (or without evidence the new version is in use) and names
// the reason."
func TestTheGuardRefusesASecondBumpInsideTheMinimumInterval(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	guard := BumpGuard{MinInterval: 15 * time.Minute, Now: func() time.Time { return now }}

	// Version 2 was applied a minute ago and is in use. Bumping to 3 would
	// retire version 1, which consumers may still be holding.
	state := RotationState{
		Applied:           2,
		AppliedAt:         now.Add(-1 * time.Minute),
		AppliedLastUsedAt: now.Add(-30 * time.Second),
	}

	err := guard.CheckBump(state, 3)
	if err == nil {
		t.Fatal("a second bump one minute after the first was allowed — it would retire a version consumers may still hold")
	}
	if !errors.Is(err, ErrBumpTooSoon) {
		t.Errorf("the refusal is %v, want it to wrap ErrBumpTooSoon", err)
	}
	// "names the reason": the message has to carry the numbers an operator
	// needs, not just a sentinel.
	for _, want := range []string{"1m0s", "15m0s", "token_version 1"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal %q does not mention %q", err, want)
		}
	}
}

// An unknown application time is treated as "too soon", never as "long ago".
func TestTheGuardRefusesABumpWhenTheApplicationTimeIsUnknown(t *testing.T) {
	guard := BumpGuard{MinInterval: time.Minute, Now: func() time.Time { return time.Unix(1_000_000, 0) }}
	err := guard.CheckBump(RotationState{Applied: 2, AppliedLastUsedAt: time.Unix(999_999, 0)}, 3)
	if !errors.Is(err, ErrBumpTooSoon) {
		t.Fatalf("a bump with no recorded application time gave %v, want ErrBumpTooSoon", err)
	}
}

// ACCEPTANCE (the "or without evidence the new version is in use" half).
func TestTheGuardRefusesABumpWithNoEvidenceTheAppliedVersionIsInUse(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	guard := BumpGuard{MinInterval: 15 * time.Minute, Now: func() time.Time { return now }}
	appliedAt := now.Add(-24 * time.Hour)

	for name, state := range map[string]RotationState{
		"never used": {
			Applied:   2,
			AppliedAt: appliedAt,
		},
		"last used before the version was applied": {
			Applied:           2,
			AppliedAt:         appliedAt,
			AppliedLastUsedAt: appliedAt.Add(-time.Second),
		},
	} {
		err := guard.CheckBump(state, 3)
		if err == nil {
			t.Fatalf("%s: the bump was allowed with no evidence anybody has picked the new version up", name)
		}
		if !errors.Is(err, ErrVersionNotInUse) {
			t.Errorf("%s: the refusal is %v, want it to wrap ErrVersionNotInUse", name, err)
		}
		if !strings.Contains(err.Error(), "token_version 1") {
			t.Errorf("%s: the refusal %q does not name the version it would retire", name, err)
		}
	}
}

// ACCEPTANCE (legal half): "a test drives the legal path."
func TestTheGuardAllowsABumpOnceTheIntervalHasPassedAndTheVersionIsInUse(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	guard := BumpGuard{MinInterval: 15 * time.Minute, Now: func() time.Time { return now }}

	state := RotationState{
		Applied:           2,
		AppliedAt:         now.Add(-16 * time.Minute),
		AppliedLastUsedAt: now.Add(-5 * time.Minute),
	}
	if err := guard.CheckBump(state, 3); err != nil {
		t.Fatalf("a bump 16 minutes after the last one, with the new version in use, was refused: %v", err)
	}

	// Exactly at the boundary is allowed; a second under it is not. An
	// inverted comparison fails here.
	state.AppliedAt = now.Add(-15 * time.Minute)
	if err := guard.CheckBump(state, 3); err != nil {
		t.Errorf("a bump exactly at the minimum interval was refused: %v", err)
	}
	state.AppliedAt = now.Add(-15*time.Minute + time.Second)
	if err := guard.CheckBump(state, 3); !errors.Is(err, ErrBumpTooSoon) {
		t.Errorf("a bump one second inside the minimum interval gave %v, want ErrBumpTooSoon", err)
	}
}

// The first bump mints beside and retires nothing, so it is legal immediately
// — however recent the org's first token is and whether or not anything has
// used it. This is what makes "one bump mints, it does not revoke" true.
func TestTheGuardAllowsTheFirstBumpImmediately(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	guard := BumpGuard{MinInterval: 24 * time.Hour, Now: func() time.Time { return now }}

	state := RotationState{Applied: FirstTokenVersion, AppliedAt: now}
	if err := guard.CheckBump(state, FirstTokenVersion+1); err != nil {
		t.Fatalf("the first bump was refused: %v — it retires nothing, so there is nobody to strand", err)
	}
	if got := RetiredBy(FirstTokenVersion, FirstTokenVersion+1); len(got) != 0 {
		t.Fatalf("the first bump retires %v — the test above passed for the wrong reason", got)
	}
}

// A bump is one version. Everything else is refused, and a SKIP is refused
// precisely because it is two bumps with no interval between them.
func TestTheGuardRefusesAnythingThatIsNotASingleBump(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	guard := BumpGuard{Now: func() time.Time { return now }}
	safe := RotationState{
		Applied:           3,
		AppliedAt:         now.Add(-24 * time.Hour),
		AppliedLastUsedAt: now.Add(-time.Hour),
	}

	for name, declared := range map[string]int32{
		"the same version": 3,
		"a lower version":  2,
		"a much lower one": 1,
		"skipping one":     5,
		"skipping many":    99,
	} {
		err := guard.CheckBump(safe, declared)
		if err == nil {
			t.Errorf("%s (declared %d against applied %d) was allowed", name, declared, safe.Applied)
			continue
		}
		if !errors.Is(err, ErrNotABump) {
			t.Errorf("%s: the refusal is %v, want it to wrap ErrNotABump", name, err)
		}
	}

	// The control: the one legal value is allowed, so the loop above is not
	// passing because everything is refused.
	if err := guard.CheckBump(safe, 4); err != nil {
		t.Fatalf("the single legal bump (3 -> 4) was refused: %v", err)
	}

	// Each refusal names ITS OWN reason, not just the shared sentinel. All
	// three wrap ErrNotABump, so without these the branches that distinguish
	// them could be deleted and every test above would still pass.
	if err := guard.CheckBump(safe, 5); !strings.Contains(err.Error(), "token_versions 2 and 3") {
		t.Errorf("the skip refusal %q does not name the two versions it would retire at once", err)
	}
	if err := guard.CheckBump(safe, 2); !strings.Contains(err.Error(), "lowering") {
		t.Errorf("the refusal of a LOWER version is %q — it must say that lowering would retire live tokens rather than rotate them", err)
	}
	if err := guard.CheckBump(safe, 3); !strings.Contains(err.Error(), "already applied") {
		t.Errorf("the refusal of the SAME version is %q — it must say there is nothing to bump", err)
	}
}

// An applied version below the first one is the caller's bug, and it is named
// as one rather than being folded into "not a bump".
func TestTheGuardRefusesAnUnusableRotationState(t *testing.T) {
	guard := BumpGuard{}
	for _, applied := range []int32{0, -1, math.MinInt32} {
		err := guard.CheckBump(RotationState{Applied: applied}, applied+1)
		if !errors.Is(err, ErrInvalidRotationState) {
			t.Errorf("an applied version of %d gave %v, want ErrInvalidRotationState", applied, err)
		}
	}
}

// The largest int32 has nowhere to bump to, and asking must refuse rather than
// wrap around into a negative version.
func TestTheGuardDoesNotWrapAroundAtTheLargestVersion(t *testing.T) {
	guard := BumpGuard{}
	state := RotationState{Applied: math.MaxInt32, AppliedAt: time.Unix(0, 0), AppliedLastUsedAt: time.Unix(1, 0)}
	for _, declared := range []int32{math.MaxInt32, math.MinInt32, 1} {
		err := guard.CheckBump(state, declared)
		if !errors.Is(err, ErrNotABump) {
			t.Errorf("declaring %d against applied %d gave %v, want ErrNotABump", declared, state.Applied, err)
			continue
		}
		// The reason must be the overflow, not "already applied" or "below the
		// applied version": those are true by accident of the branch order,
		// and an operator reading them would go looking for the wrong problem.
		// Asserting the message is what keeps the explicit MaxInt32 check from
		// being deleted as redundant — it is redundant only until somebody
		// reorders the switch.
		if !strings.Contains(err.Error(), "largest int32") {
			t.Errorf("declaring %d against applied MaxInt32 gave %q — it must name the overflow as the reason", declared, err)
		}
	}
}

// The zero value has to be usable, because a caller that has to configure the
// guardrail before it protects anything is a caller that will not configure it.
func TestTheZeroGuardEnforcesTheDefaultIntervalAgainstTheRealClock(t *testing.T) {
	var guard BumpGuard

	tooSoon := RotationState{
		Applied:           2,
		AppliedAt:         time.Now().Add(-(DefaultMinBumpInterval - time.Minute)),
		AppliedLastUsedAt: time.Now().Add(-time.Minute),
	}
	if err := guard.CheckBump(tooSoon, 3); !errors.Is(err, ErrBumpTooSoon) {
		t.Errorf("the zero guard gave %v a minute inside the default interval, want ErrBumpTooSoon", err)
	}

	safe := RotationState{
		Applied:           2,
		AppliedAt:         time.Now().Add(-(DefaultMinBumpInterval + time.Minute)),
		AppliedLastUsedAt: time.Now().Add(-time.Minute),
	}
	if err := guard.CheckBump(safe, 3); err != nil {
		t.Errorf("the zero guard refused a bump a minute past the default interval: %v", err)
	}

	// A negative MinInterval is not "no interval": there is no way to spell
	// that, because it is the failure the guard exists to prevent.
	off := BumpGuard{MinInterval: -time.Hour}
	if err := off.CheckBump(tooSoon, 3); !errors.Is(err, ErrBumpTooSoon) {
		t.Errorf("a negative MinInterval disabled the guardrail: %v", err)
	}
}

// No refusal may carry a token or a hash: these errors reach logs and, in a
// service that reports rotation status, possibly a UI.
func TestNoGuardRefusalCarriesASecret(t *testing.T) {
	token, err := Mint("email")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	guard := BumpGuard{}
	for _, refusal := range []error{
		guard.CheckBump(RotationState{Applied: 0}, 1),
		guard.CheckBump(RotationState{Applied: 2}, 2),
		guard.CheckBump(RotationState{Applied: 2}, 9),
		guard.CheckBump(RotationState{Applied: 2, AppliedAt: time.Now()}, 3),
		guard.CheckBump(RotationState{Applied: 2, AppliedAt: time.Now().Add(-24 * time.Hour)}, 3),
	} {
		if refusal == nil {
			t.Fatal("one of the refusal cases returned nil — the test checked nothing")
		}
		message := refusal.Error()
		for _, secret := range []string{token, Hash(token), Prefix} {
			if strings.Contains(message, secret) {
				t.Errorf("a refusal message leaks a secret: %q", message)
			}
		}
	}
}

// ACCEPTANCE (verifier half, end to end): a retired row that a store still
// answers with must not authenticate. Retirement deletes rows, so in the
// steady state the lookup simply misses — this proves the accepted set is
// enforced even when it has not.
func TestARetiredVersionIsRefusedEvenWhenTheStoreStillHoldsIt(t *testing.T) {
	h := newHarness(t, &helloHandler{})

	previous, current, retired := mustMint(t), mustMint(t), mustMint(t)
	h.store.holdAt(current, "becoming-the-hunter", 3, 3)
	h.store.holdAt(previous, "becoming-the-hunter", 2, 3)
	h.store.holdAt(retired, "becoming-the-hunter", 1, 3)

	for name, token := range map[string]string{"the current version": current, "the previous version": previous} {
		if _, err := h.call(t, bearer(token)); err != nil {
			t.Errorf("%s was refused (%v) — both live versions must authenticate", name, connect.CodeOf(err))
		}
	}

	_, err := h.call(t, bearer(retired))
	if err == nil {
		t.Fatal("a token two versions behind authenticated — the following bump must revoke it")
	}
	if got := connect.CodeOf(err); got != connect.CodeUnauthenticated {
		t.Errorf("a retired token gave %v, want %v — a revoked token is indistinguishable from an unknown one", got, connect.CodeUnauthenticated)
	}
	// And the refusal says nothing about which failure it was.
	if message := err.Error(); strings.Contains(message, "version") || strings.Contains(message, "3") {
		t.Errorf("the refusal %q tells a prober why it failed", message)
	}
}

// A store that does not report the applied version is a store the accepted set
// cannot be checked against. That is this service's bug, not the caller's, so
// it is INTERNAL — and emphatically not "accept anything", which would turn
// revocation off without a word.
func TestAStoreThatReportsNoVersionsFailsClosedAsInternal(t *testing.T) {
	for name, identity := range map[string]Identity{
		"no versions at all":     {Org: "becoming-the-hunter"},
		"no applied version":     {Org: "becoming-the-hunter", TokenVersion: 1},
		"no token version":       {Org: "becoming-the-hunter", AppliedTokenVersion: 1},
		"a negative token row":   {Org: "becoming-the-hunter", TokenVersion: -1, AppliedTokenVersion: 1},
		"a negative applied row": {Org: "becoming-the-hunter", TokenVersion: 1, AppliedTokenVersion: -1},
	} {
		h := newHarness(t, &helloHandler{})
		token := mustMint(t)
		h.store.holdAt(token, identity.Org, identity.TokenVersion, identity.AppliedTokenVersion)

		_, err := h.call(t, bearer(token))
		if err == nil {
			t.Fatalf("%s: the request was authenticated against a store that cannot be version-checked", name)
		}
		if got := connect.CodeOf(err); got != connect.CodeInternal {
			t.Errorf("%s: got %v, want %v — the store is at fault, not the caller", name, got, connect.CodeInternal)
		}
	}
}

// The control for the test above: the same harness with both versions set
// authenticates, so "INTERNAL" is not simply what this harness always answers.
func TestAStoreThatReportsBothVersionsAuthenticates(t *testing.T) {
	h := newHarness(t, &helloHandler{})
	token := mustMint(t)
	h.store.holdAt(token, "becoming-the-hunter", 1, 1)
	if org, err := h.call(t, bearer(token)); err != nil || org != "becoming-the-hunter" {
		t.Fatalf("a fully-reported identity gave (%q, %v), want the org and no error", org, err)
	}
}

// The rotation window as a handler sees it: it learns which version
// authenticated AND which one the org is on, so a service can tell a consumer
// that it is still on the previous token and should cut over before the next
// bump retires it.
func TestTheInterceptorPlantsBothVersionsInTheContext(t *testing.T) {
	store := newRecordingStore()
	token := mustMint(t)
	store.holdAt(token, "becoming-the-hunter", 4, 5)

	interceptor, err := NewInterceptor("email", store)
	if err != nil {
		t.Fatalf("NewInterceptor: %v", err)
	}

	var seen Identity
	wrapped := interceptor.WrapStreamingHandler(func(ctx context.Context, _ connect.StreamingHandlerConn) error {
		seen, _ = FromContext(ctx)
		return nil
	})
	conn := newFakeHandlerConn(hellov1connect.HelloServiceSayHelloProcedure)
	conn.header.Set("Authorization", "Bearer "+token)
	if err := wrapped(context.Background(), conn); err != nil {
		t.Fatalf("a token at the previous version was refused: %v", err)
	}
	if seen.TokenVersion != 4 || seen.AppliedTokenVersion != 5 {
		t.Errorf("the handler saw %+v, want TokenVersion 4 and AppliedTokenVersion 5", seen)
	}
}

func mustMint(t *testing.T) string {
	t.Helper()
	token, err := Mint("email")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	return token
}

// formatVersions renders into error messages an operator reads under pressure,
// so its output is pinned.
func TestFormatVersionsReadsAsProse(t *testing.T) {
	for _, tc := range []struct {
		in   []int32
		want string
	}{
		{nil, "nothing"},
		{[]int32{1}, "token_version 1"},
		{[]int32{1, 2}, "token_versions 1 and 2"},
		{[]int32{1, 2, 3}, "token_versions 1, 2 and 3"},
	} {
		if got := formatVersions(tc.in); got != tc.want {
			t.Errorf("formatVersions(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// spinProbeEnv makes this test binary re-exec itself as the probe child.
const spinProbeEnv = "SPHYRIX_AUTH_SPIN_PROBE"

// spinProbeSentinel is what the child prints on success, so a child that never
// ran cannot be mistaken for one that passed.
const spinProbeSentinel = "spin-probe-ok"

// The largest int32 must not spin. `token_version` is ORG-AUTHORED and the
// reconciler validates it only as "an integer >= 1" — explicitly unbounded
// above — so math.MaxInt32 is a value a tenant can put in its own repo. The
// obvious `for v := low; v <= high; v++` never terminates there (the increment
// wraps to the smallest int32, which is still <= high) and appends until the
// process is OOM-killed.
//
// The REACHABLE path is retirement, not authentication: [AcceptedVersions] is
// called by [RetiredBy] — and so by [BumpGuard.CheckBump] — and directly by a
// service computing its retirement floor. The per-request path uses
// [VersionAccepted], which builds no slice. An earlier version of this test
// claimed the hot path and could not fail; it drives the real caller now.
//
// The probe runs in a SUBPROCESS under GOMEMLIMIT. A regression here does not
// fail an assertion, it allocates about 1.8 GB/s toward a 16 GB target — in
// this package's own history it OOM-killed the machine twice. Bounding the
// child means a regression is a clean non-zero exit instead of an outage.
func TestTheAcceptedSetTerminatesAtTheLargestVersion(t *testing.T) {
	if os.Getenv(spinProbeEnv) == "1" {
		// Child. Reached only via the re-exec below.
		got := AcceptedVersions(math.MaxInt32)
		if len(got) != LiveVersions || got[0] != math.MaxInt32-1 || got[1] != math.MaxInt32 {
			fmt.Fprintf(os.Stderr, "AcceptedVersions(MaxInt32) = %v\n", got)
			os.Exit(3)
		}
		// And through the caller that actually reaches it.
		if retired := RetiredBy(math.MaxInt32, math.MaxInt32); len(retired) != 0 {
			fmt.Fprintf(os.Stderr, "RetiredBy(MaxInt32, MaxInt32) = %v\n", retired)
			os.Exit(4)
		}
		// A sentinel the parent insists on. It does NOT prove the child ran the
		// real calls — a gutted child could print it — but it does mean an
		// empty or skipped child run cannot pass for a successful one.
		fmt.Fprintf(os.Stderr, "%s %d %d %d\n", spinProbeSentinel, len(got), got[0], got[1])
		os.Exit(0)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	// t.Name(), never a literal: a stale -test.run matches zero tests, and
	// `go test` reports "no tests to run" with exit 0 — which the parent would
	// read as success. Renaming this function would have turned the only guard
	// against a confirmed machine-OOMing loop into a no-op, silently.
	cmd := exec.CommandContext(ctx, os.Args[0],
		"-test.run=^"+regexp.QuoteMeta(t.Name())+"$", "-test.timeout=45s")
	cmd.Env = append(os.Environ(), spinProbeEnv+"=1", "GOMEMLIMIT=64MiB", "GOGC=10")

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("the bounded probe did not complete cleanly (%v) — the accepted-set loop is unbounded at math.MaxInt32.\nchild output:\n%s", err, output)
	}
	want := fmt.Sprintf("%s %d %d %d", spinProbeSentinel, LiveVersions, math.MaxInt32-1, math.MaxInt32)
	if !strings.Contains(string(output), want) {
		t.Fatalf("the probe child did not report %q — it did not run, so this guard proved nothing.\nchild output:\n%s", want, output)
	}
}

// The parent above proves the probe mechanism runs; this proves the values, in
// process, where it is safe to do so because the fix makes the call O(1).
func TestTheAcceptedSetIsCorrectAtTheLargestVersion(t *testing.T) {
	if !VersionAccepted(math.MaxInt32, math.MaxInt32) || !VersionAccepted(math.MaxInt32-1, math.MaxInt32) {
		t.Error("the two live versions are not accepted at the largest applied version")
	}
	if VersionAccepted(math.MaxInt32-2, math.MaxInt32) {
		t.Error("a retired version is accepted at the largest applied version")
	}
}

// A request presenting a token at the largest applied version authenticates.
// This is NOT the spin guard — the request path never builds the set — it is
// the end-to-end boundary check that the interceptor's comparison holds there.
func TestARequestAtTheLargestVersionAuthenticates(t *testing.T) {
	h := newHarness(t, &helloHandler{})
	current, previous, retired := mustMint(t), mustMint(t), mustMint(t)
	h.store.holdAt(current, "becoming-the-hunter", math.MaxInt32, math.MaxInt32)
	h.store.holdAt(previous, "becoming-the-hunter", math.MaxInt32-1, math.MaxInt32)
	h.store.holdAt(retired, "becoming-the-hunter", math.MaxInt32-2, math.MaxInt32)

	for name, token := range map[string]string{"the current version": current, "the previous version": previous} {
		if org, err := h.call(t, bearer(token)); err != nil || org != "becoming-the-hunter" {
			t.Errorf("%s at MaxInt32 gave (%q, %v), want the org and no error", name, org, err)
		}
	}
	if _, err := h.call(t, bearer(retired)); err == nil {
		t.Error("a token two versions below MaxInt32 authenticated — it is retired")
	}
}

// ACCEPTANCE (the guardrail's "or"): ADR 020's Consequences call for "a minimum
// interval, OR a check that the new version is in use". [EvidenceRequired]
// enforces both; [EvidenceOptional] drops the second and keeps the first.
//
// The waiver is not laxity, it is reachability. The 2026-09-02 ruling leaves
// sphyrix no custodian-side override, so an org's two commits are the ONLY
// revocation path — and requiring a request at the new version blocks it
// forever when the consumer has been offboarded (the usual reason to revoke),
// has not gone live, or sends monthly. A guardrail that cannot be satisfied is
// an outage of the only revocation mechanism there is.
func TestEvidenceOptionalDropsTheUseCheckButKeepsTheInterval(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }

	// Nothing has EVER authenticated at the applied version.
	neverUsed := RotationState{Applied: 2, AppliedAt: now.Add(-24 * time.Hour)}

	strict := BumpGuard{MinInterval: 15 * time.Minute, Now: clock}
	if err := strict.CheckBump(neverUsed, 3); !errors.Is(err, ErrVersionNotInUse) {
		t.Fatalf("the default guard gave %v, want ErrVersionNotInUse — EvidenceRequired must be the zero value", err)
	}
	if strict.Evidence != EvidenceRequired {
		t.Error("the zero value of BumpGuard is not EvidenceRequired — the safe setting must be the default")
	}

	lenient := BumpGuard{MinInterval: 15 * time.Minute, Now: clock, Evidence: EvidenceOptional}
	if err := lenient.CheckBump(neverUsed, 3); err != nil {
		t.Fatalf("EvidenceOptional refused a bump a day after the last one with no use evidence: %v — revocation would be unreachable", err)
	}

	// The interval is NOT waived by the same switch. This is the assertion
	// that keeps EvidenceOptional from quietly becoming "no guardrail".
	tooSoon := RotationState{Applied: 2, AppliedAt: now.Add(-time.Minute)}
	if err := lenient.CheckBump(tooSoon, 3); !errors.Is(err, ErrBumpTooSoon) {
		t.Errorf("EvidenceOptional gave %v one minute after the last bump, want ErrBumpTooSoon — the interval is never waivable", err)
	}

	// And it does not turn off the other refusals either.
	if err := lenient.CheckBump(RotationState{Applied: 3, AppliedAt: now.Add(-24 * time.Hour)}, 5); !errors.Is(err, ErrNotABump) {
		t.Errorf("EvidenceOptional allowed a version skip: %v", err)
	}

	// EvidenceOptional is the ONLY value that waives anything. EvidencePolicy
	// is an exported named int with exported-field access, so a config value,
	// a cast or a third constant added out of order can all produce something
	// this package does not recognise — and an unrecognised policy that came
	// out LAX would silently disable half of the only revocation guardrail
	// there is. Anything that is not the opt-out must stay strict.
	for _, unknown := range []EvidencePolicy{EvidenceOptional + 1, EvidenceOptional + 7, -1} {
		guard := BumpGuard{MinInterval: 15 * time.Minute, Now: clock, Evidence: unknown}
		if err := guard.CheckBump(neverUsed, 3); !errors.Is(err, ErrVersionNotInUse) {
			t.Errorf("EvidencePolicy(%d) gave %v, want ErrVersionNotInUse — an unrecognised policy must fail closed, never waive the check", unknown, err)
		}
	}
}

// The streaming path must refuse a retired version too. `authenticate` is
// shared, but "the security control is structurally shared" is an argument, not
// an assertion — a caller opening a stream with a revoked token is the case
// that matters.
func TestAStreamingCallerCannotOpenAStreamWithARetiredVersion(t *testing.T) {
	store := newRecordingStore()
	live, retired := mustMint(t), mustMint(t)
	store.holdAt(live, "becoming-the-hunter", 3, 3)
	store.holdAt(retired, "becoming-the-hunter", 1, 3)

	interceptor, err := NewInterceptor("email", store)
	if err != nil {
		t.Fatalf("NewInterceptor: %v", err)
	}
	ran := false
	wrapped := interceptor.WrapStreamingHandler(func(context.Context, connect.StreamingHandlerConn) error {
		ran = true
		return nil
	})

	open := func(token string) error {
		ran = false
		conn := newFakeHandlerConn(hellov1connect.HelloServiceSayHelloProcedure)
		conn.header.Set("Authorization", "Bearer "+token)
		return wrapped(context.Background(), conn)
	}

	if err := open(retired); err == nil {
		t.Error("a retired version opened a stream")
	} else if got := connect.CodeOf(err); got != connect.CodeUnauthenticated {
		t.Errorf("a retired version gave %v, want %v", got, connect.CodeUnauthenticated)
	}
	if ran {
		t.Error("the streaming handler ran behind a retired token")
	}

	if err := open(live); err != nil {
		t.Fatalf("the live version was refused on the streaming path: %v", err)
	}
	if !ran {
		t.Error("the streaming handler did not run for a live token")
	}
}

// versionSource is a scripted [TokenPathVersion] that records every call, so a
// test can assert the READ happened again on each retry rather than trusting
// that it did.
type versionSource struct {
	versions []int // one per call; the last repeats once exhausted
	err      error
	calls    int
}

func (v *versionSource) CurrentVersion(context.Context, string) (int, error) {
	v.calls++
	if v.err != nil {
		return 0, v.err
	}
	if len(v.versions) == 0 {
		return 0, nil
	}
	if v.calls-1 < len(v.versions) {
		return v.versions[v.calls-1], nil
	}
	return v.versions[len(v.versions)-1], nil
}

// The ruled happy path: one metadata read, one write, and the cas that reached
// Vault is the version that was read.
func TestCASWriterPassesTheVersionItRead(t *testing.T) {
	source := &versionSource{versions: []int{7}}
	var got []int
	err := CASWriter{Version: source}.Write(context.Background(), "becoming-the-hunter",
		func(_ context.Context, cas int) error {
			got = append(got, cas)
			return nil
		})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if want := []int{7}; !reflect.DeepEqual(got, want) {
		t.Errorf("the write saw cas %v, want %v", got, want)
	}
	if source.calls != 1 {
		t.Errorf("the version was read %d times, want 1 — a successful write must not re-read", source.calls)
	}
}

// A refused cas is retried AFTER A FRESH READ. Retrying with the same cas
// cannot succeed — the version is exactly what was wrong — so this asserts the
// second attempt carried the second version, not the first one again.
func TestCASWriterRereadsTheVersionOnARefusal(t *testing.T) {
	source := &versionSource{versions: []int{7, 9}}
	var seen []int
	err := CASWriter{Version: source}.Write(context.Background(), "becoming-the-hunter",
		func(_ context.Context, cas int) error {
			seen = append(seen, cas)
			if len(seen) == 1 {
				return fmt.Errorf("vault said no: %w", ErrCASRefused)
			}
			return nil
		})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if want := []int{7, 9}; !reflect.DeepEqual(seen, want) {
		t.Errorf("the write saw cas %v, want %v — the retry must carry a freshly read version", seen, want)
	}
	if source.calls != 2 {
		t.Errorf("the version was read %d times, want 2 — a retry without a re-read is an infinite loop with extra steps", source.calls)
	}
}

// The budget is bounded and nothing is written when it runs out. The error is
// the loud one, so the caller can surface it.
func TestCASWriterGivesUpLoudlyAfterABoundedNumberOfAttempts(t *testing.T) {
	source := &versionSource{versions: []int{1, 2, 3, 4, 5, 6, 7, 8}}
	writes := 0
	err := CASWriter{Version: source, Attempts: 3}.Write(context.Background(), "becoming-the-hunter",
		func(context.Context, int) error {
			writes++
			return ErrCASRefused
		})
	if !errors.Is(err, ErrCASExhausted) {
		t.Fatalf("Write gave %v, want ErrCASExhausted", err)
	}
	if writes != 3 || source.calls != 3 {
		t.Errorf("%d writes and %d reads, want 3 and 3 — the loop must be bounded by Attempts", writes, source.calls)
	}
	if !strings.Contains(err.Error(), "becoming-the-hunter") || !strings.Contains(err.Error(), "3 attempts") {
		t.Errorf("the exhaustion error %q does not name the org and the budget", err)
	}
}

// The exhaustion error wraps BOTH sentinels, so a caller can ask "did the
// budget run out?" and "why?" without parsing the message.
func TestCASExhaustionWrapsTheRefusalToo(t *testing.T) {
	source := &versionSource{versions: []int{1}}
	refusal := fmt.Errorf("vault: check-and-set parameter did not match: %w", ErrCASRefused)
	err := CASWriter{Version: source, Attempts: 2}.Write(context.Background(), "org",
		func(context.Context, int) error { return refusal })
	if !errors.Is(err, ErrCASExhausted) {
		t.Errorf("the error does not match ErrCASExhausted: %v", err)
	}
	if !errors.Is(err, ErrCASRefused) {
		t.Errorf("the error does not match ErrCASRefused: %v — a caller cannot tell WHY the budget ran out", err)
	}
}

// Zero and negative Attempts mean the default, never "unbounded".
func TestCASWriterAttemptsCannotBeUnbounded(t *testing.T) {
	for name, attempts := range map[string]int{"zero": 0, "negative": -5} {
		source := &versionSource{versions: []int{1}}
		writes := 0
		err := CASWriter{Version: source, Attempts: attempts}.Write(context.Background(), "org",
			func(context.Context, int) error {
				writes++
				return ErrCASRefused
			})
		if !errors.Is(err, ErrCASExhausted) {
			t.Errorf("%s: got %v, want ErrCASExhausted", name, err)
		}
		if writes != DefaultCASAttempts {
			t.Errorf("%s: %d attempts, want DefaultCASAttempts (%d)", name, writes, DefaultCASAttempts)
		}
	}
}

// Only a refused cas is retried. Any other write error fails the mint at once —
// retrying an error whose cause is unknown is how a bounded loop becomes an
// unbounded one, and a permission error retried three times is three audit-log
// denials instead of one.
func TestCASWriterDoesNotRetryANonCASError(t *testing.T) {
	source := &versionSource{versions: []int{1}}
	sentinel := errors.New("vault is sealed")
	writes := 0
	err := CASWriter{Version: source}.Write(context.Background(), "org",
		func(context.Context, int) error {
			writes++
			return sentinel
		})
	if !errors.Is(err, sentinel) {
		t.Fatalf("Write gave %v, want the write's own error unchanged", err)
	}
	if errors.Is(err, ErrCASExhausted) {
		t.Error("a non-cas failure was reported as cas exhaustion")
	}
	if writes != 1 {
		t.Errorf("the write ran %d times, want 1 — only a refused cas is retried", writes)
	}
}

// A version source that cannot answer fails the mint, and nothing is written.
// Guessing a cas would be the silent fallback this contract exists to prevent.
func TestCASWriterFailsTheMintWhenTheVersionIsUnknown(t *testing.T) {
	source := &versionSource{err: errors.New("metadata read denied")}
	writes := 0
	err := CASWriter{Version: source}.Write(context.Background(), "org",
		func(context.Context, int) error { writes++; return nil })
	if err == nil {
		t.Fatal("Write succeeded with no version — it must never guess a cas")
	}
	if writes != 0 {
		t.Errorf("the write ran %d times with an unknown version, want 0", writes)
	}
	if !strings.Contains(err.Error(), "metadata read denied") {
		t.Errorf("the error %q loses the cause", err)
	}
}

// A cancelled context stops the loop instead of spending the whole budget.
func TestCASWriterStopsOnACancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	source := &versionSource{versions: []int{1}}
	writes := 0
	err := CASWriter{Version: source}.Write(ctx, "org",
		func(context.Context, int) error { writes++; return ErrCASRefused })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Write gave %v, want context.Canceled", err)
	}
	if writes != 0 || source.calls != 0 {
		t.Errorf("%d writes and %d reads on a cancelled context, want 0 and 0", writes, source.calls)
	}
}

// A misconfigured writer is refused rather than silently doing nothing.
func TestCASWriterRequiresItsCollaborators(t *testing.T) {
	if err := (CASWriter{}).Write(context.Background(), "org", func(context.Context, int) error { return nil }); err == nil {
		t.Error("a CASWriter with no version source was accepted")
	}
	if err := (CASWriter{Version: &versionSource{}}).Write(context.Background(), "org", nil); err == nil {
		t.Error("a CASWriter with no write function was accepted")
	}
}

// The interval constants are PINNED BY INVARIANT here, because every other
// interval test builds its fixtures relative to DefaultMinBumpInterval — a test
// shaped like `AppliedAt: now.Add(-(DefaultMinBumpInterval - time.Minute))`
// moves with the constant, so setting the constant to 0, 1ns or a negative
// duration leaves the whole suite green while the guardrail is off for every
// zero-value BumpGuard{}, which is the configuration the README recommends.
//
// So: assert what the value has to BE, not what some fixture computed from it
// happens to do.
func TestTheDefaultBumpIntervalIsAUsableInterval(t *testing.T) {
	got := BumpGuard{}.minInterval()

	// Zero or negative is not an interval. minInterval() maps a zero or
	// negative FIELD to the default, so a non-positive default would make the
	// guardrail unenforceable with no way for a caller to restore it.
	if got <= 0 {
		t.Fatalf("BumpGuard{}.minInterval() = %s — a zero-value guard must enforce a positive interval, or the interval half of the guardrail is off by default", got)
	}

	// And it must be at least the time an on-platform consumer can take to
	// pick the new token up, which is the floor ADR 020's Consequences put
	// under the safe interval between two bumps. 1ns is positive and useless.
	if got < onPlatformPickupBound {
		t.Errorf("BumpGuard{}.minInterval() = %s, which is below the on-platform pickup bound of %s — a second bump inside that window retires a version consumers have not replaced yet",
			got, onPlatformPickupBound)
	}

	// The bound itself is derived from published numbers; if DefaultRefreshInterval
	// grows past it, the derivation in DefaultMinBumpInterval's doc is stale.
	if onPlatformPickupBound <= DefaultRefreshInterval {
		t.Errorf("onPlatformPickupBound (%s) is not above DefaultRefreshInterval (%s) — the pickup bound must cover the consumer's own re-read",
			onPlatformPickupBound, DefaultRefreshInterval)
	}

	// And an ABSOLUTE floor under the floor. The check above only anchors the
	// bound to DefaultRefreshInterval (5s), a 36x margin, so lowering the bound
	// to 10s would pass it and quietly re-open the interval it is supposed to
	// protect. VSO's `refreshAfter: 1m` (ADR 027 Decision 5) is a published
	// number and the bound cannot be below one refresh cycle.
	if onPlatformPickupBound < time.Minute {
		t.Errorf("onPlatformPickupBound = %s, below ADR 027 Decision 5's refreshAfter of 1m — a consumer cannot pick a token up faster than VSO republishes it",
			onPlatformPickupBound)
	}
}

// DefaultCASAttempts is unpinned in the same way: every CAS test compares
// against the constant, so widening it to 50 keeps them green while turning a
// bounded retry into a long one against a tenant-writable path.
func TestTheDefaultCASAttemptBudgetIsSmallAndPositive(t *testing.T) {
	if DefaultCASAttempts < 1 {
		t.Fatalf("DefaultCASAttempts = %d — a budget below 1 means a mint never attempts its write at all", DefaultCASAttempts)
	}
	if DefaultCASAttempts > 10 {
		t.Errorf("DefaultCASAttempts = %d — the conflict being retried is a tenant overwriting its own path, which is rare and not adversarial; a large budget hides a path being rewritten continuously instead of reporting it", DefaultCASAttempts)
	}
}
