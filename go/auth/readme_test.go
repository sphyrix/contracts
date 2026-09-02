package auth

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// ACCEPTANCE (Story 9.4): "The two-commit revocation procedure is documented as
// a numbered procedure (in the contracts README and referenced from
// `email-onboarding.md`), stating explicitly that one bump mints and does not
// revoke."
//
// A prose paragraph saying "revocation takes two bumps" is not a procedure, and
// ADR 020's Consequences are explicit about why this one has to be written down
// as a numbered sequence: the intuitive single edit MINTS rather than revokes,
// and someone reaching for it in an incident will assume otherwise. The README
// is what they will read, so the README is what is asserted.
//
// The `email-onboarding.md` half lives in `sphyrix/infrastructure` (Story 12.3
// / #441) and cannot be written from this repo. What this repo owes it is a
// STABLE ANCHOR, which is pinned below: GitHub derives the anchor from the
// heading text, so an innocuous heading edit here silently breaks that link.
func TestTheReadmeDocumentsTheTwoCommitRevocation(t *testing.T) {
	readme := readReadme(t)
	lower := strings.ToLower(readme)

	// The anchor the infrastructure runbook links to is derived from this
	// exact heading. Changing it is a cross-repo break, not a wording change.
	const heading = "#### Revoking a token: two commits"
	if !strings.Contains(readme, heading) {
		t.Fatalf("the README has no %q heading — the anchor #revoking-a-token-two-commits that email-onboarding.md links to is gone", heading)
	}

	section := revocationSection(t, readme, heading)
	sectionLower := strings.ToLower(section)

	// A numbered procedure: consecutive "1." "2." ... at the start of a line.
	steps := regexp.MustCompile(`(?m)^(\d+)\. `).FindAllStringSubmatch(section, -1)
	if len(steps) < 4 {
		t.Errorf("the revocation section has %d numbered steps, want at least 4 — a paragraph is not a procedure", len(steps))
	}
	for i, step := range steps {
		if want := strconv.Itoa(i + 1); step[1] != want {
			t.Errorf("step %d is numbered %q, want %q — the steps must read as a sequence", i+1, step[1], want)
		}
	}

	// The thing the reader gets wrong, stated explicitly.
	for _, phrase := range []string{"one bump mints", "does not revoke", "two commits"} {
		if !strings.Contains(sectionLower, phrase) {
			t.Errorf("the revocation section does not say %q — the single edit that mints rather than revokes is exactly the misreading this procedure exists to prevent", phrase)
		}
	}

	// Both bumps have to be in the procedure, and so does the off-platform
	// delivery rerun: ADR 019's Consequences make it a step of rotation, not
	// an afterthought, and a consumer whose command is never rerun fails
	// closed at step 4.
	for _, phrase := range []string{"off-platform", "rerun"} {
		if !strings.Contains(sectionLower, phrase) {
			t.Errorf("the revocation section does not mention %q — an off-platform consumer that is never redelivered to is stranded by the second bump", phrase)
		}
	}

	// The evidence half of the guardrail is WAIVABLE, and the procedure has to
	// say so. ADR 020 asks for "a minimum interval, OR a check that the new
	// version is in use"; without the waiver this very section contradicts
	// itself, because it lists an offboarded consumer as a reason to revoke and
	// an offboarded consumer never authenticates at the new version. The
	// interval, by contrast, is never waivable — assert both halves, or the
	// waiver could be widened into "no guardrail" without a test noticing.
	// Scoped to ONE paragraph, not to the section: "waivable",
	// "EvidenceOptional" and "offboarded" all occur elsewhere in this section
	// for unrelated reasons, so a section-wide check passes even after the
	// waiver paragraph is deleted outright. It has to be the same paragraph
	// that says the waiver exists AND names the switch.
	if !anyParagraphContainsAll(paragraphsOf(section), []string{"waivable", "evidenceoptional"}) {
		t.Error("no single paragraph of the revocation section says the evidence check is waivable AND names EvidenceOptional — without it an operator whose consumer can never authenticate at the new version finds the only revocation path blocked with no way out, and this section still lists an offboarded consumer as a reason to revoke")
	}
	// The interval is the half that is NEVER waivable; if that sentence goes,
	// the waiver above can be widened into "no guardrail" unnoticed.
	if !strings.Contains(sectionLower, "no interval") {
		t.Error("the revocation section no longer says there is no way to spell \"no interval\" — the interval must not become waivable alongside the evidence check")
	}

	// ACCEPTANCE: "The convention is described as platform-wide with
	// `token_version` named as the single control, so a second sphyrix service
	// copies it rather than inventing a `revoked` flag."
	for _, phrase := range []string{"platform-wide", "single control", "token_version", "`revoked`"} {
		if !strings.Contains(lower, strings.ToLower(phrase)) {
			t.Errorf("the README does not say %q — a second sphyrix service reading it would not know this convention is the platform's one mechanism", phrase)
		}
	}
}

// TestTheReadmeCheckCanFail proves the matchers above are not vacuous: run over
// a README that says none of it, every one of them must miss.
func TestTheReadmeCheckCanFail(t *testing.T) {
	const empty = "# contracts\n\nSome protobuf schemas and a Go SDK.\n"

	if strings.Contains(empty, "#### Revoking a token: two commits") {
		t.Error("the heading matcher found a heading in a README that has none")
	}
	if steps := regexp.MustCompile(`(?m)^(\d+)\. `).FindAllString(empty, -1); len(steps) != 0 {
		t.Errorf("the step matcher found %d numbered steps in prose with none", len(steps))
	}
	for _, phrase := range []string{"one bump mints", "does not revoke", "platform-wide", "single control"} {
		if strings.Contains(strings.ToLower(empty), phrase) {
			t.Errorf("the phrase matcher found %q in a README that does not contain it", phrase)
		}
	}
	// And the matchers do find what is present, so they are not simply blind.
	present := "1. first\n2. second\n\none bump mints and does not revoke"
	if steps := regexp.MustCompile(`(?m)^(\d+)\. `).FindAllString(present, -1); len(steps) != 2 {
		t.Errorf("the step matcher found %d steps in a two-step list", len(steps))
	}
	if !strings.Contains(present, "one bump mints") {
		t.Error("the phrase matcher missed a phrase that is present — it would never find anything")
	}
}

// paragraphsOf splits markdown into blank-line-separated paragraphs, so an
// assertion that two phrases belong together cannot be satisfied by two
// unrelated sentences that merely share a section.
func paragraphsOf(section string) []string {
	var paragraphs []string
	for _, block := range strings.Split(section, "\n\n") {
		if text := strings.Join(strings.Fields(block), " "); text != "" {
			paragraphs = append(paragraphs, text)
		}
	}
	return paragraphs
}

// revocationSection returns the README text from the given heading to the next
// heading at the same level or above, so an assertion about "the procedure"
// cannot be satisfied by a sentence somewhere else in the file.
func revocationSection(t *testing.T, readme, heading string) string {
	t.Helper()

	start := strings.Index(readme, heading)
	if start < 0 {
		t.Fatalf("heading %q not found", heading)
	}
	rest := readme[start+len(heading):]

	end := len(rest)
	for _, line := range []string{"\n# ", "\n## ", "\n### ", "\n#### ", "\n##### "} {
		if at := strings.Index(rest, line); at >= 0 && at < end {
			end = at
		}
	}
	section := rest[:end]
	if strings.TrimSpace(section) == "" {
		t.Fatal("the revocation heading is followed by nothing — the section is empty")
	}
	return section
}

// readReadme reads the module's README, which sits two directories above this
// package.
func readReadme(t *testing.T) string {
	t.Helper()
	content, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatalf("reading the module README: %v", err)
	}
	return string(content)
}
