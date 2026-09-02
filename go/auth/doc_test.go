package auth

import (
	"go/ast"
	"go/doc"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ACCEPTANCE: "The package documents that callers must never log the token and
// that the `sphx_` prefix exists for secret scanning."
//
// Both are obligations on every consumer of this package, and a consumer reads
// the package documentation, not the ADR. Asserting on the doc comment is what
// keeps them from being edited away: ADR 027 records "a token in a consumer's
// log" as the design's standing risk, and the prefix is the mitigation that
// only works if people know what it is for.
//
// The checks are paragraph-scoped rather than exact-string, so the wording can
// be improved; what cannot happen is the obligation disappearing.
func TestThePackageDocumentsItsObligations(t *testing.T) {
	paragraphs := packageDocParagraphs(t)

	for _, want := range []struct {
		what     string
		together []string
	}{
		{
			what:     "that a caller must never log the token",
			together: []string{"never log", "token"},
		},
		{
			what:     "that the sphx_ prefix exists for secret scanning",
			together: []string{"sphx_", "secret scanning"},
		},
		{
			what:     "that the authorization header must be kept out of logs and telemetry",
			together: []string{"authorization", "header", "log"},
		},
		{
			what:     "that only the hash is stored, never the plaintext",
			together: []string{"sha-256", "hash"},
		},
		{
			what:     "that a mounted token is re-read on change",
			together: []string{"tokenfromfile", "re-read"},
		},
		// ACCEPTANCE (Story 9.4): "The convention is described as platform-wide
		// with token_version named as the single control, so a second sphyrix
		// service copies it rather than inventing a `revoked` flag."
		//
		// This is the sentence that stops the second sphyrix service from
		// solving revocation again, and the package doc is where its author
		// will look. ADR 020 rejected a `revoked` field explicitly — a second
		// control saying what a second bump already says — so the negative is
		// asserted alongside the positive.
		{
			what:     "that token_version is the platform-wide single control",
			together: []string{"token_version", "platform-wide", "single control"},
		},
		{
			what:     "that a service must not invent a `revoked` flag of its own",
			together: []string{"revoked", "invent"},
		},
		// ACCEPTANCE (Story 9.4): the two-commit procedure, stated explicitly.
		{
			what:     "that one bump mints and does not revoke",
			together: []string{"one bump mints", "does not revoke"},
		},
		{
			// "takes two commits", not "two commits": the same paragraph cites
			// the README heading "Revoking a token: two commits" verbatim, so
			// the looser phrase is satisfied by the citation even after the
			// sentence that makes the claim is deleted.
			what:     "that revoking takes two commits",
			together: []string{"one bump mints", "takes two commits"},
		},
		{
			what:     "that verification is against an accepted set of token_versions",
			together: []string{"accepted set", "token_version"},
		},
	} {
		if !anyParagraphContainsAll(paragraphs, want.together) {
			t.Errorf("the package documentation does not say %s (looked for %q together in one paragraph)", want.what, want.together)
		}
	}
}

// TestTheDocObligationCheckCanFail proves the test above is not vacuous: the
// same matcher run over documentation that says none of it must report a miss.
func TestTheDocObligationCheckCanFail(t *testing.T) {
	empty := []string{"Package auth does something with tokens."}
	for _, together := range [][]string{
		{"never log", "token"},
		{"sphx_", "secret scanning"},
		{"authorization", "header", "log"},
	} {
		if anyParagraphContainsAll(empty, together) {
			t.Errorf("the matcher found %q in documentation that does not contain it", together)
		}
	}
	if !anyParagraphContainsAll([]string{"never log the TOKEN anywhere"}, []string{"never log", "token"}) {
		t.Error("the matcher missed a phrase that is present — it would never find anything")
	}
}

func anyParagraphContainsAll(paragraphs []string, phrases []string) bool {
	for _, paragraph := range paragraphs {
		lower := strings.ToLower(paragraph)
		found := true
		for _, phrase := range phrases {
			if !strings.Contains(lower, strings.ToLower(phrase)) {
				found = false
				break
			}
		}
		if found {
			return true
		}
	}
	return false
}

// packageDocParagraphs returns the package's own doc comment, split into
// paragraphs, read from source exactly as `go doc` would render it.
func packageDocParagraphs(t *testing.T) []string {
	t.Helper()

	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading the package directory: %v", err)
	}
	files := map[string]*ast.File{}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(".", name), nil, parser.ParseComments|parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		files[name] = file
	}

	pkg, err := doc.NewFromFiles(fset, values(files), "github.com/sphyrix/contracts/go/auth")
	if err != nil {
		t.Fatalf("building the package documentation: %v", err)
	}
	if strings.TrimSpace(pkg.Doc) == "" {
		t.Fatal("the package has no doc comment at all")
	}

	// Scope is per paragraph AND per list item. A doc-comment list is a single
	// paragraph as far as blank lines go, so without the second split every
	// bullet's words would pool together and "these two phrases appear
	// together" would be satisfied by two unrelated bullets.
	var paragraphs []string
	for _, block := range strings.Split(pkg.Doc, "\n\n") {
		for _, item := range splitListItems(block) {
			if text := strings.Join(strings.Fields(item), " "); text != "" {
				paragraphs = append(paragraphs, text)
			}
		}
	}
	if len(paragraphs) < 2 {
		t.Fatalf("the package doc split into %d paragraphs — the splitter is not working", len(paragraphs))
	}
	return paragraphs
}

// splitListItems breaks a doc-comment block at each "  - " bullet.
func splitListItems(block string) []string {
	var (
		items   []string
		current []string
	)
	for _, line := range strings.Split(block, "\n") {
		if strings.HasPrefix(strings.TrimRight(line, " "), "  - ") {
			items = append(items, strings.Join(current, "\n"))
			current = nil
		}
		current = append(current, line)
	}
	return append(items, strings.Join(current, "\n"))
}

func values(m map[string]*ast.File) []*ast.File {
	out := make([]*ast.File, 0, len(m))
	for _, file := range m {
		out = append(out, file)
	}
	return out
}

// TestEveryExportedSymbolIsDocumented: this package is imported by every
// sphyrix service and every tenant caller, so its surface is a contract and an
// undocumented export is a contract nobody can read.
func TestEveryExportedSymbolIsDocumented(t *testing.T) {
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading the package directory: %v", err)
	}
	files := map[string]*ast.File{}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(".", name), nil, parser.ParseComments|parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		files[name] = file
	}
	pkg, err := doc.NewFromFiles(fset, values(files), "github.com/sphyrix/contracts/go/auth")
	if err != nil {
		t.Fatalf("building the package documentation: %v", err)
	}

	var undocumented []string
	note := func(kind, name, comment string) {
		if strings.TrimSpace(comment) == "" {
			undocumented = append(undocumented, kind+" "+name)
		}
	}
	for _, value := range append(pkg.Consts, pkg.Vars...) {
		// A grouped `const (...)` carries one doc comment for the block and
		// one per spec; either documents the names in it.
		for _, spec := range value.Decl.Specs {
			valueSpec, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			var names []string
			for _, ident := range valueSpec.Names {
				if ident.IsExported() {
					names = append(names, ident.Name)
				}
			}
			if len(names) == 0 {
				continue
			}
			comment := value.Doc
			if valueSpec.Doc != nil {
				comment = valueSpec.Doc.Text()
			}
			note("const/var", strings.Join(names, ", "), comment)
		}
	}
	for _, fn := range pkg.Funcs {
		note("func", fn.Name, fn.Doc)
	}
	for _, typ := range pkg.Types {
		note("type", typ.Name, typ.Doc)
		for _, fn := range append(typ.Funcs, typ.Methods...) {
			note("func", typ.Name+"."+fn.Name, fn.Doc)
		}
	}
	if len(undocumented) != 0 {
		t.Errorf("undocumented exported symbols: %s", strings.Join(undocumented, ", "))
	}
	if len(pkg.Funcs)+len(pkg.Types) == 0 {
		t.Fatal("no exported symbols were found — this test checked nothing")
	}
}
