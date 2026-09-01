// Package contractcheck asserts properties over every proto package this
// module publishes, by walking the compiled descriptor set rather than
// reading source.
package contractcheck_test

import (
	"strings"
	"testing"

	_ "github.com/sphyrix/contracts/gen/go/email/v1"
	_ "github.com/sphyrix/contracts/gen/go/hello/v1"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
)

// forbiddenFieldSubstrings catches any field that would let a caller see or
// carry Postal's own credentials. Design 001 §9.2: Postal's per-message
// token is deliberately never exposed — it is only useful with a Postal API
// key, which callers never hold.
var forbiddenFieldSubstrings = []string{
	"postal_token",
	"postal_api_key",
	"postal_apikey",
	"api_key",
	"apikey",
}

// TestNoPostalCredentialFields walks every message field in every proto
// package registered by this module's generated SDK and fails if any field
// name matches a Postal credential pattern. It is descriptor-based (not a
// source grep) so it also catches fields introduced by a future package
// whose comments omit the word "Postal" entirely.
func TestNoPostalCredentialFields(t *testing.T) {
	visited := map[protoreflect.FullName]bool{}
	var checked int

	var walk func(md protoreflect.MessageDescriptor)
	walk = func(md protoreflect.MessageDescriptor) {
		if visited[md.FullName()] {
			return
		}
		visited[md.FullName()] = true

		fields := md.Fields()
		for i := 0; i < fields.Len(); i++ {
			f := fields.Get(i)
			checked++
			lower := strings.ToLower(string(f.Name()))
			for _, bad := range forbiddenFieldSubstrings {
				if strings.Contains(lower, bad) {
					t.Errorf("%s.%s: field name matches forbidden pattern %q — Postal's per-message token/API key must never appear on this contract (design 001 §9.2)", md.FullName(), f.Name(), bad)
				}
			}
			if f.Kind() == protoreflect.MessageKind || f.Kind() == protoreflect.GroupKind {
				walk(f.Message())
			}
		}

		nested := md.Messages()
		for i := 0; i < nested.Len(); i++ {
			walk(nested.Get(i))
		}
	}

	var sawFile bool
	protoregistry.GlobalFiles.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
		if !strings.HasPrefix(string(fd.Package()), "email.v1") && !strings.HasPrefix(string(fd.Package()), "hello.v1") {
			return true
		}
		sawFile = true
		msgs := fd.Messages()
		for i := 0; i < msgs.Len(); i++ {
			walk(msgs.Get(i))
		}
		return true
	})

	if !sawFile {
		t.Fatal("no email.v1/hello.v1 file descriptors registered — is the generated package imported?")
	}
	if checked == 0 {
		t.Fatal("walked zero fields — the descriptor walk is not visiting any message")
	}
}
