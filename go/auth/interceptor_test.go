package auth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"

	"connectrpc.com/connect"

	hellov1 "github.com/sphyrix/contracts/gen/go/hello/v1"
	"github.com/sphyrix/contracts/gen/go/hello/v1/hellov1connect"
)

// recordingStore is the acceptance criterion's instrument: a [TokenStore] that
// keeps every argument it was ever handed, so a test can assert what the
// interceptor passed rather than trusting that it hashed.
type recordingStore struct {
	mu      sync.Mutex
	seen    []string
	orgs    map[string]Identity // hash -> identity
	failing error
}

func newRecordingStore() *recordingStore {
	return &recordingStore{orgs: map[string]Identity{}}
}

func (s *recordingStore) hold(token, org string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.orgs[Hash(token)] = Identity{Org: org, TokenVersion: 1}
}

func (s *recordingStore) LookupTokenHash(_ context.Context, sha256Hex string) (Identity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seen = append(s.seen, sha256Hex)
	if s.failing != nil {
		return Identity{}, s.failing
	}
	identity, ok := s.orgs[sha256Hex]
	if !ok {
		return Identity{}, fmt.Errorf("looking up a token: %w", ErrTokenNotFound)
	}
	return identity, nil
}

func (s *recordingStore) arguments() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.seen...)
}

// helloHandler answers with the caller's org, after checking that the caller
// owns the resource it is asking for. resourceOrg stands in for "the org
// column of the row this handler just loaded".
type helloHandler struct {
	resourceOrg string
}

func (h *helloHandler) SayHello(ctx context.Context, req *connect.Request[hellov1.SayHelloRequest]) (*connect.Response[hellov1.SayHelloResponse], error) {
	if h.resourceOrg != "" {
		if err := AuthorizeOrg(ctx, h.resourceOrg); err != nil {
			return nil, err
		}
	}
	org, ok := OrgFromContext(ctx)
	if !ok {
		org = "(unauthenticated)"
	}
	return connect.NewResponse(&hellov1.SayHelloResponse{Message: org}), nil
}

type harness struct {
	store  *recordingStore
	logs   *bytes.Buffer
	server *httptest.Server
	client hellov1connect.HelloServiceClient
}

// newHarness stands up the real interceptor in front of a real Connect server
// reached by a real Connect client, so that what a test asserts is the gRPC
// code a caller actually receives.
func newHarness(t *testing.T, handler *helloHandler, opts ...Option) *harness {
	t.Helper()

	store := newRecordingStore()
	logs := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	interceptor, err := NewInterceptor("email", store, append([]Option{WithLogger(logger)}, opts...)...)
	if err != nil {
		t.Fatalf("NewInterceptor: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle(hellov1connect.NewHelloServiceHandler(handler, connect.WithInterceptors(interceptor)))
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	return &harness{
		store:  store,
		logs:   logs,
		server: server,
		client: hellov1connect.NewHelloServiceClient(server.Client(), server.URL),
	}
}

// call makes one request presenting authorization exactly as given. A nil
// authorization sends no header at all.
func (h *harness) call(t *testing.T, authorization *string) (string, error) {
	t.Helper()
	if authorization == nil {
		return h.callWith(t)
	}
	return h.callWith(t, *authorization)
}

// callWith makes one request carrying exactly the given Authorization headers
// — none, one, or several.
func (h *harness) callWith(t *testing.T, authorizations ...string) (string, error) {
	t.Helper()
	req := connect.NewRequest(&hellov1.SayHelloRequest{Name: "sphyrix"})
	for _, authorization := range authorizations {
		req.Header().Add("Authorization", authorization)
	}
	res, err := h.client.SayHello(context.Background(), req)
	if err != nil {
		return "", err
	}
	return res.Msg.GetMessage(), nil
}

func bearer(token string) *string {
	value := "Bearer " + token
	return &value
}

// ACCEPTANCE: "The server interceptor never compares plaintext: a test injects
// a TokenStore recording its arguments and asserts it receives only a hash."
func TestTheStoreOnlyEverSeesAHash(t *testing.T) {
	h := newHarness(t, &helloHandler{})

	minted, err := Mint("email")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	h.store.hold(minted, "becoming-the-hunter")

	unknown, err := Mint("email")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	for _, token := range []string{minted, unknown} {
		if _, err := h.call(t, bearer(token)); err != nil && connect.CodeOf(err) != connect.CodeUnauthenticated {
			t.Fatalf("calling with a token: %v", err)
		}
	}

	arguments := h.store.arguments()
	if len(arguments) != 2 {
		t.Fatalf("the store was called %d times, want 2 — the test proved nothing", len(arguments))
	}
	for i, argument := range arguments {
		if argument != Hash([]string{minted, unknown}[i]) {
			t.Errorf("argument %d is not SHA-256 of the presented token", i)
		}
		if len(argument) != HashHexLen {
			t.Errorf("argument %d is %d characters, want a %d-character hash", i, len(argument), HashHexLen)
		}
		for _, c := range argument {
			if !strings.ContainsRune("0123456789abcdef", c) {
				t.Fatalf("argument %d contains %q — it is not lowercase hex", i, c)
			}
		}
		// The decisive check: no run of the plaintext survives into the store,
		// down to fragments far too short to be a coincidence in 64 hex
		// characters.
		for _, token := range []string{minted, unknown} {
			if strings.Contains(argument, token) {
				t.Fatalf("argument %d is the plaintext token", i)
			}
			secret := strings.TrimPrefix(token, "sphx_email_")
			for size := 6; size <= len(secret); size++ {
				for start := 0; start+size <= len(secret); start++ {
					if strings.Contains(argument, secret[start:start+size]) {
						t.Fatalf("argument %d contains a %d-character run of a presented token", i, size)
					}
				}
			}
		}
		if strings.Contains(argument, Prefix) {
			t.Errorf("argument %d contains %q — the plaintext leaked", i, Prefix)
		}
	}
}

// TestTokenStoreCannotBeHandedPlaintext is a tripwire on the interface itself:
// one method, taking one string that the interceptor only ever fills with a
// hash. It fails if someone adds a plaintext-taking method, which is how the
// property above would be lost without any existing test noticing.
func TestTokenStoreCannotBeHandedPlaintext(t *testing.T) {
	iface := reflect.TypeFor[TokenStore]()
	if got := iface.NumMethod(); got != 1 {
		names := make([]string, 0, got)
		for i := range got {
			names = append(names, iface.Method(i).Name)
		}
		t.Fatalf("TokenStore has %d methods (%v), want exactly 1: a second method is a second way to hand the store a secret", got, names)
	}
	method := iface.Method(0)
	if method.Name != "LookupTokenHash" {
		t.Errorf("TokenStore's method is %q, want LookupTokenHash — the name is the contract", method.Name)
	}
	if got := method.Type.NumIn(); got != 2 {
		t.Errorf("LookupTokenHash takes %d arguments, want 2 (context, hash)", got)
	}
}

// ACCEPTANCE: "A malformed, absent, wrong-prefix and correct-prefix-but-unknown
// token each yield UNAUTHENTICATED."
func TestEveryBadTokenIsUnauthenticated(t *testing.T) {
	h := newHarness(t, &helloHandler{})

	valid, err := Mint("email")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	h.store.hold(valid, "becoming-the-hunter")

	unknown, err := Mint("email")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	foreign, err := Mint("billing")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	secret := strings.TrimPrefix(valid, "sphx_email_")

	raw := func(v string) *string { return &v }
	cases := map[string]*string{
		"absent":                               nil,
		"an empty header":                      raw(""),
		"the scheme alone":                     raw("Bearer"),
		"the scheme and nothing else":          raw("Bearer "),
		"whitespace after the scheme":          raw("Bearer    "),
		"malformed — no scheme":                raw(valid),
		"malformed — the wrong scheme":         raw("Basic " + valid),
		"a scheme that merely starts the same": raw("Bearerx " + valid),
		"a six-character scheme":               raw("Basicx " + valid),
		"malformed — a Vault-ish token":        bearer("hvs.CAESIJ2example"),
		"malformed — random text":              bearer("not a token at all"),
		"the wrong prefix":                     bearer("ghp_email_" + secret),
		"no prefix":                            bearer("email_" + secret),
		"a lookalike prefix":                   bearer("sphx-email_" + secret),
		"the right prefix, another service":    bearer(foreign),
		"the right prefix, no service":         bearer("sphx__" + secret),
		"the right prefix, a short secret":     bearer("sphx_email_" + secret[:20]),
		"the right prefix, a padded secret":    bearer("sphx_email_" + secret + "=="),
		"the right prefix, unknown to us":      bearer(unknown),
		"a valid token with a suffix":          bearer(valid + "x"),
		"a valid token that has been upcased":  bearer(strings.ToUpper(valid)),
	}

	for name, authorization := range cases {
		_, err := h.call(t, authorization)
		if err == nil {
			t.Errorf("%s: the call succeeded; want UNAUTHENTICATED", name)
			continue
		}
		if got := connect.CodeOf(err); got != connect.CodeUnauthenticated {
			t.Errorf("%s: got %v, want %v", name, got, connect.CodeUnauthenticated)
		}
		// One answer for every failure: a prober must not be able to tell
		// "unknown token" from "malformed" from "absent".
		if got, want := err.Error(), "unauthenticated"; !strings.Contains(got, want) {
			t.Errorf("%s: the message is %q, want the one contentless answer %q", name, got, want)
		}
	}

	// A request carrying two Authorization headers is ambiguous: RFC 7235 §4.2
	// allows one, and a credential that depends on which hop reads it is not a
	// credential. Both orderings are refused, including the one whose FIRST
	// header is the valid token.
	for name, headers := range map[string][]string{
		"valid then rubbish": {"Bearer " + valid, "Bearer nonsense"},
		"rubbish then valid": {"Bearer nonsense", "Bearer " + valid},
		"the same twice":     {"Bearer " + valid, "Bearer " + valid},
	} {
		if _, err := h.callWith(t, headers...); connect.CodeOf(err) != connect.CodeUnauthenticated {
			t.Errorf("two Authorization headers (%s): got %v, want %v", name, connect.CodeOf(err), connect.CodeUnauthenticated)
		}
	}

	// The scheme is matched case-insensitively (RFC 7235 §2.1), so the
	// lowercase and uppercase forms must SUCCEED. Without these the
	// case-insensitivity could be dropped for an exact "Bearer " comparison and
	// nothing would notice.
	if org, err := h.call(t, raw("bearer "+valid)); err != nil || org != "becoming-the-hunter" {
		t.Errorf("a lowercase `bearer` scheme was refused (org=%q): %v", org, err)
	}
	if org, err := h.call(t, raw("BEARER "+valid)); err != nil || org != "becoming-the-hunter" {
		t.Errorf("an uppercase `BEARER` scheme was refused (org=%q): %v", org, err)
	}

	// And the control: the same harness admits the valid token, so the table
	// above is not passing because everything fails.
	org, err := h.call(t, bearer(valid))
	if err != nil {
		t.Fatalf("the valid token was refused: %v", err)
	}
	if org != "becoming-the-hunter" {
		t.Errorf("the handler saw org %q, want becoming-the-hunter", org)
	}
}

// TestAShapeFailureNeverReachesTheStore: a value that cannot be one of our
// tokens is refused before a lookup is spent on it.
func TestAShapeFailureNeverReachesTheStore(t *testing.T) {
	h := newHarness(t, &helloHandler{})
	foreign, err := Mint("billing")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	for _, token := range []string{"not-a-token", "ghp_email_x", foreign} {
		if _, err := h.call(t, bearer(token)); connect.CodeOf(err) != connect.CodeUnauthenticated {
			t.Fatalf("%q: got %v, want UNAUTHENTICATED", token, connect.CodeOf(err))
		}
	}
	if got := h.store.arguments(); len(got) != 0 {
		t.Errorf("the store was consulted %d times for tokens that cannot be ours", len(got))
	}
}

// ACCEPTANCE: "a valid token for org A asking for org B's resource yields
// PERMISSION_DENIED."
func TestACrossOrgRequestIsPermissionDenied(t *testing.T) {
	// The handler's resource belongs to org B.
	h := newHarness(t, &helloHandler{resourceOrg: "org-b"})

	tokenA, err := Mint("email")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	tokenB, err := Mint("email")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	h.store.hold(tokenA, "org-a")
	h.store.hold(tokenB, "org-b")

	_, err = h.call(t, bearer(tokenA))
	if err == nil {
		t.Fatal("org A reached org B's resource")
	}
	if got := connect.CodeOf(err); got != connect.CodePermissionDenied {
		t.Errorf("org A asking for org B's resource: got %v, want %v", got, connect.CodePermissionDenied)
	}

	// The same request from the owner succeeds — otherwise the check above
	// would pass for a handler that denied everybody.
	org, err := h.call(t, bearer(tokenB))
	if err != nil {
		t.Fatalf("org B was refused its own resource: %v", err)
	}
	if org != "org-b" {
		t.Errorf("the handler saw org %q, want org-b", org)
	}
}

func TestAuthorizeOrg(t *testing.T) {
	authenticated := NewContext(context.Background(), Identity{Org: "org-a", TokenVersion: 1})

	if err := AuthorizeOrg(authenticated, "org-a"); err != nil {
		t.Errorf("the owner was refused its own resource: %v", err)
	}
	for name, tc := range map[string]struct {
		ctx      context.Context
		resource string
		want     connect.Code
	}{
		"another org's resource":   {authenticated, "org-b", connect.CodePermissionDenied},
		"an unowned resource":      {authenticated, "", connect.CodePermissionDenied},
		"an empty identity":        {NewContext(context.Background(), Identity{}), "", connect.CodePermissionDenied},
		"an empty identity vs org": {NewContext(context.Background(), Identity{}), "org-a", connect.CodePermissionDenied},
		"no identity at all":       {context.Background(), "org-a", connect.CodeUnauthenticated},
	} {
		err := AuthorizeOrg(tc.ctx, tc.resource)
		if err == nil {
			t.Errorf("%s: allowed; want %v", name, tc.want)
			continue
		}
		if got := connect.CodeOf(err); got != tc.want {
			t.Errorf("%s: got %v, want %v", name, got, tc.want)
		}
	}
}

// TestAStoreFailureIsUnavailableNotUnauthenticated: a database outage must not
// tell every caller its token is bad — they would all go and fetch new ones,
// and the outage would be invisible in the error codes.
func TestAStoreFailureIsUnavailableNotUnauthenticated(t *testing.T) {
	h := newHarness(t, &helloHandler{})
	valid, err := Mint("email")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	h.store.hold(valid, "becoming-the-hunter")
	h.store.failing = errors.New("dial tcp 10.0.0.1:5432: connect: connection refused")

	_, err = h.call(t, bearer(valid))
	if err == nil {
		t.Fatal("a request succeeded while the token store was down")
	}
	if got := connect.CodeOf(err); got != connect.CodeUnavailable {
		t.Errorf("got %v, want %v", got, connect.CodeUnavailable)
	}

	// And the store's own error text is not handed to the caller.
	if strings.Contains(err.Error(), "5432") {
		t.Errorf("the store's error reached the caller: %v", err)
	}
}

// TestAnEmptyOrgFromTheStoreIsInternal: an org of "" would authorize nothing
// under AuthorizeOrg, but it would still let a handler run with a caller the
// service cannot name.
func TestAnEmptyOrgFromTheStoreIsInternal(t *testing.T) {
	h := newHarness(t, &helloHandler{})
	valid, err := Mint("email")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	h.store.hold(valid, "")

	_, err = h.call(t, bearer(valid))
	if got := connect.CodeOf(err); got != connect.CodeInternal {
		t.Errorf("got %v, want %v", got, connect.CodeInternal)
	}
}

func TestExemptProceduresRunWithoutAToken(t *testing.T) {
	h := newHarness(t, &helloHandler{}, WithExemptProcedures(hellov1connect.HelloServiceSayHelloProcedure))
	org, err := h.call(t, nil)
	if err != nil {
		t.Fatalf("an exempt procedure was refused: %v", err)
	}
	if org != "(unauthenticated)" {
		t.Errorf("the handler saw org %q; an exempt procedure must carry no identity", org)
	}
	if got := h.store.arguments(); len(got) != 0 {
		t.Errorf("an exempt procedure consulted the store %d times", len(got))
	}

	// A procedure that was not exempted still needs a token — otherwise
	// "exempt" would be indistinguishable from "no auth at all". The near-miss
	// names pin the matching as EXACT: a prefix or suffix rule would exempt
	// more procedures than the operator named, which is precisely the silently
	// public endpoint the option's doc warns about.
	for name, exempt := range map[string]string{
		"an unrelated procedure":   "/hello.v1.HelloService/SomethingElse",
		"a prefix of the live one": "/hello.v1.HelloService/SayHell",
		"a suffix of the live one": "hello.v1.HelloService/SayHello",
		"the package alone":        "/hello.v1.HelloService/",
		"the live one, upcased":    "/hello.v1.HelloService/SAYHELLO",
	} {
		other := newHarness(t, &helloHandler{}, WithExemptProcedures(exempt))
		if _, err := other.call(t, nil); connect.CodeOf(err) != connect.CodeUnauthenticated {
			t.Errorf("%s (%q) exempted the live procedure: %v", name, exempt, err)
		}
	}
}

func TestWithExemptPredicate(t *testing.T) {
	h := newHarness(t, &helloHandler{}, WithExempt(func(procedure string) bool {
		return strings.HasPrefix(procedure, "/hello.v1.")
	}))
	if _, err := h.call(t, nil); err != nil {
		t.Fatalf("an exempt procedure was refused: %v", err)
	}
}

// TestNothingLogsOrReturnsTheToken drives every refusal path with a token whose
// secret is a distinctive marker, then searches everything the process emitted
// — logs at debug and the error the caller received — for any run of it.
//
// ADR 027's stated risk is a token in a log; this is the assertion that the
// risk is not realised here.
func TestNothingLogsOrReturnsTheToken(t *testing.T) {
	h := newHarness(t, &helloHandler{resourceOrg: "org-b"})

	known, err := Mint("email")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	unknown, err := Mint("email")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	foreign, err := Mint("billing")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	h.store.hold(known, "org-a")

	var errorText strings.Builder
	presented := []string{known, unknown, foreign, "sphx_email_TOOSHORT", "Basic " + known}
	for _, token := range presented {
		if _, err := h.call(t, bearer(token)); err != nil {
			errorText.WriteString(err.Error())
			errorText.WriteString("\n")
		}
	}
	// And a store outage, whose error path logs at warn.
	h.store.failing = errors.New("the database is down")
	if _, err := h.call(t, bearer(known)); err != nil {
		errorText.WriteString(err.Error())
	}

	emitted := h.logs.String() + errorText.String()
	if len(emitted) == 0 {
		t.Fatal("nothing was logged or returned — this test checked nothing")
	}
	for _, token := range presented {
		if strings.Contains(emitted, token) {
			t.Fatalf("a token appears verbatim in the logs or in an error")
		}
		if strings.Contains(emitted, Hash(token)) {
			t.Fatalf("a token's hash appears in the logs or in an error")
		}
		secret := strings.TrimPrefix(token, "sphx_email_")
		if len(secret) < 8 {
			continue
		}
		for size := 8; size <= len(secret); size++ {
			for start := 0; start+size <= len(secret); start++ {
				if strings.Contains(emitted, secret[start:start+size]) {
					t.Fatalf("a %d-character run of a token appears in the logs or in an error", size)
				}
			}
		}
	}
	// The header's name may be mentioned; its value may not. Prove the search
	// above could have found something by looking for a marker that IS there.
	if !strings.Contains(emitted, "procedure=") {
		t.Error("the captured logs do not look like this interceptor's logs — the search may be looking in the wrong place")
	}
}

// TestTheContentlessErrorsAreNotShared pins the reason they are built per call
// rather than kept as package-level values.
//
// connect.Error.Meta() lazily allocates on its receiver. A shared value handed
// to concurrent requests is therefore a data race the moment any downstream
// interceptor annotates it — and whatever it was annotated with would then ride
// along on every later caller's error. Without this assertion, a future "these
// allocations are wasteful" refactor reintroduces both silently.
func TestTheContentlessErrorsAreNotShared(t *testing.T) {
	for name, build := range map[string]func() error{
		"UNAUTHENTICATED":   errUnauthenticated,
		"PERMISSION_DENIED": errPermissionDenied,
		"UNAVAILABLE":       errUnavailable,
		"INTERNAL":          errInternal,
	} {
		first, second := build(), build()

		firstErr, ok := first.(*connect.Error)
		if !ok {
			t.Fatalf("%s: %T is not a *connect.Error", name, first)
		}
		secondErr, ok := second.(*connect.Error)
		if !ok {
			t.Fatalf("%s: %T is not a *connect.Error", name, second)
		}
		if firstErr == secondErr {
			t.Errorf("%s: two calls returned the same *connect.Error", name)
			continue
		}

		firstErr.Meta().Set("X-Poisoned", "1")
		if got := secondErr.Meta().Get("X-Poisoned"); got != "" {
			t.Errorf("%s: annotating one error changed another — the value is shared", name)
		}
		if got := build().(*connect.Error).Meta().Get("X-Poisoned"); got != "" {
			t.Errorf("%s: a freshly built error carries an annotation from an earlier one", name)
		}
	}
}

func TestNewInterceptorRefusesAWiringMistake(t *testing.T) {
	if _, err := NewInterceptor("email", nil); err == nil {
		t.Error("NewInterceptor accepted a nil TokenStore")
	}
	for _, service := range []string{"", "Email", "email_relay", "email service"} {
		if _, err := NewInterceptor(service, newRecordingStore()); err == nil {
			t.Errorf("NewInterceptor accepted the service name %q", service)
		}
	}
	if _, err := NewInterceptor("email", newRecordingStore()); err != nil {
		t.Errorf("NewInterceptor rejected a correct wiring: %v", err)
	}
}
