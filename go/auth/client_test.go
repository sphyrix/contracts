package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	hellov1 "github.com/sphyrix/contracts/gen/go/hello/v1"
	"github.com/sphyrix/contracts/gen/go/hello/v1/hellov1connect"
)

// testClock is a clock a test advances by hand, so change detection can be
// proven at its real interval without the test sleeping through it.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func newTestClock() *testClock {
	return &testClock{now: time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)}
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func writeToken(t *testing.T, path, token string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}

// ACCEPTANCE: "TokenFromFile re-reads the file after the underlying content
// changes, within a bounded interval — the test rewrites the file mid-run and
// fails if the old value is served."
//
// The clock is injected so the assertion is about the INTERVAL rather than
// about how long the test was willing to wait. A source that cached for the
// process lifetime — the failure mode design 001 §10 names — fails the last
// assertion here.
func TestTokenFromFileRereadsAfterTheContentChanges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	before, err := Mint("email")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	after, err := Mint("email")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	writeToken(t, path, before)

	clock := newTestClock()
	source := TokenFromFile(path, withClock(clock.Now))

	got, err := source.Token(context.Background())
	if err != nil {
		t.Fatalf("the first read: %v", err)
	}
	if got != before {
		t.Fatalf("the first read returned the wrong token")
	}

	// The token is re-minted under the running process — every dev/test `up`.
	writeToken(t, path, after)

	// Inside the interval the cached value is still served: the contract is a
	// BOUNDED staleness, not a read per request.
	if got, err := source.Token(context.Background()); err != nil || got != before {
		t.Errorf("inside the refresh interval the source did not serve its cached value (err=%v)", err)
	}

	// Once the interval has elapsed the new token must be served. This is the
	// assertion that fails for a source that caches for the process lifetime.
	clock.advance(DefaultRefreshInterval)
	got, err = source.Token(context.Background())
	if err != nil {
		t.Fatalf("the read after the interval: %v", err)
	}
	if got == before {
		t.Fatal("the source served the OLD token after the file changed and the interval elapsed")
	}
	if got != after {
		t.Fatalf("the source served neither the old nor the new token")
	}

	// And it keeps up with a second change, so the first re-read was not a
	// one-off.
	third, err := Mint("email")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	writeToken(t, path, third)
	clock.advance(DefaultRefreshInterval)
	if got, err := source.Token(context.Background()); err != nil || got != third {
		t.Errorf("the source did not follow a second change (got the third token: %v, err=%v)", got == third, err)
	}
}

// TestTokenFromFileRereadsOnTheWallClock runs the same property on time.Now,
// so the behaviour is proven on the code path a consumer actually gets rather
// than only through the test seam.
func TestTokenFromFileRereadsOnTheWallClock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	before, err := Mint("email")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	after, err := Mint("email")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	writeToken(t, path, before)

	const interval = 20 * time.Millisecond
	source := TokenFromFile(path, WithRefreshInterval(interval))
	if got, err := source.Token(context.Background()); err != nil || got != before {
		t.Fatalf("the first read: got the expected token=%v, err=%v", got == before, err)
	}

	writeToken(t, path, after)
	deadline := time.Now().Add(5 * time.Second)
	for {
		got, err := source.Token(context.Background())
		if err != nil {
			t.Fatalf("re-reading: %v", err)
		}
		if got == after {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the old token was still served %s after the file changed, with a %s refresh interval", 5*time.Second, interval)
		}
		time.Sleep(interval / 2)
	}
}

// TestTokenFromFileFollowsAProjectedSecretSwap reproduces how the file
// actually changes on the platform. A kubelet-projected Secret is not
// rewritten in place: a new timestamped directory is created and the `..data`
// symlink is swapped atomically, so the token's path is a symlink to a symlink
// and its inode and mtime are not what changed.
//
// A change-detection scheme built on stat alone can pass the tests above and
// still miss this. Re-reading through the path does not.
func TestTokenFromFileFollowsAProjectedSecretSwap(t *testing.T) {
	dir := t.TempDir()
	before, err := Mint("email")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	after, err := Mint("email")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	project := func(name, token string) {
		t.Helper()
		version := filepath.Join(dir, name)
		if err := os.Mkdir(version, 0o700); err != nil {
			t.Fatalf("creating %s: %v", version, err)
		}
		writeToken(t, filepath.Join(version, "token"), token)
	}
	project("..2026_09_02_12_00_00", before)
	project("..2026_09_02_12_05_00", after)

	if err := os.Symlink("..2026_09_02_12_00_00", filepath.Join(dir, "..data")); err != nil {
		t.Fatalf("linking ..data: %v", err)
	}
	if err := os.Symlink(filepath.Join("..data", "token"), filepath.Join(dir, "token")); err != nil {
		t.Fatalf("linking token: %v", err)
	}

	clock := newTestClock()
	source := TokenFromFile(filepath.Join(dir, "token"), withClock(clock.Now))
	if got, err := source.Token(context.Background()); err != nil || got != before {
		t.Fatalf("the first read: got the expected token=%v, err=%v", got == before, err)
	}

	// The atomic swap kubelet performs: a temporary link, then a rename over
	// the live one.
	tmp := filepath.Join(dir, "..data_tmp")
	if err := os.Symlink("..2026_09_02_12_05_00", tmp); err != nil {
		t.Fatalf("linking ..data_tmp: %v", err)
	}
	if err := os.Rename(tmp, filepath.Join(dir, "..data")); err != nil {
		t.Fatalf("swapping ..data: %v", err)
	}

	clock.advance(DefaultRefreshInterval)
	got, err := source.Token(context.Background())
	if err != nil {
		t.Fatalf("reading after the projection swap: %v", err)
	}
	if got != after {
		t.Fatal("the source did not follow a projected-Secret swap")
	}
}

// TestTokenFromFileNeverServesAStaleTokenAfterAFailedRead: a value read before
// the file was deleted is not evidence that the caller may still use it. A
// silent fallback here would turn a visible, self-clearing failure into an
// invisible one.
func TestTokenFromFileNeverServesAStaleTokenAfterAFailedRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	minted, err := Mint("email")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	writeToken(t, path, minted)

	clock := newTestClock()
	source := TokenFromFile(path, withClock(clock.Now))
	if _, err := source.Token(context.Background()); err != nil {
		t.Fatalf("the first read: %v", err)
	}

	if err := os.Remove(path); err != nil {
		t.Fatalf("removing the token file: %v", err)
	}
	clock.advance(DefaultRefreshInterval)

	got, err := source.Token(context.Background())
	if err == nil {
		t.Fatal("a missing token file was not reported")
	}
	if got != "" {
		t.Error("a token was returned alongside an error")
	}
	if strings.Contains(err.Error(), minted) {
		t.Error("the error carries the token")
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("the error does not name the file it could not read: %v", err)
	}

	// And the failure does not stick: the next call after the file returns
	// serves the new content.
	replacement, err := Mint("email")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	writeToken(t, path, replacement)
	if got, err := source.Token(context.Background()); err != nil || got != replacement {
		t.Errorf("the source did not recover after the file came back (err=%v)", err)
	}
}

func TestTokenFromFileRejectsContentThatIsNotAToken(t *testing.T) {
	dir := t.TempDir()
	minted, err := Mint("email")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	for name, content := range map[string]string{
		"empty":               "",
		"whitespace only":     "  \n\t ",
		"two lines":           minted + "\n" + minted,
		"an embedded newline": minted[:10] + "\n" + minted[10:],
		"an embedded space":   minted[:10] + " " + minted[10:],
		"a header injection":  minted + "\r\nx-sphyrix-admin: true",
		"an embedded NUL":     minted[:10] + "\x00" + minted[10:],
		// A literal length, not one derived from the constant: deriving it
		// would let the bound be raised to anything at all without the test
		// noticing.
		"absurdly long": strings.Repeat("a", 513),
	} {
		path := filepath.Join(dir, "token")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("writing: %v", err)
		}
		got, err := TokenFromFile(path).Token(context.Background())
		if err == nil {
			t.Errorf("%s: accepted; want an error", name)
		}
		if got != "" {
			t.Errorf("%s: returned a token alongside an error", name)
		}
		if err != nil && strings.Contains(err.Error(), content) && content != "" {
			t.Errorf("%s: the error quotes the file's content", name)
		}
	}

	// Surrounding whitespace, on the other hand, is trimmed: whether a
	// delivered secret ends in a newline is not the consumer's problem.
	path := filepath.Join(dir, "token")
	if err := os.WriteFile(path, []byte("\n  "+minted+"  \n"), 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}
	if got, err := TokenFromFile(path).Token(context.Background()); err != nil || got != minted {
		t.Errorf("a padded token was not trimmed (err=%v)", err)
	}
}

func TestTokenFromFileHonoursContextCancellation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	minted, err := Mint("email")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	writeToken(t, path, minted)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := TokenFromFile(path).Token(ctx); err == nil {
		t.Error("a cancelled context still produced a token")
	}
}

// TestTokenFromFileIsSafeForConcurrentUse exercises the shared-source path
// every request of a client takes.
//
// Be clear about what it proves: without `-race` it only shows the source does
// not crash or corrupt its answer under load — removing the mutex leaves it
// green. It is the RACE DETECTOR that turns it into an assertion, and the
// devtools container runs with CGO_ENABLED=0, where `-race` is unavailable. So
// CI does not check this property; `go test -race ./...` on a cgo-enabled host
// does, and that is where a change to the locking must be run.
func TestTokenFromFileIsSafeForConcurrentUse(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	minted, err := Mint("email")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	writeToken(t, path, minted)

	source := TokenFromFile(path, WithRefreshInterval(time.Millisecond))
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 32 {
				if _, err := source.Token(context.Background()); err != nil {
					t.Errorf("Token: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()

	if got := source.Path(); got != path {
		t.Errorf("Path() = %q, want %q", got, path)
	}
}

// captureAuthorization stands up a plain HTTP server that records the
// Authorization header of every request and answers 404, which is enough to
// see what the client interceptor put on the wire.
func captureAuthorization(t *testing.T) (*httptest.Server, func() []string) {
	t.Helper()
	var (
		mu   sync.Mutex
		seen []string
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Get("Authorization"))
		mu.Unlock()
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(server.Close)
	return server, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), seen...)
	}
}

func TestClientInterceptorAttachesTheBearerToken(t *testing.T) {
	server, headers := captureAuthorization(t)
	minted, err := Mint("email")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	client := hellov1connect.NewHelloServiceClient(server.Client(), server.URL,
		connect.WithInterceptors(NewClientInterceptor(StaticToken(minted))))
	//nolint:errcheck // the server answers 404 on purpose; the header is what matters.
	_, _ = client.SayHello(context.Background(), connect.NewRequest(&hellov1.SayHelloRequest{Name: "sphyrix"}))

	got := headers()
	if len(got) != 1 {
		t.Fatalf("the server saw %d requests, want 1", len(got))
	}
	if want := "Bearer " + minted; got[0] != want {
		t.Errorf("the request carried %q, want the minted token as a bearer", got[0])
	}
}

func TestClientInterceptorOverwritesWhateverTheCallerSet(t *testing.T) {
	server, headers := captureAuthorization(t)
	minted, err := Mint("email")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	client := hellov1connect.NewHelloServiceClient(server.Client(), server.URL,
		connect.WithInterceptors(NewClientInterceptor(StaticToken(minted))))
	req := connect.NewRequest(&hellov1.SayHelloRequest{Name: "sphyrix"})
	req.Header().Set("Authorization", "Bearer somebody-elses-token")
	//nolint:errcheck // as above.
	_, _ = client.SayHello(context.Background(), req)

	got := headers()
	if len(got) != 1 {
		t.Fatalf("the server saw %d requests, want 1", len(got))
	}
	if got[0] != "Bearer "+minted {
		t.Errorf("the interceptor did not replace the caller's header: %q", got[0])
	}
	if strings.Contains(got[0], "somebody-elses-token") {
		t.Error("the caller's header survived")
	}
}

func TestClientInterceptorRefusesToSendAnUnusableToken(t *testing.T) {
	server, headers := captureAuthorization(t)

	for name, source := range map[string]TokenSource{
		"a failing source": TokenSourceFunc(func(context.Context) (string, error) {
			return "", os.ErrNotExist
		}),
		"an empty token": TokenSourceFunc(func(context.Context) (string, error) {
			return "", nil
		}),
		"a token with a newline": TokenSourceFunc(func(context.Context) (string, error) {
			return "sphx_email_x\r\nx-sphyrix-admin: true", nil
		}),
		"a token with a space": TokenSourceFunc(func(context.Context) (string, error) {
			return "sphx_email_x y", nil
		}),
	} {
		client := hellov1connect.NewHelloServiceClient(server.Client(), server.URL,
			connect.WithInterceptors(NewClientInterceptor(source)))
		_, err := client.SayHello(context.Background(), connect.NewRequest(&hellov1.SayHelloRequest{Name: "sphyrix"}))
		if err == nil {
			t.Errorf("%s: the request was sent anyway", name)
			continue
		}
		if got := connect.CodeOf(err); got != connect.CodeUnauthenticated {
			t.Errorf("%s: got %v, want %v", name, got, connect.CodeUnauthenticated)
		}
	}

	if got := headers(); len(got) != 0 {
		t.Errorf("%d requests reached the server with an unusable token: %q", len(got), got)
	}
}

func TestNewClientInterceptorRefusesANilSource(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("NewClientInterceptor(nil) did not panic")
		}
	}()
	NewClientInterceptor(nil)
}

// TestTheTokenLengthBoundIsWhatItSays pins the bound itself. A token is about
// 55 characters; 512 is headroom, and a bound that could be silently raised to
// anything would not be a bound.
func TestTheTokenLengthBoundIsWhatItSays(t *testing.T) {
	if maxTokenLen != 512 {
		t.Errorf("maxTokenLen is %d, want 512", maxTokenLen)
	}
	if _, err := StaticToken(strings.Repeat("a", 512)).Token(context.Background()); err != nil {
		t.Errorf("a 512-character token was refused: %v", err)
	}
	if _, err := StaticToken(strings.Repeat("a", 513)).Token(context.Background()); err == nil {
		t.Error("a 513-character token was accepted")
	}
}

func TestStaticTokenRefusesAnUnusableValue(t *testing.T) {
	if got, err := StaticToken("sphx_email_ok").Token(context.Background()); err != nil || got != "sphx_email_ok" {
		t.Errorf("a usable token was rejected: %q, %v", got, err)
	}
	for _, value := range []string{"", "  ", "a\nb", strings.Repeat("a", 513)} {
		if _, err := StaticToken(value).Token(context.Background()); err == nil {
			t.Errorf("StaticToken(%q) was accepted", value)
		}
	}
}

// TestTheTwoHalvesAgree wires design 001 §10's example end to end: a client
// reading its token from a mounted file, a server verifying it by hash — and
// then the token is re-minted under both of them, exactly as a dev/test `up`
// does. The call must start failing and then recover on its own, with no
// restart.
func TestTheTwoHalvesAgree(t *testing.T) {
	h := newHarness(t, &helloHandler{resourceOrg: "becoming-the-hunter"})

	path := filepath.Join(t.TempDir(), "token")
	first, err := Mint("email")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	writeToken(t, path, first)
	h.store.hold(first, "becoming-the-hunter")

	clock := newTestClock()
	source := TokenFromFile(path, withClock(clock.Now))
	client := hellov1connect.NewHelloServiceClient(h.server.Client(), h.server.URL,
		connect.WithInterceptors(NewClientInterceptor(source)))

	call := func() (string, error) {
		res, err := client.SayHello(context.Background(), connect.NewRequest(&hellov1.SayHelloRequest{Name: "sphyrix"}))
		if err != nil {
			return "", err
		}
		return res.Msg.GetMessage(), nil
	}

	org, err := call()
	if err != nil {
		t.Fatalf("the first call: %v", err)
	}
	if org != "becoming-the-hunter" {
		t.Fatalf("the handler saw org %q", org)
	}

	// The environment comes back up: a new token in Vault, a new hash in the
	// store, the old one gone, and the mounted file replaced.
	second, err := Mint("email")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	h.store.mu.Lock()
	h.store.orgs = map[string]Identity{Hash(second): {Org: "becoming-the-hunter", TokenVersion: 1}}
	h.store.mu.Unlock()

	// Before the file is replaced the client is presenting a revoked token —
	// ADR 027 Decision 5's bounded UNAUTHENTICATED window.
	if _, err := call(); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("a revoked token was not refused: %v", connect.CodeOf(err))
	}

	writeToken(t, path, second)
	clock.advance(DefaultRefreshInterval)

	org, err = call()
	if err != nil {
		t.Fatalf("the client did not recover after the token was re-minted: %v", err)
	}
	if org != "becoming-the-hunter" {
		t.Errorf("the handler saw org %q after recovery", org)
	}
}
