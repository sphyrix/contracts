package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
)

// DefaultRefreshInterval is how often [TokenFromFile] re-reads its file: the
// upper bound on how long a caller keeps using a token that has been replaced.
//
// It is deliberately far below the delivery latency it sits behind. ADR 027
// Decision 5 renders `VaultStaticSecret`s for token paths with
// `refreshAfter: 1m`, and kubelet projection adds its own delay on top; a
// consumer-side cache measured in seconds therefore contributes nothing
// noticeable to the propagation window, while costing one read of a ~60-byte
// file every few seconds.
const DefaultRefreshInterval = 5 * time.Second

// maxTokenLen bounds what any [TokenSource] may return. A token is about 55
// characters; this is headroom, not a format check.
const maxTokenLen = 512

// TokenSource yields the bearer token to present. Implementations must be safe
// for concurrent use: one source is shared by every request a client makes.
type TokenSource interface {
	// Token returns the token to present, or an error. The error must not
	// contain the token.
	Token(ctx context.Context) (string, error)
}

// TokenSourceFunc adapts a function to [TokenSource].
type TokenSourceFunc func(ctx context.Context) (string, error)

// Token implements [TokenSource].
func (f TokenSourceFunc) Token(ctx context.Context) (string, error) { return f(ctx) }

// StaticToken is a [TokenSource] that always yields the same token.
//
// It is for OFF-PLATFORM callers, which receive their token once into a CI
// secret store and read it from the environment at start-up (ADR 019). Do not
// use it on the platform: a mounted token is re-minted on every dev/test `up`
// (design 001 §13), and a process holding a static copy of it never notices —
// [TokenFromFile] is the on-platform source.
func StaticToken(token string) TokenSource {
	return TokenSourceFunc(func(context.Context) (string, error) {
		if !usableAsHeaderValue(token) {
			return "", errors.New("auth: the configured token is empty or contains characters that cannot be sent in a header")
		}
		return token, nil
	})
}

// FileTokenSource reads a token from a file and RE-READS IT ON CHANGE, within
// [DefaultRefreshInterval] (or whatever [WithRefreshInterval] sets).
//
// Re-reading is the whole point. The mounted file is a `VaultStaticSecret`
// projection whose contents are replaced when the token is re-minted — on
// every dev/test `up` and after a Postgres-only prod restore (design 001 §10,
// §13). A consumer that read the file once at start-up would authenticate
// until the next cycle and then fail every request until somebody restarted
// it.
type FileTokenSource struct {
	path     string
	interval time.Duration
	now      func() time.Time

	mu     sync.Mutex
	token  string
	readAt time.Time
}

var _ TokenSource = (*FileTokenSource)(nil)

// FileOption configures a [FileTokenSource].
type FileOption func(*fileOptions)

type fileOptions struct {
	interval time.Duration
	now      func() time.Time
}

// WithRefreshInterval bounds how long a token read from the file may be
// reused before the file is read again. Default [DefaultRefreshInterval]; a
// non-positive value re-reads on every call.
func WithRefreshInterval(interval time.Duration) FileOption {
	return func(o *fileOptions) { o.interval = interval }
}

// withClock is the test seam for the refresh interval, so a test can prove
// change detection without sleeping through it.
func withClock(now func() time.Time) FileOption {
	return func(o *fileOptions) { o.now = now }
}

// TokenFromFile returns a [TokenSource] reading path — for an on-platform
// consumer, the mount ADR 027 Decision 5 renders:
// `/var/run/sphyrix/<org>/platform/<service>/token`.
//
// Nothing is read until the first [FileTokenSource.Token] call, so this cannot
// fail and a client may be constructed before its token has been projected.
// Surrounding whitespace is trimmed, because whether a delivered secret ends
// in a newline is not something a consumer should have to know.
func TokenFromFile(path string, opts ...FileOption) *FileTokenSource {
	cfg := fileOptions{interval: DefaultRefreshInterval}
	for _, opt := range opts {
		opt(&cfg)
	}
	if cfg.now == nil {
		cfg.now = time.Now
	}
	return &FileTokenSource{path: path, interval: cfg.interval, now: cfg.now}
}

// Token implements [TokenSource].
//
// A read that fails is returned as an error and DROPS the cached token: a
// value read before the file was deleted or emptied is not evidence that the
// caller may still use it. ADR 027 Decision 5 already accepts a bounded window
// of failures while a re-minted token propagates; serving a stale token past
// that window would turn a visible, self-clearing failure into an invisible
// one.
func (s *FileTokenSource) Token(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	if s.token != "" && s.interval > 0 && now.Sub(s.readAt) < s.interval {
		return s.token, nil
	}

	data, err := os.ReadFile(s.path)
	if err != nil {
		s.forget()
		return "", fmt.Errorf("auth: reading the token file %s: %w", s.path, err)
	}
	token := strings.TrimSpace(string(data))
	if !usableAsHeaderValue(token) {
		s.forget()
		// The file's CONTENT is never quoted, here or in any other error: it
		// is the secret.
		return "", fmt.Errorf("auth: the token file %s is empty or does not hold a single-line token", s.path)
	}

	s.token, s.readAt = token, now
	return token, nil
}

// Path returns the file this source reads, for a caller assembling a start-up
// log line. It is a path, not a secret.
func (s *FileTokenSource) Path() string { return s.path }

// forget must be called with s.mu held.
func (s *FileTokenSource) forget() {
	s.token, s.readAt = "", time.Time{}
}

// ClientInterceptor attaches `authorization: Bearer <token>` to every outbound
// request (ADR 027 Decision 6). It is the caller's half of this package;
// [Interceptor] is the server's.
type ClientInterceptor struct {
	source TokenSource
}

var _ connect.Interceptor = (*ClientInterceptor)(nil)

// NewClientInterceptor returns the interceptor a caller adds to its generated
// client:
//
//	client := emailv1connect.NewEmailServiceClient(http.DefaultClient,
//	    "https://email.dev.sphyrix.cloud",
//	    connect.WithInterceptors(auth.NewClientInterceptor(
//	        auth.TokenFromFile("/var/run/sphyrix/becoming-the-hunter/platform/email/token"))))
//
// It panics on a nil source: a client with nothing to authenticate with is a
// wiring mistake, and it is better found at start-up than as an
// `UNAUTHENTICATED` in production.
func NewClientInterceptor(source TokenSource) *ClientInterceptor {
	if source == nil {
		panic("auth: NewClientInterceptor needs a TokenSource")
	}
	return &ClientInterceptor{source: source}
}

// WrapUnary implements connect.Interceptor.
func (c *ClientInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		if !req.Spec().IsClient {
			return next(ctx, req)
		}
		if err := c.attach(ctx, req.Header()); err != nil {
			return nil, err
		}
		return next(ctx, req)
	}
}

// WrapStreamingClient implements connect.Interceptor: the token is attached
// once, when the stream is opened.
func (c *ClientInterceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return func(ctx context.Context, spec connect.Spec) connect.StreamingClientConn {
		conn := next(ctx, spec)
		if err := c.attach(ctx, conn.RequestHeader()); err != nil {
			return &failedStreamingClientConn{StreamingClientConn: conn, err: err}
		}
		return conn
	}
}

// WrapStreamingHandler implements connect.Interceptor. Inbound calls are not
// this interceptor's business.
func (c *ClientInterceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return next
}

// attach sets — never adds — the header, so the token this client is
// configured with is what goes on the wire regardless of what a caller put
// there.
func (c *ClientInterceptor) attach(ctx context.Context, header http.Header) error {
	token, err := c.source.Token(ctx)
	if err != nil {
		return connect.NewError(connect.CodeUnauthenticated,
			fmt.Errorf("auth: no token to attach to the request: %w", err))
	}
	if !usableAsHeaderValue(token) {
		// A custom [TokenSource] handed back something with a newline, a
		// space or a control character in it. Sending it would at best be
		// rejected and at worst splice a header of the caller's choosing into
		// the request.
		return connect.NewError(connect.CodeUnauthenticated,
			errors.New("auth: the TokenSource returned a value that cannot be sent in a header"))
	}
	header.Set(authorizationHeader, bearerPrefix+token)
	return nil
}

// failedStreamingClientConn reports a token that could not be attached on the
// stream's first use. connect's streaming client interceptor cannot return an
// error at wrap time, and returning the unauthenticated connection unchanged
// would send the stream without credentials.
type failedStreamingClientConn struct {
	connect.StreamingClientConn
	err error
}

func (c *failedStreamingClientConn) Send(any) error       { return c.err }
func (c *failedStreamingClientConn) Receive(any) error    { return c.err }
func (c *failedStreamingClientConn) CloseRequest() error  { return c.err }
func (c *failedStreamingClientConn) CloseResponse() error { return c.err }

// usableAsHeaderValue accepts only visible ASCII with no spaces — which every
// token minted by [Mint] is, being base64url and underscores. It exists to
// keep a newline or a control character out of an HTTP header, whatever
// produced the value.
func usableAsHeaderValue(token string) bool {
	if token == "" || len(token) > maxTokenLen {
		return false
	}
	for i := 0; i < len(token); i++ {
		if token[i] < 0x21 || token[i] > 0x7e {
			return false
		}
	}
	return true
}
