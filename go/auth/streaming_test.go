package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"connectrpc.com/connect"

	hellov1 "github.com/sphyrix/contracts/gen/go/hello/v1"
	"github.com/sphyrix/contracts/gen/go/hello/v1/hellov1connect"
)

// The streaming halves of both interceptors are reached only by a streaming
// RPC, and no package in this module declares one yet. Driving them through a
// hand-rolled connection is therefore the only way to assert them at all —
// and they are security controls, so "no streaming RPC exists yet" is not a
// reason to ship them unasserted. A handler wrapper that quietly returned
// `next` would serve every future streaming procedure unauthenticated.

// fakeHandlerConn is a connect.StreamingHandlerConn carrying nothing but a
// procedure and request headers.
type fakeHandlerConn struct {
	procedure string
	header    http.Header
}

func newFakeHandlerConn(procedure string) *fakeHandlerConn {
	return &fakeHandlerConn{procedure: procedure, header: http.Header{}}
}

func (c *fakeHandlerConn) Spec() connect.Spec {
	return connect.Spec{Procedure: c.procedure, StreamType: connect.StreamTypeBidi}
}
func (c *fakeHandlerConn) Peer() connect.Peer           { return connect.Peer{} }
func (c *fakeHandlerConn) Receive(any) error            { return nil }
func (c *fakeHandlerConn) RequestHeader() http.Header   { return c.header }
func (c *fakeHandlerConn) Send(any) error               { return nil }
func (c *fakeHandlerConn) ResponseHeader() http.Header  { return http.Header{} }
func (c *fakeHandlerConn) ResponseTrailer() http.Header { return http.Header{} }

var _ connect.StreamingHandlerConn = (*fakeHandlerConn)(nil)

// TestTheStreamingHandlerIsAuthenticatedToo asserts what the package doc
// claims: the same check, applied once when the stream opens, so an
// unauthenticated caller cannot open one.
func TestTheStreamingHandlerIsAuthenticatedToo(t *testing.T) {
	store := newRecordingStore()
	valid, err := Mint("email")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	store.hold(valid, "becoming-the-hunter")
	unknown, err := Mint("email")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	interceptor, err := NewInterceptor("email", store)
	if err != nil {
		t.Fatalf("NewInterceptor: %v", err)
	}

	// next records whether the handler ran and what identity it saw.
	var (
		ran  bool
		seen Identity
	)
	wrapped := interceptor.WrapStreamingHandler(func(ctx context.Context, _ connect.StreamingHandlerConn) error {
		ran = true
		seen, _ = FromContext(ctx)
		return nil
	})

	for name, authorization := range map[string]string{
		"absent":           "",
		"the wrong scheme": "Basic " + valid,
		"malformed":        "Bearer not-a-token",
		"another service":  "Bearer sphx_billing_" + strings.TrimPrefix(valid, "sphx_email_"),
		"unknown to us":    "Bearer " + unknown,
	} {
		ran, seen = false, Identity{}
		conn := newFakeHandlerConn(hellov1connect.HelloServiceSayHelloProcedure)
		if authorization != "" {
			conn.header.Set("Authorization", authorization)
		}
		err := wrapped(context.Background(), conn)
		if err == nil {
			t.Errorf("%s: the stream opened; want UNAUTHENTICATED", name)
		} else if got := connect.CodeOf(err); got != connect.CodeUnauthenticated {
			t.Errorf("%s: got %v, want %v", name, got, connect.CodeUnauthenticated)
		}
		if ran {
			t.Errorf("%s: the handler ran behind a refused stream", name)
		}
	}

	// The control: a valid token opens the stream and the handler sees the org.
	ran, seen = false, Identity{}
	conn := newFakeHandlerConn(hellov1connect.HelloServiceSayHelloProcedure)
	conn.header.Set("Authorization", "Bearer "+valid)
	if err := wrapped(context.Background(), conn); err != nil {
		t.Fatalf("a valid token was refused: %v", err)
	}
	if !ran {
		t.Fatal("the handler did not run for a valid token")
	}
	if seen.Org != "becoming-the-hunter" {
		t.Errorf("the handler saw org %q, want becoming-the-hunter", seen.Org)
	}

	// And the store saw only hashes here too.
	for _, argument := range store.arguments() {
		if len(argument) != HashHexLen || strings.Contains(argument, Prefix) {
			t.Errorf("the streaming path handed the store %q, want a hash", argument)
		}
	}
}

func TestTheStreamingHandlerHonoursExemptProcedures(t *testing.T) {
	interceptor, err := NewInterceptor("email", newRecordingStore(),
		WithExemptProcedures(hellov1connect.HelloServiceSayHelloProcedure))
	if err != nil {
		t.Fatalf("NewInterceptor: %v", err)
	}
	var ran bool
	wrapped := interceptor.WrapStreamingHandler(func(context.Context, connect.StreamingHandlerConn) error {
		ran = true
		return nil
	})
	if err := wrapped(context.Background(), newFakeHandlerConn(hellov1connect.HelloServiceSayHelloProcedure)); err != nil {
		t.Fatalf("an exempt streaming procedure was refused: %v", err)
	}
	if !ran {
		t.Error("the handler did not run for an exempt procedure")
	}
}

// TestTheServerInterceptorLeavesOutboundStreamsAlone: the server half is an
// inbound control, so wrapping a streaming CLIENT must be the IDENTITY — the
// same connection back, untouched.
//
// "next was called" is not that property: a wrapper that returned a decorated
// connection, or stamped a header of its own on the way past, would satisfy it.
// So this asserts the connection's identity and that nothing was written to it.
func TestTheServerInterceptorLeavesOutboundStreamsAlone(t *testing.T) {
	store := newRecordingStore()
	interceptor, err := NewInterceptor("email", store)
	if err != nil {
		t.Fatalf("NewInterceptor: %v", err)
	}

	underlying := newFakeClientConn()
	underlying.header.Set("X-Sentinel", "untouched")
	var called bool
	next := connect.StreamingClientFunc(func(context.Context, connect.Spec) connect.StreamingClientConn {
		called = true
		return underlying
	})

	got := interceptor.WrapStreamingClient(next)(context.Background(), connect.Spec{})
	if !called {
		t.Fatal("the server interceptor swallowed an outbound stream")
	}
	if got != connect.StreamingClientConn(underlying) {
		t.Error("the server interceptor decorated an outbound stream; it must hand back the same connection")
	}
	if v := underlying.header.Get(authorizationHeader); v != "" {
		t.Errorf("the server interceptor wrote %q to an outbound stream's Authorization header", v)
	}
	if v := underlying.header.Get("X-Sentinel"); v != "untouched" {
		t.Errorf("the server interceptor rewrote an outbound stream's headers (sentinel is now %q)", v)
	}
	if len(store.arguments()) != 0 {
		t.Error("the server interceptor consulted the token store for an OUTBOUND stream")
	}
}

// TestTheServerInterceptorLeavesOutboundUnaryCallsAlone is the same property
// for the unary path: the `IsClient` guard, which nothing else exercises.
func TestTheServerInterceptorLeavesOutboundUnaryCallsAlone(t *testing.T) {
	server, headers := captureAuthorization(t)
	store := newRecordingStore()
	interceptor, err := NewInterceptor("email", store)
	if err != nil {
		t.Fatalf("NewInterceptor: %v", err)
	}

	// The SERVER interceptor, installed on a client by mistake. It must be
	// inert rather than refusing the caller's own outbound request.
	client := hellov1connect.NewHelloServiceClient(server.Client(), server.URL,
		connect.WithInterceptors(interceptor))
	_, err = client.SayHello(context.Background(), connect.NewRequest(&hellov1.SayHelloRequest{Name: "sphyrix"}))
	if connect.CodeOf(err) == connect.CodeUnauthenticated {
		t.Error("the server interceptor authenticated an OUTBOUND unary call and refused it")
	}
	if got := headers(); len(got) != 1 {
		t.Fatalf("the server saw %d requests, want 1", len(got))
	} else if got[0] != "" {
		t.Errorf("the server interceptor attached %q to an outbound request", got[0])
	}
	if len(store.arguments()) != 0 {
		t.Error("the server interceptor consulted the token store for an OUTBOUND unary call")
	}
}

// TestTheClientInterceptorLeavesInboundUnaryCallsAlone is the mirror: the
// client half installed on a handler must not touch the inbound request.
func TestTheClientInterceptorLeavesInboundUnaryCallsAlone(t *testing.T) {
	minted, err := Mint("email")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	// A handler wrapped in the CLIENT interceptor: it must run, and must not
	// have had an Authorization header stamped on its inbound request.
	mux := http.NewServeMux()
	var seen string
	mux.Handle(hellov1connect.NewHelloServiceHandler(
		connectHandlerFunc(func(ctx context.Context, req *connect.Request[hellov1.SayHelloRequest]) (*connect.Response[hellov1.SayHelloResponse], error) {
			seen = req.Header().Get(authorizationHeader)
			return connect.NewResponse(&hellov1.SayHelloResponse{Message: "ok"}), nil
		}),
		connect.WithInterceptors(NewClientInterceptor(StaticToken(minted)))))
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	res, err := hellov1connect.NewHelloServiceClient(server.Client(), server.URL).
		SayHello(context.Background(), connect.NewRequest(&hellov1.SayHelloRequest{Name: "sphyrix"}))
	if err != nil {
		t.Fatalf("the client interceptor refused an inbound unary call: %v", err)
	}
	if res.Msg.GetMessage() != "ok" {
		t.Errorf("the handler answered %q", res.Msg.GetMessage())
	}
	if seen != "" {
		t.Errorf("the client interceptor stamped %q on an INBOUND request", seen)
	}
}

// connectHandlerFunc adapts a function to hellov1connect.HelloServiceHandler.
type connectHandlerFunc func(context.Context, *connect.Request[hellov1.SayHelloRequest]) (*connect.Response[hellov1.SayHelloResponse], error)

func (f connectHandlerFunc) SayHello(ctx context.Context, req *connect.Request[hellov1.SayHelloRequest]) (*connect.Response[hellov1.SayHelloResponse], error) {
	return f(ctx, req)
}

// fakeClientConn is a connect.StreamingClientConn that records the request
// headers it was given and whether each half was closed.
type fakeClientConn struct {
	header         http.Header
	closedRequest  bool
	closedResponse bool
}

func newFakeClientConn() *fakeClientConn {
	return &fakeClientConn{header: http.Header{}}
}

func (c *fakeClientConn) Spec() connect.Spec           { return connect.Spec{StreamType: connect.StreamTypeBidi} }
func (c *fakeClientConn) Peer() connect.Peer           { return connect.Peer{} }
func (c *fakeClientConn) Send(any) error               { return nil }
func (c *fakeClientConn) RequestHeader() http.Header   { return c.header }
func (c *fakeClientConn) CloseRequest() error          { c.closedRequest = true; return nil }
func (c *fakeClientConn) Receive(any) error            { return nil }
func (c *fakeClientConn) ResponseHeader() http.Header  { return http.Header{} }
func (c *fakeClientConn) ResponseTrailer() http.Header { return http.Header{} }
func (c *fakeClientConn) CloseResponse() error         { c.closedResponse = true; return nil }

var _ connect.StreamingClientConn = (*fakeClientConn)(nil)

func TestTheClientInterceptorAuthenticatesStreamsToo(t *testing.T) {
	minted, err := Mint("email")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	underlying := newFakeClientConn()
	conn := NewClientInterceptor(StaticToken(minted)).
		WrapStreamingClient(func(context.Context, connect.Spec) connect.StreamingClientConn {
			return underlying
		})(context.Background(), connect.Spec{})

	if got, want := underlying.header.Get("Authorization"), "Bearer "+minted; got != want {
		t.Errorf("the stream carried %q, want the token as a bearer", got)
	}
	if err := conn.Send(nil); err != nil {
		t.Errorf("an authenticated stream refused to send: %v", err)
	}
}

// TestAStreamWithNoTokenIsRefusedAndClosed: the underlying call is already
// open by the time the token is found to be missing, so it must be reported
// AND released — not left dangling for the life of the process.
func TestAStreamWithNoTokenIsRefusedAndClosed(t *testing.T) {
	underlying := newFakeClientConn()
	source := TokenSourceFunc(func(context.Context) (string, error) {
		return "", errors.New("the token file is not there")
	})

	conn := NewClientInterceptor(source).
		WrapStreamingClient(func(context.Context, connect.Spec) connect.StreamingClientConn {
			return underlying
		})(context.Background(), connect.Spec{})

	if got := underlying.header.Get("Authorization"); got != "" {
		t.Errorf("a stream with no token still carried %q", got)
	}
	for name, call := range map[string]func() error{
		"Send":          func() error { return conn.Send(nil) },
		"Receive":       func() error { return conn.Receive(nil) },
		"CloseRequest":  conn.CloseRequest,
		"CloseResponse": conn.CloseResponse,
	} {
		if err := call(); err == nil {
			t.Errorf("%s on an unauthenticated stream succeeded", name)
		} else if got := connect.CodeOf(err); got != connect.CodeUnauthenticated {
			t.Errorf("%s: got %v, want %v", name, got, connect.CodeUnauthenticated)
		}
	}
	if !underlying.closedRequest || !underlying.closedResponse {
		t.Error("closing the refused stream did not close the call underneath it — the duplex call leaks")
	}
}

// TestTheClientInterceptorLeavesInboundStreamsAlone: the client half is an
// outbound control, so wrapping a streaming HANDLER must be the identity.
func TestTheClientInterceptorLeavesInboundStreamsAlone(t *testing.T) {
	minted, err := Mint("email")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	var ran bool
	wrapped := NewClientInterceptor(StaticToken(minted)).
		WrapStreamingHandler(func(context.Context, connect.StreamingHandlerConn) error {
			ran = true
			return nil
		})
	conn := newFakeHandlerConn("/hello.v1.HelloService/SayHello")
	conn.header.Set("X-Sentinel", "untouched")
	if err := wrapped(context.Background(), conn); err != nil {
		t.Fatalf("the client interceptor refused an inbound stream: %v", err)
	}
	if !ran {
		t.Error("the client interceptor swallowed an inbound stream")
	}
	if v := conn.header.Get(authorizationHeader); v != "" {
		t.Errorf("the client interceptor stamped %q on an INBOUND stream", v)
	}
	if v := conn.header.Get("X-Sentinel"); v != "untouched" {
		t.Errorf("the client interceptor rewrote an inbound stream's headers (sentinel is now %q)", v)
	}
}
