package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"connectrpc.com/connect"

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
// inbound control, so wrapping a streaming CLIENT must be the identity.
func TestTheServerInterceptorLeavesOutboundStreamsAlone(t *testing.T) {
	interceptor, err := NewInterceptor("email", newRecordingStore())
	if err != nil {
		t.Fatalf("NewInterceptor: %v", err)
	}
	var called bool
	next := connect.StreamingClientFunc(func(context.Context, connect.Spec) connect.StreamingClientConn {
		called = true
		return newFakeClientConn()
	})
	interceptor.WrapStreamingClient(next)(context.Background(), connect.Spec{})
	if !called {
		t.Error("the server interceptor swallowed an outbound stream")
	}
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
	if err := wrapped(context.Background(), newFakeHandlerConn("/hello.v1.HelloService/SayHello")); err != nil {
		t.Fatalf("the client interceptor refused an inbound stream: %v", err)
	}
	if !ran {
		t.Error("the client interceptor swallowed an inbound stream")
	}
}
