package auth

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"connectrpc.com/connect"
)

const (
	authorizationHeader = "Authorization"
	bearerPrefix        = "Bearer "
)

// The errors a caller ever sees from this package. All four are contentless on
// purpose: ADR 027 Decision 6 gives one answer to every failed authentication,
// so an absent token, a malformed one, one minted for another service and one
// no org holds are indistinguishable to a prober. None of them carries the
// token, the hash, or anything read from the store.
//
// They are built per call rather than shared as package-level values because
// connect.Error.Meta() lazily allocates on its receiver: one shared value
// handed to concurrent requests would be a data race the moment any
// downstream interceptor annotated it, and whatever it was annotated with
// would then be attached to every later caller's error.
func errUnauthenticated() error {
	return connect.NewError(connect.CodeUnauthenticated, errors.New("unauthenticated"))
}

func errPermissionDenied() error {
	return connect.NewError(connect.CodePermissionDenied, errors.New("this org may not access that resource"))
}

func errUnavailable() error {
	return connect.NewError(connect.CodeUnavailable, errors.New("the caller's identity could not be checked"))
}

func errInternal() error {
	return connect.NewError(connect.CodeInternal, errors.New("the caller's identity could not be established"))
}

// Interceptor is ADR 027 Decision 6 and design 001 §9.4's auth middleware: the
// one place a sphyrix-hosted service sees an M2M token.
//
// Per request it reads `authorization: Bearer <token>`, refuses anything that
// is not shaped like one of this service's tokens without spending a lookup on
// it, hashes what is left with SHA-256 and looks the HASH up through a
// [TokenStore]. The org that comes back is put in the request context, where
// [FromContext] reads it and [AuthorizeOrg] checks it against what a handler
// is about to touch.
//
// It implements connect.Interceptor, so it covers unary and streaming handlers
// alike, over gRPC, gRPC-Web and Connect. As a client interceptor it does
// nothing: this is an inbound control ([NewClientInterceptor] is the outbound
// half).
type Interceptor struct {
	service string
	store   TokenStore
	exempt  func(procedure string) bool
	logger  *slog.Logger
}

var _ connect.Interceptor = (*Interceptor)(nil)

// Option configures an [Interceptor].
type Option func(*options)

type options struct {
	exempt func(procedure string) bool
	logger *slog.Logger
}

// WithExemptProcedures leaves the named procedures unauthenticated — health
// and reflection, typically. Use the generated `...Procedure` constants: a
// typo here is a silently public endpoint, and a constant cannot be mistyped.
// Repeated calls add to the set.
func WithExemptProcedures(procedures ...string) Option {
	return func(o *options) {
		exempt := make(map[string]struct{}, len(procedures))
		for _, procedure := range procedures {
			exempt[procedure] = struct{}{}
		}
		previous := o.exempt
		o.exempt = func(procedure string) bool {
			if previous != nil && previous(procedure) {
				return true
			}
			_, ok := exempt[procedure]
			return ok
		}
	}
}

// WithExempt leaves every procedure the predicate accepts unauthenticated.
// Prefer [WithExemptProcedures]; this is for prefix rules (a whole package,
// say), where a predicate that is one character too broad exempts more than
// it means to.
func WithExempt(predicate func(procedure string) bool) Option {
	return func(o *options) {
		previous := o.exempt
		o.exempt = func(procedure string) bool {
			return (previous != nil && previous(procedure)) || predicate(procedure)
		}
	}
}

// WithLogger records WHY a request was refused: at debug for anything the
// caller did, at warn or error for anything that is ours (an unreadable store,
// a store that answers wrongly). It never logs a token, a hash or the
// `authorization` header — neither does the rest of this package, and design
// 001 §9.4 requires the same of the gateway's access logs and of OTel's HTTP
// attributes.
func WithLogger(logger *slog.Logger) Option {
	return func(o *options) { o.logger = logger }
}

// NewInterceptor builds the server interceptor for the named service.
//
// service is this service's own name — the `<service>` segment its tokens
// carry, e.g. "email". A token minted for a different service is refused
// without a store lookup, so a token that leaked from one sphyrix service is
// not even presentable to another.
func NewInterceptor(service string, store TokenStore, opts ...Option) (*Interceptor, error) {
	if err := validateService(service); err != nil {
		return nil, err
	}
	if store == nil {
		return nil, errors.New("auth: a TokenStore is required")
	}

	var cfg options
	for _, opt := range opts {
		opt(&cfg)
	}
	if cfg.logger == nil {
		cfg.logger = slog.New(slog.DiscardHandler)
	}

	return &Interceptor{
		service: service,
		store:   store,
		exempt:  cfg.exempt,
		logger:  cfg.logger,
	}, nil
}

// WrapUnary implements connect.Interceptor.
func (i *Interceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		if req.Spec().IsClient {
			return next(ctx, req)
		}
		ctx, err := i.authenticate(ctx, req.Spec().Procedure, req.Header())
		if err != nil {
			return nil, err
		}
		return next(ctx, req)
	}
}

// WrapStreamingClient implements connect.Interceptor. Outbound calls are not
// this interceptor's business.
func (i *Interceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return next
}

// WrapStreamingHandler implements connect.Interceptor: the same check, applied
// once when the stream opens, so an unauthenticated caller cannot open one.
func (i *Interceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		ctx, err := i.authenticate(ctx, conn.Spec().Procedure, conn.RequestHeader())
		if err != nil {
			return err
		}
		return next(ctx, conn)
	}
}

// authenticate returns the context the handler runs with, or the error that
// keeps the handler from running at all.
func (i *Interceptor) authenticate(ctx context.Context, procedure string, header http.Header) (context.Context, error) {
	if i.exempt != nil && i.exempt(procedure) {
		return ctx, nil
	}

	token, ok := bearerToken(header)
	if !ok {
		// Absent, or not `Bearer <something>`.
		i.logger.DebugContext(ctx, "request carries no bearer token", "procedure", procedure)
		return nil, errUnauthenticated()
	}

	// Shape first, so a value that cannot be one of our tokens never becomes a
	// store lookup — a free 404-oracle and a free amplification vector
	// otherwise.
	service, ok := ServiceOf(token)
	if !ok || service != i.service {
		i.logger.DebugContext(ctx, "bearer token is not shaped like a token for this service",
			"procedure", procedure, "service", i.service)
		return nil, errUnauthenticated()
	}

	// The plaintext ends here. Everything below sees only the hash.
	identity, err := i.store.LookupTokenHash(ctx, Hash(token))
	switch {
	case errors.Is(err, ErrTokenNotFound):
		i.logger.DebugContext(ctx, "no org holds that token", "procedure", procedure)
		return nil, errUnauthenticated()
	case err != nil:
		// Ours, not the caller's: the same token may well be valid. Saying
		// UNAUTHENTICATED here would tell a caller to go and fetch a new token
		// during a database outage, and would hide the outage from whoever is
		// watching the error codes.
		i.logger.WarnContext(ctx, "the token store could not be read", "procedure", procedure, "err", err)
		return nil, errUnavailable()
	}

	if identity.Org == "" {
		// The store answered, and answered wrongly. Not the same thing as
		// being unreachable, and emphatically not the same thing as a valid
		// token: an empty org would authorize nothing under [AuthorizeOrg],
		// but it would still let a handler run.
		i.logger.ErrorContext(ctx, "the token store returned an empty org", "procedure", procedure)
		return nil, errInternal()
	}

	return NewContext(ctx, identity), nil
}

// bearerToken pulls the token out of `Authorization: Bearer <token>`. The
// scheme is matched case-insensitively (RFC 7235 §2.1) and everything else is
// refused. The token is never logged, here or anywhere.
//
// A request carrying more than one Authorization header is refused rather than
// resolved: RFC 7235 §4.2 allows exactly one, and a credential that depends on
// which hop reads it is not a credential.
func bearerToken(header http.Header) (string, bool) {
	values := header.Values(authorizationHeader)
	if len(values) != 1 {
		return "", false
	}
	value := values[0]
	if len(value) <= len(bearerPrefix) || !strings.EqualFold(value[:len(bearerPrefix)], bearerPrefix) {
		return "", false
	}
	token := strings.TrimSpace(value[len(bearerPrefix):])
	return token, token != ""
}
