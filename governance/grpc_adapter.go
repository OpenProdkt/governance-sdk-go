package governance

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// GRPCAssetReference is resolved from trusted route configuration, never from
// caller-supplied OpenProdkt identity metadata.
type GRPCAssetReference struct {
	AssetID       string
	AssetKey      string
	AssetIdentity *AssetIdentity
}

// GRPCRequestContext describes RPC establishment. Stream adapters receive a nil
// Request and authorize once before stream creation; they never inspect messages.
type GRPCRequestContext struct {
	FullMethod string
	Service    string
	Method     string
	RPCType    string
	Request    any
	Metadata   metadata.MD
}

// GRPCAdapterOptions contains trusted application resolvers and a metadata
// allowlist for constructing one canonical gRPC evaluation request.
type GRPCAdapterOptions struct {
	ResolveAsset            func(context.Context, GRPCRequestContext) (GRPCAssetReference, error)
	ResolveMetadata         func(context.Context, GRPCRequestContext) (any, error)
	ResolvePrincipalContext func(context.Context, GRPCRequestContext) (*PrincipalContext, error)
	ResolveOperationID      func(context.Context, GRPCRequestContext) (string, error)
	ResolveRouteID          func(GRPCRequestContext) string
	// ResolveApprovalRetry is consulted at stream or unary establishment only; it returns the stored tuple for an approved retry.
	ResolveApprovalRetry func(context.Context, GRPCRequestContext) (*ApprovalRetry, error)
	MetadataAllowlist    []string
}

func (c *Client) UnaryClientInterceptor(options GRPCAdapterOptions) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, request, reply any, conn *grpc.ClientConn, invoker grpc.UnaryInvoker, callOptions ...grpc.CallOption) error {
		callContext, err := c.authorizeGRPC(ctx, method, "unary", request, metadataFromOutgoing(ctx), options)
		if err != nil {
			return err
		}
		return invoker(callContext, method, request, reply, conn, callOptions...)
	}
}

func (c *Client) StreamClientInterceptor(options GRPCAdapterOptions) grpc.StreamClientInterceptor {
	return func(ctx context.Context, description *grpc.StreamDesc, conn *grpc.ClientConn, method string, streamer grpc.Streamer, callOptions ...grpc.CallOption) (grpc.ClientStream, error) {
		rpcType := grpcRPCType(description.ClientStreams, description.ServerStreams)
		callContext, err := c.authorizeGRPC(ctx, method, rpcType, nil, metadataFromOutgoing(ctx), options)
		if err != nil {
			return nil, err
		}
		return streamer(callContext, description, conn, method, callOptions...)
	}
}

func (c *Client) UnaryServerInterceptor(options GRPCAdapterOptions) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, request any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if info == nil {
			return nil, status.Error(codes.InvalidArgument, "gRPC method information is required")
		}
		callContext, err := c.authorizeGRPC(ctx, info.FullMethod, "unary", request, metadataFromIncoming(ctx), options)
		if err != nil {
			return nil, err
		}
		return handler(callContext, request)
	}
}

func (c *Client) StreamServerInterceptor(options GRPCAdapterOptions) grpc.StreamServerInterceptor {
	return func(server any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if info == nil || stream == nil {
			return status.Error(codes.InvalidArgument, "gRPC stream information is required")
		}
		rpcType := grpcRPCType(info.IsClientStream, info.IsServerStream)
		callContext, err := c.authorizeGRPC(stream.Context(), info.FullMethod, rpcType, nil, metadataFromIncoming(stream.Context()), options)
		if err != nil {
			return err
		}
		return handler(server, &authorizedGRPCServerStream{ServerStream: stream, context: callContext})
	}
}

func (c *Client) authorizeGRPC(ctx context.Context, fullMethod, rpcType string, request any, rpcMetadata metadata.MD, options GRPCAdapterOptions) (context.Context, error) {
	service, method, err := splitGRPCFullMethod(fullMethod)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	requestContext := GRPCRequestContext{
		FullMethod: fullMethod, Service: service, Method: method, RPCType: rpcType,
		Request: request, Metadata: rpcMetadata.Copy(),
	}
	if options.ResolveAsset == nil {
		return nil, status.Error(codes.FailedPrecondition, "gRPC asset resolver is required")
	}
	asset, err := options.ResolveAsset(ctx, requestContext)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "could not resolve gRPC asset")
	}
	operationID := ""
	if options.ResolveOperationID != nil {
		operationID, err = options.ResolveOperationID(ctx, requestContext)
		if err != nil {
			return nil, status.Error(codes.InvalidArgument, "could not resolve gRPC operation ID")
		}
	}
	if strings.TrimSpace(operationID) == "" {
		values := rpcMetadata.Get("idempotency-key")
		if len(values) > 0 {
			operationID = values[0]
		}
	}
	operationID, err = validateGRPCOperationID(operationID)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	var appMetadata any
	if options.ResolveMetadata != nil {
		appMetadata, err = options.ResolveMetadata(ctx, requestContext)
		if err != nil {
			return nil, status.Error(codes.InvalidArgument, "could not resolve gRPC metadata")
		}
	}
	var principalContext *PrincipalContext
	if options.ResolvePrincipalContext != nil {
		principalContext, err = options.ResolvePrincipalContext(ctx, requestContext)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, "could not resolve authenticated gRPC principal")
		}
	}
	selectedMetadata, err := selectedGRPCMetadata(rpcMetadata, options.MetadataAllowlist)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	routeID := fullMethod
	if options.ResolveRouteID != nil {
		if resolved := strings.TrimSpace(options.ResolveRouteID(requestContext)); resolved != "" {
			routeID = resolved
		}
	}
	authorization := AuthorizationRequest{
		AssetID: asset.AssetID, AssetKey: asset.AssetKey, AssetIdentity: asset.AssetIdentity,
		OperationID: operationID, Metadata: appMetadata, PrincipalContext: principalContext,
		Transport: &TransportContext{Kind: "grpc", GRPC: &GRPCTransport{
			FullMethod: fullMethod, Service: service, Method: method, RPCType: rpcType,
			RouteID: routeID, Metadata: selectedMetadata,
		}},
	}
	if options.ResolveApprovalRetry != nil {
		retry, err := options.ResolveApprovalRetry(ctx, requestContext)
		if err != nil {
			return nil, status.Error(codes.InvalidArgument, "could not resolve gRPC approval retry")
		}
		if retry != nil {
			if err := validateApprovalRetry(*retry); err != nil {
				return nil, status.Error(codes.InvalidArgument, err.Error())
			}
			authorization.ApprovalID = retry.ApprovalID
			authorization.PayloadHash = retry.PayloadHash
		}
	}
	response, err := c.Authorize(ctx, authorization)
	if err != nil {
		return nil, grpcAuthorizationError(err)
	}
	if response.Decision != "allow" {
		return nil, status.Errorf(codes.PermissionDenied, "governance decision: %s", response.Decision)
	}
	return context.WithValue(ctx, grpcDecisionContextKey{}, response), nil
}

type grpcDecisionContextKey struct{}

// GRPCDecisionFromContext returns the successful decision attached by a server interceptor.
func GRPCDecisionFromContext(ctx context.Context) (DecisionResponse, bool) {
	if ctx == nil {
		return DecisionResponse{}, false
	}
	response, ok := ctx.Value(grpcDecisionContextKey{}).(DecisionResponse)
	return response, ok
}

type authorizedGRPCServerStream struct {
	grpc.ServerStream
	context context.Context
}

func (s *authorizedGRPCServerStream) Context() context.Context { return s.context }

func metadataFromOutgoing(ctx context.Context) metadata.MD {
	values, _ := metadata.FromOutgoingContext(ctx)
	return values
}

func metadataFromIncoming(ctx context.Context) metadata.MD {
	values, _ := metadata.FromIncomingContext(ctx)
	return values
}

func splitGRPCFullMethod(fullMethod string) (string, string, error) {
	trimmed := strings.TrimSpace(fullMethod)
	parts := strings.Split(strings.TrimPrefix(trimmed, "/"), "/")
	if !strings.HasPrefix(trimmed, "/") || len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("gRPC full method must use /package.Service/Method form")
	}
	return parts[0], parts[1], nil
}

func grpcRPCType(clientStream, serverStream bool) string {
	switch {
	case clientStream && serverStream:
		return "bidirectional_streaming"
	case clientStream:
		return "client_streaming"
	case serverStream:
		return "server_streaming"
	default:
		return "unary"
	}
}

func validateGRPCOperationID(value string) (string, error) {
	operationID := strings.TrimSpace(value)
	if operationID == "" || len(operationID) > 255 || strings.ContainsAny(operationID, "\r\n") {
		return "", fmt.Errorf("operation_id or Idempotency-Key must be non-empty, header-safe, and at most 255 characters")
	}
	return operationID, nil
}

func selectedGRPCMetadata(source metadata.MD, allowlist []string) (map[string]string, error) {
	if len(allowlist) == 0 {
		return nil, nil
	}
	selected := make(map[string]string, len(allowlist))
	for _, item := range allowlist {
		name := strings.ToLower(strings.TrimSpace(item))
		if name == "" {
			return nil, fmt.Errorf("allowlisted gRPC metadata names must not be empty")
		}
		if strings.HasSuffix(name, "-bin") || name == "authorization" || name == "cookie" || strings.HasPrefix(name, "x-openprodkt-") {
			return nil, fmt.Errorf("gRPC metadata %q cannot be copied into transport context", name)
		}
		if values := source.Get(name); len(values) > 0 {
			selected[name] = strings.Join(values, ",")
		}
	}
	return selected, nil
}

func grpcAuthorizationError(err error) error {
	var outcomeError *EvaluationOutcomeError
	if errors.As(err, &outcomeError) {
		return grpcErrorForOutcome(outcomeError.Outcome)
	}
	var inputError *InvalidAuthorizationInputError
	if errors.As(err, &inputError) {
		return grpcErrorForOutcome("invalid_request")
	}
	var configurationError *ClientConfigurationError
	if errors.As(err, &configurationError) {
		return grpcErrorForOutcome("configuration_error")
	}
	return grpcErrorForOutcome("pdp_unavailable")
}

func grpcErrorForOutcome(outcome string) error {
	if outcome == "allow" {
		return nil
	}
	code := codes.Unavailable
	switch outcome {
	case "authorization_denied", "pending_approval", "approval_status_scope_required", "approval_rejected", "approval_expired", "approval_revoked", "approval_consumed":
		code = codes.PermissionDenied
	case "approval_not_found", "asset_not_found":
		code = codes.NotFound
	case "operation_conflict", "asset_identity_conflict":
		code = codes.AlreadyExists
	case "quota_exceeded":
		code = codes.ResourceExhausted
	case "invalid_request":
		code = codes.InvalidArgument
	case "configuration_error":
		code = codes.FailedPrecondition
	case "pdp_unavailable":
	default:
		outcome = "pdp_unavailable"
	}
	grpcStatus := status.New(code, "governance authorization failed")
	withDetails, err := grpcStatus.WithDetails(&errdetails.ErrorInfo{
		Reason: outcome,
		Domain: "governance.openprodkt",
	})
	if err != nil {
		return grpcStatus.Err()
	}
	return withDetails.Err()
}

var _ grpc.UnaryClientInterceptor = (*Client)(nil).UnaryClientInterceptor(GRPCAdapterOptions{})
var _ grpc.StreamClientInterceptor = (*Client)(nil).StreamClientInterceptor(GRPCAdapterOptions{})
var _ grpc.UnaryServerInterceptor = (*Client)(nil).UnaryServerInterceptor(GRPCAdapterOptions{})
var _ grpc.StreamServerInterceptor = (*Client)(nil).StreamServerInterceptor(GRPCAdapterOptions{})
