package governance

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

// HTTPAssetReference is resolved from trusted route configuration, never from
// OpenProdkt identity headers supplied by the incoming request.
type HTTPAssetReference struct {
	AssetID       string
	AssetKey      string
	AssetIdentity *AssetIdentity
}

// HTTPAdapterOptions contains application-owned resolvers for request context.
// PrincipalContext must contain a credential already validated by the host app.
type HTTPAdapterOptions struct {
	ResolveAsset            func(*http.Request) (HTTPAssetReference, error)
	ResolveMetadata         func(*http.Request) (any, error)
	ResolvePrincipalContext func(*http.Request) (*PrincipalContext, error)
	ResolveOperationID      func(*http.Request) (string, error)
	ResolveHost             func(*http.Request) string
	ResolveRouteID          func(*http.Request) string
	// ResolveApprovalRetry returns the stored approval tuple for an approved retry, or nil.
	ResolveApprovalRetry func(*http.Request) (*ApprovalRetry, error)
	HeaderAllowlist      []string
}

// AuthorizeHTTPRequest builds the canonical HTTP transport from a net/http
// request and calls the shared authorize primitive. Asset, metadata, and
// principal values are supplied by trusted application callbacks.
func (c *Client) AuthorizeHTTPRequest(ctx context.Context, request *http.Request, options HTTPAdapterOptions) (DecisionResponse, error) {
	if request == nil || request.URL == nil {
		return DecisionResponse{}, fmt.Errorf("HTTP request is required")
	}
	asset := HTTPAssetReference{}
	var err error
	if options.ResolveAsset != nil {
		asset, err = options.ResolveAsset(request)
		if err != nil {
			return DecisionResponse{}, fmt.Errorf("resolve HTTP asset: %w", err)
		}
	}
	var metadata any
	if options.ResolveMetadata != nil {
		metadata, err = options.ResolveMetadata(request)
		if err != nil {
			return DecisionResponse{}, fmt.Errorf("resolve HTTP metadata: %w", err)
		}
	}
	var principalContext *PrincipalContext
	if options.ResolvePrincipalContext != nil {
		principalContext, err = options.ResolvePrincipalContext(request)
		if err != nil {
			return DecisionResponse{}, fmt.Errorf("resolve HTTP principal context: %w", err)
		}
	}
	operationID := ""
	if options.ResolveOperationID != nil {
		operationID, err = options.ResolveOperationID(request)
		if err != nil {
			return DecisionResponse{}, fmt.Errorf("resolve HTTP operation ID: %w", err)
		}
	}
	if strings.TrimSpace(operationID) == "" {
		operationID = request.Header.Get("Idempotency-Key")
	}
	operationID, err = validateHTTPOperationID(operationID)
	if err != nil {
		return DecisionResponse{}, err
	}
	headers, err := selectedHTTPHeaders(request, options.HeaderAllowlist)
	if err != nil {
		return DecisionResponse{}, err
	}
	host := ""
	if options.ResolveHost != nil {
		host = strings.TrimSpace(options.ResolveHost(request))
	}
	routeID := request.URL.Path
	if options.ResolveRouteID != nil {
		routeID = strings.TrimSpace(options.ResolveRouteID(request))
	}
	scheme := "http"
	if request.TLS != nil {
		scheme = "https"
	}
	var approval *ApprovalRetry
	if options.ResolveApprovalRetry != nil {
		approval, err = options.ResolveApprovalRetry(request)
		if err != nil {
			return DecisionResponse{}, fmt.Errorf("resolve HTTP approval retry: %w", err)
		}
	}

	authorization := AuthorizationRequest{
		AssetID: asset.AssetID, AssetKey: asset.AssetKey, AssetIdentity: asset.AssetIdentity,
		OperationID: operationID, Metadata: metadata, PrincipalContext: principalContext,
		Transport: &TransportContext{Kind: "http", HTTP: &HTTPTransport{
			Method: strings.ToUpper(strings.TrimSpace(request.Method)), Path: request.URL.Path,
			Host: host, Scheme: scheme, RouteID: routeID, Headers: headers,
		}},
	}
	if approval != nil {
		if err := validateApprovalRetry(*approval); err != nil {
			return DecisionResponse{}, err
		}
		authorization.ApprovalID = approval.ApprovalID
		authorization.PayloadHash = approval.PayloadHash
	}
	return c.Authorize(ctx, authorization)
}

// validateApprovalRetry requires the approval ID and payload hash to be supplied together.
func validateApprovalRetry(retry ApprovalRetry) error {
	if strings.TrimSpace(retry.ApprovalID) == "" || strings.TrimSpace(retry.PayloadHash) == "" {
		return fmt.Errorf("approval retry requires approval_id and payload_hash")
	}
	return nil
}

// HTTPMiddleware authorizes before invoking the protected handler. Supply
// handleOutcome to integrate application-specific typed HTTP error mapping.
func (c *Client) HTTPMiddleware(options HTTPAdapterOptions, handleOutcome func(http.ResponseWriter, *http.Request, DecisionResponse, error)) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
			response, err := c.AuthorizeHTTPRequest(request.Context(), request, options)
			if err != nil || response.Decision != "allow" {
				if handleOutcome == nil {
					http.Error(w, "authorization outcome handler is required", http.StatusInternalServerError)
					return
				}
				handleOutcome(w, request, response, err)
				return
			}
			next.ServeHTTP(w, request.WithContext(context.WithValue(request.Context(), httpDecisionContextKey{}, response)))
		})
	}
}

type httpDecisionContextKey struct{}

// DecisionFromHTTPRequest returns the allow decision attached by HTTPMiddleware.
func DecisionFromHTTPRequest(request *http.Request) (DecisionResponse, bool) {
	if request == nil {
		return DecisionResponse{}, false
	}
	response, ok := request.Context().Value(httpDecisionContextKey{}).(DecisionResponse)
	return response, ok
}

func validateHTTPOperationID(value string) (string, error) {
	operationID := strings.TrimSpace(value)
	if operationID == "" || len(operationID) > 255 || strings.ContainsAny(operationID, "\r\n") {
		return "", fmt.Errorf("operation_id or Idempotency-Key must be non-empty, header-safe, and at most 255 characters")
	}
	return operationID, nil
}

func selectedHTTPHeaders(request *http.Request, allowlist []string) (map[string]string, error) {
	if len(allowlist) == 0 {
		return nil, nil
	}
	headers := make(map[string]string, len(allowlist))
	for _, item := range allowlist {
		name := strings.ToLower(strings.TrimSpace(item))
		if name == "" {
			return nil, fmt.Errorf("allowlisted HTTP header names must not be empty")
		}
		if name == "authorization" || name == "proxy-authorization" || name == "cookie" || name == "set-cookie" || name == "host" || strings.HasPrefix(name, "x-openprodkt-") {
			return nil, fmt.Errorf("HTTP header %q cannot be copied into transport context", name)
		}
		if values := request.Header.Values(name); len(values) > 0 {
			headers[name] = strings.Join(values, ",")
		}
	}
	return headers, nil
}
