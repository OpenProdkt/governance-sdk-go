package governance

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Client struct {
	baseURL              string
	apiKey               string
	httpClient           *http.Client
	defaultAssetIdentity *AssetIdentity
}

type EvaluationOutcomeError struct {
	HTTPStatus int
	Outcome    string
	Code       string
	Response   DecisionResponse
}

func (e *EvaluationOutcomeError) Error() string {
	return fmt.Sprintf("POST /v1/evaluate returned status %d", e.HTTPStatus)
}

type AuthorizationDeniedError struct{ EvaluationOutcomeError }
type ApprovalTerminalError struct{ EvaluationOutcomeError }

func (e *AuthorizationDeniedError) Unwrap() error { return &e.EvaluationOutcomeError }
func (e *ApprovalTerminalError) Unwrap() error    { return &e.EvaluationOutcomeError }

type PendingApprovalError struct {
	EvaluationOutcomeError
	OperationID   string
	ApprovalID    string
	PayloadHash   string
	Asset         EvaluateAsset
	AssetIdentity *AssetIdentity
	StatusURL     string
	ExpiresAt     time.Time
}

func (e *PendingApprovalError) Unwrap() error { return &e.EvaluationOutcomeError }

type InvalidAuthorizationInputError struct{ Message string }

func (e *InvalidAuthorizationInputError) Error() string { return e.Message }

type ClientConfigurationError struct{ Message string }

func (e *ClientConfigurationError) Error() string { return e.Message }

type ApprovalStatusAccessError struct{ StatusCode int }

func (e *ApprovalStatusAccessError) Error() string {
	return "approval status requires approvals:read scope"
}

type ApprovalNotFoundError struct{ StatusCode int }

func (e *ApprovalNotFoundError) Error() string { return "approval not found" }

type httpResponseError struct {
	Method     string
	Path       string
	StatusCode int
	Body       string
}

func (e *httpResponseError) Error() string {
	if e.Body != "" {
		return fmt.Sprintf("%s %s returned status %d: %s", e.Method, e.Path, e.StatusCode, e.Body)
	}
	return fmt.Sprintf("%s %s returned status %d", e.Method, e.Path, e.StatusCode)
}

func evaluationOutcome(status int) (string, bool) {
	switch status {
	case http.StatusForbidden:
		return "authorization_denied", true
	case http.StatusNotFound:
		return "approval_not_found", true
	case http.StatusConflict:
		return "operation_conflict", true
	case http.StatusPaymentRequired:
		return "quota_exceeded", true
	case http.StatusBadRequest:
		return "invalid_request", true
	case http.StatusServiceUnavailable:
		return "pdp_unavailable", true
	default:
		return "", false
	}
}

func NewClient(baseURL, apiKey string, timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		apiKey:  apiKey,
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
}

// NewClientWithDefaultAssetIdentity configures the stable identity used when an
// authorization request omits both AssetID and AssetKey.
func NewClientWithDefaultAssetIdentity(baseURL, apiKey string, timeout time.Duration, identity AssetIdentity) *Client {
	client := NewClient(baseURL, apiKey, timeout)
	client.defaultAssetIdentity = &identity
	return client
}

func (c *Client) Authorize(ctx context.Context, req AuthorizationRequest) (DecisionResponse, error) {
	if strings.TrimSpace(req.OperationID) == "" {
		return DecisionResponse{}, &InvalidAuthorizationInputError{Message: "operation_id is required"}
	}
	credential, err := c.authorizationCredential(req.PrincipalContext)
	if err != nil {
		return DecisionResponse{}, &InvalidAuthorizationInputError{Message: err.Error()}
	}
	if (strings.TrimSpace(req.ApprovalID) == "") != (strings.TrimSpace(req.PayloadHash) == "") {
		return DecisionResponse{}, &InvalidAuthorizationInputError{Message: "approval_id and payload_hash must be supplied together"}
	}
	assetID := strings.TrimSpace(req.AssetID)
	assetKey := strings.TrimSpace(req.AssetKey)
	assetIdentity := req.AssetIdentity
	if assetIdentity == nil && assetID == "" && assetKey == "" && c.defaultAssetIdentity != nil {
		identity := *c.defaultAssetIdentity
		assetIdentity = &identity
	}
	if assetIdentity != nil {
		generatedKey, err := GenerateAssetKey(*assetIdentity)
		if err != nil {
			return DecisionResponse{}, &InvalidAuthorizationInputError{Message: err.Error()}
		}
		if assetID == "" && assetKey == "" {
			assetKey = generatedKey
		} else if assetID == "" && assetKey != generatedKey {
			return DecisionResponse{}, &InvalidAuthorizationInputError{Message: "asset_key does not match asset_identity"}
		}
	}
	if assetID == "" && assetKey == "" {
		return DecisionResponse{}, &ClientConfigurationError{Message: "exactly one of asset_id or asset_key is required; configure a default asset identity"}
	}
	if assetID != "" && assetKey != "" {
		return DecisionResponse{}, &InvalidAuthorizationInputError{Message: "exactly one of asset_id or asset_key is required"}
	}
	req.OperationID = strings.TrimSpace(req.OperationID)
	var sanitizedMetadata map[string]interface{}
	if req.Metadata != nil {
		sanitized, err := SanitizeMetadata(req.Metadata)
		if err != nil {
			return DecisionResponse{}, &InvalidAuthorizationInputError{Message: err.Error()}
		}
		sanitizedMetadata = sanitized
	}
	transport := TransportContext{Kind: "http"}
	if req.Transport != nil {
		transport = *req.Transport
	}
	wireRequest := EvaluateRequest{
		Version:     "v1",
		Asset:       EvaluateAsset{ID: assetID, Key: assetKey},
		OperationID: strings.TrimSpace(req.OperationID),
		ApprovalID:  strings.TrimSpace(req.ApprovalID),
		PayloadHash: strings.TrimSpace(req.PayloadHash),
		Transport:   transport,
		Metadata:    sanitizedMetadata,
	}
	if assetIdentity != nil {
		wireRequest.Asset.Application = assetIdentity.Application
		wireRequest.Asset.Service = assetIdentity.Service
		wireRequest.Asset.Environment = assetIdentity.Environment
	}
	return c.evaluateWithCredential(ctx, wireRequest, credential)
}

// EvaluateProxy posts a canonical request to /v1/proxy/evaluate. It is intended
// only for protocol PEP adapters (for example the Envoy ext_authz adapter).
// The principal is mandatory: proxy traffic never falls back to the client API key.
// Application code must use Authorize.
func (c *Client) EvaluateProxy(ctx context.Context, request EvaluateRequest, principal *PrincipalContext) (DecisionResponse, error) {
	if principal == nil {
		return DecisionResponse{}, &InvalidAuthorizationInputError{Message: "principal context is required for proxy evaluation"}
	}
	credential, err := c.authorizationCredential(principal)
	if err != nil {
		return DecisionResponse{}, &InvalidAuthorizationInputError{Message: err.Error()}
	}
	if strings.TrimSpace(request.OperationID) == "" {
		return DecisionResponse{}, &InvalidAuthorizationInputError{Message: "operation_id is required"}
	}
	return c.evaluateAt(ctx, "/v1/proxy/evaluate", request, credential)
}

func (c *Client) evaluateWithCredential(ctx context.Context, request EvaluateRequest, credential string) (DecisionResponse, error) {
	return c.evaluateAt(ctx, "/v1/evaluate", request, credential)
}

func (c *Client) evaluateAt(ctx context.Context, path string, request EvaluateRequest, credential string) (DecisionResponse, error) {
	encoded, err := json.Marshal(request)
	if err != nil {
		return DecisionResponse{}, fmt.Errorf("marshal evaluation request: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(encoded))
	if err != nil {
		return DecisionResponse{}, fmt.Errorf("create evaluation request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+credential)
	httpResp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return DecisionResponse{}, fmt.Errorf("evaluation request failed: %w", err)
	}
	defer httpResp.Body.Close()

	status := httpResp.StatusCode
	outcome, isOutcome := evaluationOutcome(status)
	if status != http.StatusOK && status != http.StatusAccepted && !isOutcome {
		return DecisionResponse{}, fmt.Errorf("unexpected %s HTTP status %d", path, status)
	}
	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return DecisionResponse{}, fmt.Errorf("read evaluation response: %w", err)
	}
	var response DecisionResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return DecisionResponse{}, fmt.Errorf("decode evaluation response: %w", err)
	}
	if (status == http.StatusOK || status == http.StatusAccepted) && response.Decision == "" {
		return DecisionResponse{}, fmt.Errorf("decode evaluation response: decision is required")
	}
	if status == http.StatusOK && response.Decision != "allow" {
		return DecisionResponse{}, fmt.Errorf("evaluation status 200 conflicts with decision %q", response.Decision)
	}
	if status == http.StatusOK && request.ApprovalID != "" && response.ApprovalStatus != "consumed" {
		return DecisionResponse{}, fmt.Errorf("approved retry was not confirmed consumed by /v1/evaluate")
	}
	if status == http.StatusAccepted && response.Decision != "approval_required" {
		return DecisionResponse{}, fmt.Errorf("evaluation status 202 conflicts with decision %q", response.Decision)
	}
	if status == http.StatusAccepted {
		if response.ApprovalID == "" || !validCanonicalPayloadHash(response.PayloadHash) || response.ApprovalExpiresAt == nil {
			return DecisionResponse{}, fmt.Errorf("pending evaluation response is missing approval ID, canonical payload hash, or expiry")
		}
		operationID := response.OperationID
		if operationID == "" {
			operationID = request.OperationID
		}
		assetIdentity := (*AssetIdentity)(nil)
		if request.Asset.Application != "" || request.Asset.Service != "" || request.Asset.Environment != "" {
			assetIdentity = &AssetIdentity{Application: request.Asset.Application, Service: request.Asset.Service, Environment: request.Asset.Environment}
		}
		pending := &PendingApprovalError{
			EvaluationOutcomeError: EvaluationOutcomeError{HTTPStatus: status, Outcome: "pending_approval", Response: response},
			OperationID:            operationID, ApprovalID: response.ApprovalID, PayloadHash: response.PayloadHash,
			Asset: request.Asset, AssetIdentity: assetIdentity,
			StatusURL: c.baseURL + "/v1/approvals/" + url.PathEscape(response.ApprovalID),
			ExpiresAt: *response.ApprovalExpiresAt,
		}
		return response, pending
	}
	if isOutcome {
		outcomeErr := EvaluationOutcomeError{HTTPStatus: status, Outcome: outcome, Code: response.Code, Response: response}
		if status == http.StatusForbidden {
			terminalReason := response.Reason
			if terminalReason == "" {
				terminalReason = response.Code
			}
			if terminalReason == "approval_grant_expired" {
				terminalReason = "approval_expired"
			}
			switch terminalReason {
			case "approval_rejected", "approval_expired", "approval_revoked", "approval_consumed":
				outcomeErr.Outcome = terminalReason
				return response, &ApprovalTerminalError{outcomeErr}
			}
			if response.Code == "approvals_disabled" {
				outcomeErr.Outcome = "configuration_error"
				return response, &outcomeErr
			}
			outcomeErr.Outcome = "authorization_denied"
			return response, &AuthorizationDeniedError{outcomeErr}
		}
		if status == http.StatusConflict && response.Code == "asset_identity_conflict" {
			outcomeErr.Outcome = "asset_identity_conflict"
		}
		if status == http.StatusNotFound && (response.Code == "asset_not_found" || response.Error == "asset not found") {
			outcomeErr.Outcome = "asset_not_found"
		}
		return response, &outcomeErr
	}
	return response, nil
}

func validCanonicalPayloadHash(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	hexValue := strings.TrimPrefix(value, "sha256:")
	decoded, err := hex.DecodeString(hexValue)
	return err == nil && len(decoded) == 32 && hexValue == strings.ToLower(hexValue)
}

// AuthorizeAndWait evaluates a decision and, if it comes back approval_required, blocks for up
// to waitTimeout polling for resolution before returning. Use this for interactive short-wait
// UX only; app-managed retry and async webhook delivery remain the recommended defaults.
func (c *Client) AuthorizeAndWait(ctx context.Context, req AuthorizationRequest, waitTimeout, pollInterval time.Duration) (DecisionResponse, error) {
	return c.AuthorizeAndWaitWithOptions(ctx, req, ApprovalWaitOptions{
		Timeout: waitTimeout, PollInterval: pollInterval, MaxPollInterval: pollInterval,
		BackoffMultiplier: 1, JitterFraction: 0,
	})
}

type ApprovalWaitOptions struct {
	Timeout           time.Duration
	PollInterval      time.Duration
	MaxPollInterval   time.Duration
	BackoffMultiplier float64
	JitterFraction    float64
}

func (c *Client) AuthorizeAndWaitWithOptions(ctx context.Context, req AuthorizationRequest, options ApprovalWaitOptions) (DecisionResponse, error) {
	options, err := normalizeApprovalWaitOptions(options, 30*time.Second)
	if err != nil {
		return DecisionResponse{}, err
	}
	resp, err := c.Authorize(ctx, req)
	var pending *PendingApprovalError
	if !errors.As(err, &pending) {
		return resp, err
	}
	resp = pending.Response
	approval, err := c.WaitForApprovalWithOptions(ctx, pending.ApprovalID, options, req.PrincipalContext)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return resp, pending
		}
		return resp, err
	}
	resp.ApprovalStatus = approval.Status
	if approval.Status == "pending" {
		return resp, pending
	}
	if approval.RevokedAt != nil {
		return resp, &ApprovalTerminalError{EvaluationOutcomeError{HTTPStatus: http.StatusForbidden, Outcome: "approval_revoked", Response: resp}}
	}
	if approval.Status != "approved" {
		outcome := "approval_" + approval.Status
		return resp, &ApprovalTerminalError{EvaluationOutcomeError{HTTPStatus: http.StatusForbidden, Outcome: outcome, Response: resp}}
	}
	req.ApprovalID = pending.ApprovalID
	req.PayloadHash = pending.PayloadHash
	return c.Authorize(ctx, req)
}

func (c *Client) PlaygroundCheck(ctx context.Context, req DecisionRequest) (DecisionResponse, error) {
	if req.Metadata != nil {
		sanitized, err := SanitizeMetadata(req.Metadata)
		if err != nil {
			return DecisionResponse{}, err
		}
		req.Metadata = sanitized
	}
	var resp DecisionResponse
	if err := c.doJSON(ctx, http.MethodPost, "/v1/playground/decision", req, &resp, true); err != nil {
		return DecisionResponse{}, err
	}
	return resp, nil
}

func (c *Client) RequestCode(ctx context.Context, req RequestCodeRequest) (map[string]any, error) {
	return c.requestMap(ctx, http.MethodPost, "/auth/request-code", req, false)
}

func (c *Client) VerifyCode(ctx context.Context, req VerifyCodeRequest) (VerifyCodeResponse, error) {
	var resp VerifyCodeResponse
	if err := c.doJSON(ctx, http.MethodPost, "/auth/verify", req, &resp, false); err != nil {
		return VerifyCodeResponse{}, err
	}
	return resp, nil
}

func (c *Client) Register(ctx context.Context, req RegisterRequest) (map[string]any, error) {
	return c.requestMap(ctx, http.MethodPost, "/auth/register", req, false)
}

func (c *Client) Bootstrap(ctx context.Context, req BootstrapRequest) (map[string]any, error) {
	return c.requestMap(ctx, http.MethodPost, "/v1/bootstrap", req, true)
}

func (c *Client) InviteMember(ctx context.Context, req InviteMemberRequest) (map[string]any, error) {
	return c.requestMap(ctx, http.MethodPost, "/members", req, true)
}

func (c *Client) Me(ctx context.Context) (map[string]any, error) {
	return c.requestMap(ctx, http.MethodGet, "/me", nil, true)
}

func (c *Client) Settings(ctx context.Context) (map[string]any, error) {
	return c.requestMap(ctx, http.MethodGet, "/settings", nil, true)
}

func (c *Client) ListAPIKeys(ctx context.Context) (map[string]any, error) {
	return c.requestMap(ctx, http.MethodGet, "/v1/api-keys", nil, true)
}

func (c *Client) CreateAPIKey(ctx context.Context, req CreateAPIKeyRequest) (map[string]any, error) {
	return c.requestMap(ctx, http.MethodPost, "/v1/api-keys", req, true)
}

func (c *Client) RotateAPIKey(ctx context.Context, keyID string) (map[string]any, error) {
	return c.requestMap(ctx, http.MethodPost, "/v1/api-keys/"+keyID+"/rotate", nil, true)
}

func (c *Client) RevokeAPIKey(ctx context.Context, keyID string) (map[string]any, error) {
	return c.requestMap(ctx, http.MethodPost, "/v1/api-keys/"+keyID+"/revoke", nil, true)
}

func (c *Client) ListDecisionExplorer(ctx context.Context, query DecisionQuery) (DecisionExplorerResponse, error) {
	values := url.Values{}
	values.Set("limit", fmt.Sprint(query.Limit))
	values.Set("offset", fmt.Sprint(query.Offset))
	if query.Decision != "" {
		values.Set("decision", query.Decision)
	}
	if query.Status != "" {
		values.Set("status", query.Status)
	}
	if query.AssetID != "" {
		values.Set("assetId", query.AssetID)
	}
	if query.PolicyID != "" {
		values.Set("policyId", query.PolicyID)
	}
	if query.Search != "" {
		values.Set("search", query.Search)
	}
	if query.From != nil {
		values.Set("from", query.From.Format(time.RFC3339))
	}
	if query.To != nil {
		values.Set("to", query.To.Format(time.RFC3339))
	}
	var resp DecisionExplorerResponse
	err := c.doJSON(ctx, http.MethodGet, "/v1/decision-explorer?"+values.Encode(), nil, &resp, true)
	return resp, err
}

func (c *Client) ListAssets(ctx context.Context) (map[string]any, error) {
	return c.requestMap(ctx, http.MethodGet, "/v1/assets", nil, true)
}

func (c *Client) CreateAsset(ctx context.Context, req CreateAssetRequest) (map[string]any, error) {
	return c.requestMap(ctx, http.MethodPost, "/v1/assets", req, true)
}

func (c *Client) UpdateAsset(ctx context.Context, assetID string, req UpdateAssetRequest) (map[string]any, error) {
	return c.requestMap(ctx, http.MethodPatch, "/v1/assets/"+assetID, req, true)
}

func (c *Client) DeleteAsset(ctx context.Context, assetID string) (map[string]any, error) {
	return c.requestMap(ctx, http.MethodDelete, "/v1/assets/"+assetID, nil, true)
}

func (c *Client) IngestAssetDiscovery(ctx context.Context, req IngestAssetDiscoveryRequest) (map[string]any, error) {
	return c.requestMap(ctx, http.MethodPost, "/v1/asset-discoveries", req, true)
}

func (c *Client) ListAssetDiscoveries(ctx context.Context) (AssetDiscoveriesResponse, error) {
	var response AssetDiscoveriesResponse
	err := c.doJSON(ctx, http.MethodGet, "/v1/asset-discoveries", nil, &response, true)
	return response, err
}

func (c *Client) DeleteAssetDiscovery(ctx context.Context, discoveryID string) (map[string]any, error) {
	return c.requestMap(ctx, http.MethodDelete, "/v1/asset-discoveries/"+url.PathEscape(discoveryID), nil, true)
}

func (c *Client) ListGroups(ctx context.Context) (map[string]any, error) {
	return c.requestMap(ctx, http.MethodGet, "/v1/groups", nil, true)
}

func (c *Client) CreateGroup(ctx context.Context, req CreateGroupRequest) (map[string]any, error) {
	return c.requestMap(ctx, http.MethodPost, "/v1/groups", req, true)
}

func (c *Client) UpdateGroup(ctx context.Context, groupID string, req UpdateGroupRequest) (map[string]any, error) {
	return c.requestMap(ctx, http.MethodPatch, "/v1/groups/"+groupID, req, true)
}

func (c *Client) DeleteGroup(ctx context.Context, groupID string) (map[string]any, error) {
	return c.requestMap(ctx, http.MethodDelete, "/v1/groups/"+groupID, nil, true)
}

func (c *Client) ListPolicies(ctx context.Context) (map[string]any, error) {
	return c.requestMap(ctx, http.MethodGet, "/v1/policies", nil, true)
}

func (c *Client) CreatePolicy(ctx context.Context, req CreatePolicyRequest) (map[string]any, error) {
	return c.requestMap(ctx, http.MethodPost, "/v1/policies", req, true)
}

func (c *Client) DeletePolicy(ctx context.Context, policyID string) (map[string]any, error) {
	return c.requestMap(ctx, http.MethodDelete, "/v1/policies/"+policyID, nil, true)
}

func (c *Client) SetPolicyActive(ctx context.Context, policyID string, isActive bool) (Policy, error) {
	var resp Policy
	err := c.doJSON(ctx, http.MethodPatch, "/v1/policies/"+url.PathEscape(policyID)+"/activation", map[string]bool{"isActive": isActive}, &resp, true)
	return resp, err
}

func (c *Client) ListPolicyRevisions(ctx context.Context, policyID string) (PolicyRevisionsResponse, error) {
	var resp PolicyRevisionsResponse
	err := c.doJSON(ctx, http.MethodGet, "/v1/policies/"+url.PathEscape(policyID)+"/revisions", nil, &resp, true)
	return resp, err
}

func (c *Client) RollbackPolicy(ctx context.Context, policyID, revisionID string) (Policy, error) {
	var resp Policy
	err := c.doJSON(ctx, http.MethodPost, "/v1/policies/"+url.PathEscape(policyID)+"/rollback", map[string]string{"revisionId": revisionID}, &resp, true)
	return resp, err
}

func (c *Client) ListApprovals(ctx context.Context, query ApprovalQuery) (ApprovalPage, error) {
	values := url.Values{}
	values.Set("limit", fmt.Sprint(query.Limit))
	values.Set("offset", fmt.Sprint(query.Offset))
	if query.Status != "" {
		values.Set("status", query.Status)
	}
	var resp ApprovalPage
	err := c.doJSON(ctx, http.MethodGet, "/v1/approvals?"+values.Encode(), nil, &resp, true)
	return resp, err
}

// GetApproval polls the current status of a single approval. It is the primitive behind
// WaitForApproval and app-managed retry/polling flows.
func (c *Client) GetApproval(ctx context.Context, approvalID string, principalContext ...*PrincipalContext) (Approval, error) {
	var resp Approval
	credential, err := c.authorizationCredential(principalContext...)
	if err != nil {
		return Approval{}, err
	}
	err = c.doJSONWithCredential(ctx, http.MethodGet, "/v1/approvals/"+url.PathEscape(approvalID), nil, &resp, credential, true)
	var responseErr *httpResponseError
	if errors.As(err, &responseErr) {
		var body struct {
			Code string `json:"code"`
		}
		_ = json.Unmarshal([]byte(responseErr.Body), &body)
		if responseErr.StatusCode == http.StatusForbidden && body.Code == "insufficient_scope" {
			return Approval{}, &ApprovalStatusAccessError{StatusCode: responseErr.StatusCode}
		}
		if responseErr.StatusCode == http.StatusNotFound {
			return Approval{}, &ApprovalNotFoundError{StatusCode: responseErr.StatusCode}
		}
	}
	return resp, err
}

func (c *Client) GetApprovalStatus(ctx context.Context, approvalID string, principalContext ...*PrincipalContext) (Approval, error) {
	return c.GetApproval(ctx, approvalID, principalContext...)
}

// WaitForApproval polls GetApproval at the given interval until the approval leaves the
// "pending" state or the timeout elapses. It never blocks indefinitely and never replaces
// async/webhook delivery, which remains the recommended default for production workloads.
func (c *Client) WaitForApproval(ctx context.Context, approvalID string, timeout, interval time.Duration, principalContext ...*PrincipalContext) (Approval, error) {
	return c.WaitForApprovalWithOptions(ctx, approvalID, ApprovalWaitOptions{
		Timeout: timeout, PollInterval: interval, MaxPollInterval: interval,
		BackoffMultiplier: 1, JitterFraction: 0,
	}, principalContext...)
}

func (c *Client) WaitForApprovalWithOptions(ctx context.Context, approvalID string, options ApprovalWaitOptions, principalContext ...*PrincipalContext) (Approval, error) {
	options, err := normalizeApprovalWaitOptions(options, 300*time.Second)
	if err != nil {
		return Approval{}, err
	}
	deadline := time.Now().Add(options.Timeout)
	interval := options.PollInterval
	for {
		approval, err := c.GetApproval(ctx, approvalID, principalContext...)
		if err != nil {
			return Approval{}, err
		}
		if approval.Status != "pending" {
			return approval, nil
		}
		if time.Now().After(deadline) {
			return approval, nil
		}
		jitterFactor := 1 + ((rand.Float64()*2 - 1) * options.JitterFraction)
		delay := time.Duration(float64(interval) * jitterFactor)
		remaining := time.Until(deadline)
		if delay > remaining {
			delay = remaining
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return Approval{}, ctx.Err()
		case <-timer.C:
		}
		interval = time.Duration(float64(interval) * options.BackoffMultiplier)
		if interval > options.MaxPollInterval {
			interval = options.MaxPollInterval
		}
	}
}

func normalizeApprovalWaitOptions(options ApprovalWaitOptions, maxTimeout time.Duration) (ApprovalWaitOptions, error) {
	if options.Timeout == 0 {
		options.Timeout = 10 * time.Second
	}
	if options.Timeout < 0 || options.Timeout > maxTimeout {
		return ApprovalWaitOptions{}, fmt.Errorf("approval wait timeout must be between zero and %s", maxTimeout)
	}
	if options.PollInterval == 0 {
		options.PollInterval = time.Second
	}
	if options.MaxPollInterval == 0 {
		options.MaxPollInterval = 5 * time.Second
	}
	if options.PollInterval < 0 || options.MaxPollInterval < options.PollInterval {
		return ApprovalWaitOptions{}, fmt.Errorf("approval polling intervals are invalid")
	}
	if options.BackoffMultiplier == 0 {
		options.BackoffMultiplier = 1.5
	}
	if options.BackoffMultiplier < 1 || options.JitterFraction < 0 || options.JitterFraction > 1 {
		return ApprovalWaitOptions{}, fmt.Errorf("approval wait backoff/jitter options are invalid")
	}
	return options, nil
}

func (c *Client) ApproveApproval(ctx context.Context, approvalID string, req ResolveApprovalRequest) (Approval, error) {
	var resp Approval
	err := c.doJSON(ctx, http.MethodPost, "/v1/approvals/"+url.PathEscape(approvalID)+"/approve", req, &resp, true)
	return resp, err
}

func (c *Client) RejectApproval(ctx context.Context, approvalID string, req ResolveApprovalRequest) (Approval, error) {
	var resp Approval
	err := c.doJSON(ctx, http.MethodPost, "/v1/approvals/"+url.PathEscape(approvalID)+"/reject", req, &resp, true)
	return resp, err
}

func (c *Client) ListAuditEvents(ctx context.Context, query AuditQuery) (AuditPage, error) {
	values := url.Values{}
	values.Set("limit", fmt.Sprint(query.Limit))
	values.Set("offset", fmt.Sprint(query.Offset))
	if query.EventType != "" {
		values.Set("eventType", query.EventType)
	}
	if query.ActorID != "" {
		values.Set("actorId", query.ActorID)
	}
	if query.ResourceType != "" {
		values.Set("resourceType", query.ResourceType)
	}
	if query.ResourceID != "" {
		values.Set("resourceId", query.ResourceID)
	}
	if query.Outcome != "" {
		values.Set("outcome", query.Outcome)
	}
	var resp AuditPage
	err := c.doJSON(ctx, http.MethodGet, "/v1/audit?"+values.Encode(), nil, &resp, true)
	return resp, err
}

func (c *Client) Usage(ctx context.Context) (map[string]any, error) {
	return c.requestMap(ctx, http.MethodGet, "/v1/usage", nil, true)
}

func (c *Client) UploadEntitlementArtifact(ctx context.Context, filename string, content []byte) (map[string]any, error) {
	buf := &bytes.Buffer{}
	writer := multipart.NewWriter(buf)
	part, err := writer.CreateFormFile("license", filename)
	if err != nil {
		return nil, fmt.Errorf("create multipart form file: %w", err)
	}
	if _, err := part.Write(content); err != nil {
		return nil, fmt.Errorf("write entitlement artifact: %w", err)
	}
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("close multipart writer: %w", err)
	}

	return c.requestMultipart(ctx, http.MethodPost, "/v1/entitlement/upload", writer.FormDataContentType(), buf.Bytes(), true)
}

func (c *Client) doJSON(ctx context.Context, method, path string, body any, out any, authenticated bool) error {
	return c.doJSONWithCredential(ctx, method, path, body, out, c.apiKey, authenticated)
}

func (c *Client) doJSONWithCredential(ctx context.Context, method, path string, body any, out any, credential string, authenticated bool) error {
	var payload io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal request: %w", err)
		}
		payload = bytes.NewReader(encoded)
	}

	httpReq, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, payload)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	if body != nil {
		httpReq.Header.Set("Content-Type", "application/json")
	}
	if authenticated {
		httpReq.Header.Set("Authorization", "Bearer "+credential)
	}

	httpResp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		bodyBytes, _ := io.ReadAll(httpResp.Body)
		return &httpResponseError{Method: method, Path: path, StatusCode: httpResp.StatusCode, Body: strings.TrimSpace(string(bodyBytes))}
	}

	if out == nil {
		return nil
	}
	if err := json.NewDecoder(httpResp.Body).Decode(out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

func (c *Client) authorizationCredential(principalContexts ...*PrincipalContext) (string, error) {
	if len(principalContexts) > 1 {
		return "", fmt.Errorf("at most one principal context may be supplied")
	}
	if len(principalContexts) == 0 || principalContexts[0] == nil {
		return c.apiKey, nil
	}
	credential := strings.TrimSpace(principalContexts[0].BearerToken)
	if credential == "" || strings.ContainsAny(credential, "\r\n") {
		return "", fmt.Errorf("principal bearer token must be non-empty and header-safe")
	}
	return credential, nil
}

func (c *Client) requestMap(ctx context.Context, method, path string, body any, authenticated bool) (map[string]any, error) {
	var resp map[string]any
	if err := c.doJSON(ctx, method, path, body, &resp, authenticated); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *Client) requestMultipart(ctx context.Context, method, path, contentType string, body []byte, authenticated bool) (map[string]any, error) {
	httpReq, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", contentType)
	if authenticated {
		httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	httpResp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		bodyBytes, _ := io.ReadAll(httpResp.Body)
		if len(bodyBytes) > 0 {
			return nil, fmt.Errorf("%s %s returned status %d: %s", method, path, httpResp.StatusCode, strings.TrimSpace(string(bodyBytes)))
		}
		return nil, fmt.Errorf("%s %s returned status %d", method, path, httpResp.StatusCode)
	}

	var resp map[string]any
	if err := json.NewDecoder(httpResp.Body).Decode(&resp); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return resp, nil
}
