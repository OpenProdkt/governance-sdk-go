package governance

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestGenerateAssetKeyConformance(t *testing.T) {
	fixtureBytes, err := os.ReadFile("../../testdata/asset-key-conformance.json")
	if err != nil {
		t.Fatalf("read asset key conformance fixtures: %v", err)
	}
	var cases []struct {
		Name     string        `json:"name"`
		Identity AssetIdentity `json:"identity"`
		AssetKey string        `json:"asset_key"`
		Error    string        `json:"error"`
	}
	if err := json.Unmarshal(fixtureBytes, &cases); err != nil {
		t.Fatalf("decode asset key conformance fixtures: %v", err)
	}
	for _, testCase := range cases {
		t.Run(testCase.Name, func(t *testing.T) {
			assetKey, err := GenerateAssetKey(testCase.Identity)
			if testCase.Error != "" {
				if err == nil {
					t.Fatalf("expected invalid %s identity component", testCase.Error)
				}
				return
			}
			if err != nil {
				t.Fatalf("generate asset key: %v", err)
			}
			if assetKey != testCase.AssetKey {
				t.Fatalf("expected %q, got %q", testCase.AssetKey, assetKey)
			}
		})
	}
}

func TestClientAuthorizeGeneratesAssetKeyFromIdentity(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request EvaluateRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if request.Asset.Key != "billing.refund-api.production" || request.Asset.Application != "billing" || request.Asset.Service != "refund-api" || request.Asset.Environment != "production" {
			t.Fatalf("unexpected asset identity: %+v", request.Asset)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(DecisionResponse{Decision: "allow"})
	}))
	defer server.Close()

	client := NewClient(server.URL, "opk_live_test", time.Second)
	_, err := client.Authorize(context.Background(), AuthorizationRequest{
		OperationID:   "refund-123",
		AssetIdentity: &AssetIdentity{Application: "billing", Service: "refund-api", Environment: "production"},
	})
	if err != nil {
		t.Fatalf("authorize with asset identity: %v", err)
	}
}

func TestClientAuthorizeUsesConfiguredDefaultAssetIdentity(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request EvaluateRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if request.Asset.Key != "billing.refund-api.production" || request.Asset.Application != "billing" || request.Asset.Service != "refund-api" || request.Asset.Environment != "production" {
			t.Fatalf("unexpected configured asset identity: %+v", request.Asset)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(DecisionResponse{Decision: "allow"})
	}))
	defer server.Close()

	client := NewClientWithDefaultAssetIdentity(server.URL, "opk_live_test", time.Second, AssetIdentity{
		Application: "billing", Service: "refund-api", Environment: "production",
	})
	if _, err := client.Authorize(context.Background(), AuthorizationRequest{OperationID: "refund-default"}); err != nil {
		t.Fatalf("authorize with configured identity: %v", err)
	}
}

func TestClientAuthorizeRejectsMissingAssetIdentityBeforeRequest(t *testing.T) {
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requestCount++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(DecisionResponse{Decision: "allow"})
	}))
	defer server.Close()

	client := NewClient(server.URL, "opk_live_test", time.Second)
	if _, err := client.Authorize(context.Background(), AuthorizationRequest{OperationID: "refund-no-asset"}); err == nil || !strings.Contains(err.Error(), "exactly one of asset_id or asset_key") {
		t.Fatalf("expected local identity validation error, got %v", err)
	}
	if _, err := client.Authorize(context.Background(), AuthorizationRequest{
		AssetID: "ast_1", OperationID: "refund-unsafe-principal",
		PrincipalContext: &PrincipalContext{BearerToken: "user-token\r\ninjected: true"},
	}); err == nil || !strings.Contains(err.Error(), "header-safe") {
		t.Fatalf("expected unsafe principal context to fail locally, got %v", err)
	}
	if requestCount != 0 {
		t.Fatalf("local identity/principal validation must happen before network I/O, requests=%d", requestCount)
	}
}

func TestClientAuthorizeSendsApprovalRetryTuple(t *testing.T) {
	expiresAt := time.Now().UTC().Add(time.Minute).Truncate(time.Second)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request EvaluateRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if request.ApprovalID != "apr_1" || request.PayloadHash != "sha256:"+strings.Repeat("a", 64) {
			t.Fatalf("unexpected retry tuple: %+v", request)
		}
		_ = json.NewEncoder(w).Encode(DecisionResponse{
			Decision: "allow", DecisionID: "dec_1", ApprovalStatus: "consumed",
			PayloadHash: request.PayloadHash, GrantExpiresAt: &expiresAt,
		})
	}))
	defer server.Close()
	client := NewClient(server.URL, "opk_live_test", time.Second)
	response, err := client.Authorize(context.Background(), AuthorizationRequest{
		AssetID: "ast_1", OperationID: "refund-1", ApprovalID: "apr_1", PayloadHash: "sha256:" + strings.Repeat("a", 64),
	})
	if err != nil || response.Decision != "allow" || response.ApprovalStatus != "consumed" || response.GrantExpiresAt == nil {
		t.Fatalf("unexpected retry response=%+v err=%v", response, err)
	}
	if _, err := client.Authorize(context.Background(), AuthorizationRequest{AssetID: "ast_1", OperationID: "refund-1", ApprovalID: "apr_1"}); err == nil {
		t.Fatalf("expected incomplete approval retry tuple to fail locally")
	}
}

func TestClientAuthorize(t *testing.T) {
	t.Parallel()
	expiresAt := time.Now().UTC().Add(time.Hour)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/evaluate" {
			t.Fatalf("expected path /v1/evaluate, got %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer opk_live_test" {
			t.Fatalf("unexpected auth header: %q", got)
		}

		var req EvaluateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if req.Version != "v1" || req.Asset.ID != "ast_invoice_agent" || req.OperationID != "refund-123" || req.Transport.Kind != "http" || req.Metadata["environment"] != "production" {
			t.Fatalf("unexpected request payload: %+v", req)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(DecisionResponse{
			OrganizationID:    "org_test",
			Decision:          "approval_required",
			DecisionID:        "dec_test",
			ApprovalID:        "apr_test",
			Reason:            "amount_threshold",
			PolicyID:          "pol_payment_threshold",
			PayloadHash:       "sha256:" + strings.Repeat("a", 64),
			ApprovalExpiresAt: &expiresAt,
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "opk_live_test", 2*time.Second)
	resp, err := client.Authorize(context.Background(), AuthorizationRequest{
		AssetID:     "ast_invoice_agent",
		OperationID: "refund-123",
		Metadata:    map[string]interface{}{"environment": "production"},
	})
	pending, ok := err.(*PendingApprovalError)
	if !ok {
		t.Fatalf("expected PendingApprovalError, got %T: %v", err, err)
	}

	if resp.Decision != "approval_required" {
		t.Fatalf("expected approval_required, got %q", resp.Decision)
	}
	if resp.DecisionID == "" {
		t.Fatalf("expected non-empty decision id")
	}
	if resp.PayloadHash != "sha256:"+strings.Repeat("a", 64) {
		t.Fatalf("expected payload hash, got %q", resp.PayloadHash)
	}
	if pending.OperationID != "refund-123" || pending.ApprovalID != "apr_test" || pending.StatusURL != server.URL+"/v1/approvals/apr_test" || !pending.ExpiresAt.Equal(expiresAt) {
		t.Fatalf("unexpected pending approval details: %+v", pending)
	}
}

func TestClientAuthorizeAcceptsStructMetadata(t *testing.T) {
	type RefundMetadata struct {
		Operation string `json:"operation"`
		Amount    int    `json:"amount"`
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request EvaluateRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("decode evaluation request: %v", err)
		}
		if request.Metadata["operation"] != "refund" || request.Metadata["amount"] != float64(42) {
			t.Fatalf("unexpected serialized metadata: %+v", request.Metadata)
		}
		_ = json.NewEncoder(w).Encode(DecisionResponse{Decision: "allow"})
	}))
	defer server.Close()
	client := NewClient(server.URL, "opk_live_test", time.Second)
	if _, err := client.Authorize(context.Background(), AuthorizationRequest{
		AssetID: "ast_1", OperationID: "refund-struct", Metadata: RefundMetadata{Operation: "refund", Amount: 42},
	}); err != nil {
		t.Fatalf("authorize with struct metadata: %v", err)
	}
}

func TestClientAuthorizeRejectsUnsupportedMetadataBeforeNetwork(t *testing.T) {
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requestCount++
		_ = json.NewEncoder(w).Encode(DecisionResponse{Decision: "allow"})
	}))
	defer server.Close()
	client := NewClient(server.URL, "opk_live_test", time.Second)
	_, err := client.Authorize(context.Background(), AuthorizationRequest{
		AssetID: "ast_1", OperationID: "refund-invalid-metadata", Metadata: map[string]interface{}{"value": make(chan int)},
	})
	if err == nil || requestCount != 0 {
		t.Fatalf("unsupported metadata should fail before network I/O, err=%v requests=%d", err, requestCount)
	}
}

func TestClientAuthorizeClassifiesEvaluationHTTPStatuses(t *testing.T) {
	for statusCode, outcome := range map[int]string{
		http.StatusForbidden:          "authorization_denied",
		http.StatusNotFound:           "approval_not_found",
		http.StatusConflict:           "operation_conflict",
		http.StatusPaymentRequired:    "quota_exceeded",
		http.StatusBadRequest:         "invalid_request",
		http.StatusServiceUnavailable: "pdp_unavailable",
	} {
		t.Run(outcome, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(statusCode)
				_ = json.NewEncoder(w).Encode(DecisionResponse{Decision: "deny", Reason: "test_outcome"})
			}))
			defer server.Close()
			client := NewClient(server.URL, "opk_live_test", time.Second)
			response, err := client.Authorize(context.Background(), AuthorizationRequest{AssetID: "ast_1", OperationID: "refund-status"})
			var outcomeErr *EvaluationOutcomeError
			if denied, ok := err.(*AuthorizationDeniedError); ok {
				outcomeErr = &denied.EvaluationOutcomeError
			} else if generic, ok := err.(*EvaluationOutcomeError); ok {
				outcomeErr = generic
			}
			if outcomeErr == nil || outcomeErr.HTTPStatus != statusCode || outcomeErr.Outcome != outcome || response.Reason != "test_outcome" {
				t.Fatalf("unexpected outcome: response=%+v err=%#v", response, err)
			}
		})
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	defer server.Close()
	client := NewClient(server.URL, "opk_live_test", time.Second)
	if _, err := client.Authorize(context.Background(), AuthorizationRequest{AssetID: "ast_1", OperationID: "refund-status"}); err == nil || !strings.Contains(err.Error(), "unexpected /v1/evaluate HTTP status 418") {
		t.Fatalf("unexpected evaluation status should be a transport failure, got %v", err)
	}
}

func TestClientAuthorizeClassifiesTerminalApprovalAndCollisionOutcomes(t *testing.T) {
	for _, reason := range []string{"approval_rejected", "approval_expired", "approval_revoked", "approval_consumed"} {
		t.Run(reason, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				_ = json.NewEncoder(w).Encode(DecisionResponse{Decision: "deny", Reason: reason})
			}))
			defer server.Close()
			client := NewClient(server.URL, "opk_live_test", time.Second)
			_, err := client.Authorize(context.Background(), AuthorizationRequest{AssetID: "ast_1", OperationID: "refund-terminal"})
			terminal, ok := err.(*ApprovalTerminalError)
			if !ok || terminal.Outcome != reason {
				t.Fatalf("expected terminal outcome %q, got %#v", reason, err)
			}
		})
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(DecisionResponse{Code: "asset_identity_conflict", Error: "identity collision"})
	}))
	defer server.Close()
	client := NewClient(server.URL, "opk_live_test", time.Second)
	_, err := client.Authorize(context.Background(), AuthorizationRequest{AssetID: "ast_1", OperationID: "refund-collision"})
	outcomeErr, ok := err.(*EvaluationOutcomeError)
	if !ok || outcomeErr.Outcome != "asset_identity_conflict" {
		t.Fatalf("expected identity conflict outcome, got %#v", err)
	}
}

func TestClientConcurrentDuplicateInitialRequestsStayPending(t *testing.T) {
	var evaluations atomic.Int32
	expiresAt := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		evaluations.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(DecisionResponse{
			Decision: "approval_required", DecisionID: "dec_pending", ApprovalID: "apr_pending",
			PayloadHash: "sha256:" + strings.Repeat("a", 64), ApprovalExpiresAt: &expiresAt,
		})
	}))
	defer server.Close()
	client := NewClient(server.URL, "opk_live_test", 2*time.Second)

	const attempts = 16
	var wg sync.WaitGroup
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := client.Authorize(context.Background(), AuthorizationRequest{AssetID: "ast_1", OperationID: "refund-duplicate"})
			pending, ok := err.(*PendingApprovalError)
			if !ok || pending.ApprovalID != "apr_pending" || pending.OperationID != "refund-duplicate" {
				t.Errorf("duplicate initial request must return the same pending challenge, err=%#v", err)
			}
		}()
	}
	wg.Wait()
	if got := evaluations.Load(); got != attempts {
		t.Fatalf("each Authorize call must issue exactly one evaluation, got %d for %d calls", got, attempts)
	}
}

func TestClientConcurrentApprovedRetryAllowsExactlyOne(t *testing.T) {
	var redemptions atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request EvaluateRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		// The fake PDP redeems at most once, mirroring the atomic approved-to-consumed transition.
		if redemptions.Add(1) == 1 {
			expiresAt := time.Now().UTC().Add(time.Minute)
			_ = json.NewEncoder(w).Encode(DecisionResponse{
				Decision: "allow", DecisionID: "dec_1", ApprovalStatus: "consumed",
				PayloadHash: request.PayloadHash, GrantExpiresAt: &expiresAt,
			})
			return
		}
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(DecisionResponse{Decision: "deny", Reason: "approval_consumed"})
	}))
	defer server.Close()
	client := NewClient(server.URL, "opk_live_test", 2*time.Second)

	const attempts = 16
	var allows, consumedDenials atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			response, err := client.Authorize(context.Background(), AuthorizationRequest{
				AssetID: "ast_1", OperationID: "refund-redeem", ApprovalID: "apr_1", PayloadHash: "sha256:" + strings.Repeat("a", 64),
			})
			if err == nil && response.Decision == "allow" && response.ApprovalStatus == "consumed" {
				allows.Add(1)
				return
			}
			terminal, ok := err.(*ApprovalTerminalError)
			if ok && terminal.Outcome == "approval_consumed" {
				consumedDenials.Add(1)
				return
			}
			t.Errorf("unexpected concurrent redemption result response=%+v err=%#v", response, err)
		}()
	}
	wg.Wait()
	if allows.Load() != 1 || consumedDenials.Load() != attempts-1 {
		t.Fatalf("exactly one ALLOW expected, allows=%d consumedDenials=%d", allows.Load(), consumedDenials.Load())
	}
}

func TestClientAuthorizeAndWaitRedeemsApprovedApproval(t *testing.T) {
	evaluationCalls := 0
	expiresAt := time.Now().UTC().Add(time.Hour)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer verified-user-token" {
			t.Fatalf("expected adapter principal credential, got %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/evaluate":
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("read evaluation request: %v", err)
			}
			if strings.Contains(string(body), "verified-user-token") || strings.Contains(string(body), "principal_context") {
				t.Fatalf("principal credential must not be serialized: %s", body)
			}
			var request EvaluateRequest
			if err := json.Unmarshal(body, &request); err != nil {
				t.Fatalf("decode evaluation request: %v", err)
			}
			evaluationCalls++
			if evaluationCalls == 1 {
				w.WriteHeader(http.StatusAccepted)
				_ = json.NewEncoder(w).Encode(DecisionResponse{
					Decision: "approval_required", DecisionID: "dec_wait", ApprovalID: "apr_wait",
					PayloadHash: "sha256:" + strings.Repeat("b", 64), ApprovalStatus: "pending", ApprovalExpiresAt: &expiresAt,
				})
				return
			}
			if request.OperationID != "refund-wait" || request.ApprovalID != "apr_wait" || request.PayloadHash != "sha256:"+strings.Repeat("b", 64) {
				t.Fatalf("expected exact approval retry tuple, got %+v", request)
			}
			_ = json.NewEncoder(w).Encode(DecisionResponse{
				Decision: "allow", DecisionID: "dec_wait", ApprovalStatus: "consumed",
			})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/approvals/apr_wait":
			_ = json.NewEncoder(w).Encode(Approval{ID: "apr_wait", Status: "approved"})
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	client := NewClient(server.URL, "opk_live_test", time.Second)
	response, err := client.AuthorizeAndWait(context.Background(), AuthorizationRequest{
		AssetID: "ast_refund", OperationID: "refund-wait",
		PrincipalContext: &PrincipalContext{BearerToken: "verified-user-token"},
	}, time.Second, time.Millisecond)
	if err != nil || response.Decision != "allow" || response.ApprovalStatus != "consumed" || evaluationCalls != 2 {
		t.Fatalf("expected bounded wait to redeem approval once, response=%+v calls=%d err=%v", response, evaluationCalls, err)
	}
}

func TestClientAuthorizeAndWaitTerminalPollOutcomesNeverRedeem(t *testing.T) {
	now := time.Now().UTC()
	cases := []struct {
		name     string
		approval Approval
		outcome  string
	}{
		{name: "rejected", approval: Approval{ID: "apr_terminal", Status: "rejected"}, outcome: "approval_rejected"},
		{name: "expired", approval: Approval{ID: "apr_terminal", Status: "expired"}, outcome: "approval_expired"},
		{name: "consumed", approval: Approval{ID: "apr_terminal", Status: "consumed"}, outcome: "approval_consumed"},
		{name: "revoked", approval: Approval{ID: "apr_terminal", Status: "approved", RevokedAt: &now}, outcome: "approval_revoked"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			evaluationCalls := 0
			expiresAt := now.Add(time.Hour)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.Method == http.MethodPost && r.URL.Path == "/v1/evaluate" {
					evaluationCalls++
					w.WriteHeader(http.StatusAccepted)
					_ = json.NewEncoder(w).Encode(DecisionResponse{
						Decision: "approval_required", DecisionID: "dec_terminal", ApprovalID: "apr_terminal",
						PayloadHash: "sha256:" + strings.Repeat("f", 64), ApprovalExpiresAt: &expiresAt,
					})
					return
				}
				if r.Method == http.MethodGet && r.URL.Path == "/v1/approvals/apr_terminal" {
					_ = json.NewEncoder(w).Encode(tc.approval)
					return
				}
				t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
			}))
			defer server.Close()
			client := NewClient(server.URL, "opk_live_test", time.Second)
			_, err := client.AuthorizeAndWait(context.Background(), AuthorizationRequest{
				AssetID: "ast_terminal", OperationID: "refund-terminal-" + tc.name,
			}, time.Second, time.Millisecond)
			terminal, ok := err.(*ApprovalTerminalError)
			if !ok || terminal.Outcome != tc.outcome || evaluationCalls != 1 {
				t.Fatalf("expected terminal %q after one evaluation, err=%#v evaluations=%d", tc.outcome, err, evaluationCalls)
			}
		})
	}
}

func TestClientAuthorizeAndWaitRedemptionFailureIsNotReevaluated(t *testing.T) {
	evaluationCalls := 0
	expiresAt := time.Now().UTC().Add(time.Hour)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost && r.URL.Path == "/v1/evaluate" {
			evaluationCalls++
			if evaluationCalls == 1 {
				w.WriteHeader(http.StatusAccepted)
				_ = json.NewEncoder(w).Encode(DecisionResponse{
					Decision: "approval_required", DecisionID: "dec_lost", ApprovalID: "apr_lost",
					PayloadHash: "sha256:" + strings.Repeat("a", 64), ApprovalExpiresAt: &expiresAt,
				})
				return
			}
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(DecisionResponse{Reason: "pdp_unavailable"})
			return
		}
		if r.Method == http.MethodGet && r.URL.Path == "/v1/approvals/apr_lost" {
			_ = json.NewEncoder(w).Encode(Approval{ID: "apr_lost", Status: "approved"})
			return
		}
		t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()
	client := NewClient(server.URL, "opk_live_test", time.Second)
	_, err := client.AuthorizeAndWait(context.Background(), AuthorizationRequest{
		AssetID: "ast_lost", OperationID: "refund-lost",
	}, time.Second, time.Millisecond)
	var outcome *EvaluationOutcomeError
	if !errors.As(err, &outcome) || outcome.HTTPStatus != http.StatusServiceUnavailable || evaluationCalls != 2 {
		t.Fatalf("expected one failed redemption and no re-evaluation, err=%#v evaluations=%d", err, evaluationCalls)
	}
}

func TestClientAuthorizeAndWaitOptionsReturnPendingOnContextCancellation(t *testing.T) {
	evaluationCalls := 0
	statusCalls := 0
	expiresAt := time.Now().UTC().Add(time.Hour)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost && r.URL.Path == "/v1/evaluate" {
			evaluationCalls++
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(DecisionResponse{
				Decision: "approval_required", DecisionID: "dec_cancel", ApprovalID: "apr_cancel",
				PayloadHash: "sha256:" + strings.Repeat("d", 64), ApprovalExpiresAt: &expiresAt,
			})
			return
		}
		if r.Method == http.MethodGet && r.URL.Path == "/v1/approvals/apr_cancel" {
			statusCalls++
			_ = json.NewEncoder(w).Encode(Approval{ID: "apr_cancel", Status: "pending"})
			return
		}
		t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()
	client := NewClient(server.URL, "opk_live_test", time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(20*time.Millisecond, cancel)
	response, err := client.AuthorizeAndWaitWithOptions(ctx, AuthorizationRequest{
		AssetID: "ast_cancel", OperationID: "refund-cancel",
	}, ApprovalWaitOptions{
		Timeout: time.Second, PollInterval: 50 * time.Millisecond, MaxPollInterval: 100 * time.Millisecond,
		BackoffMultiplier: 2, JitterFraction: 0,
	})
	var pending *PendingApprovalError
	if !errors.As(err, &pending) || response.Decision != "approval_required" || pending.ApprovalID != "apr_cancel" || evaluationCalls != 1 || statusCalls < 1 {
		t.Fatalf("cancelled wait should preserve one pending challenge, response=%+v err=%v evals=%d status=%d", response, err, evaluationCalls, statusCalls)
	}
}

func TestClientAuthorizeAndWaitOptionsRejectUnboundedWait(t *testing.T) {
	client := NewClient("https://pdp.example.test", "opk_live_test", time.Second)
	_, err := client.AuthorizeAndWaitWithOptions(context.Background(), AuthorizationRequest{
		AssetID: "ast_1", OperationID: "refund-bounds",
	}, ApprovalWaitOptions{Timeout: 31 * time.Second})
	if err == nil || !strings.Contains(err.Error(), "timeout") {
		t.Fatalf("expected bounded-wait validation error, got %v", err)
	}
}

func TestClientAuthorizeAndWaitOptionsTimeoutPreservesPendingChallenge(t *testing.T) {
	evaluationCalls := 0
	statusCalls := 0
	expiresAt := time.Now().UTC().Add(time.Hour)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost && r.URL.Path == "/v1/evaluate" {
			evaluationCalls++
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(DecisionResponse{
				Decision: "approval_required", DecisionID: "dec_timeout", ApprovalID: "apr_timeout",
				PayloadHash: "sha256:" + strings.Repeat("e", 64), ApprovalExpiresAt: &expiresAt,
			})
			return
		}
		if r.Method == http.MethodGet && r.URL.Path == "/v1/approvals/apr_timeout" {
			statusCalls++
			_ = json.NewEncoder(w).Encode(Approval{ID: "apr_timeout", Status: "pending"})
			return
		}
		t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()
	client := NewClient(server.URL, "opk_live_test", time.Second)
	response, err := client.AuthorizeAndWaitWithOptions(context.Background(), AuthorizationRequest{
		AssetID: "ast_timeout", OperationID: "refund-timeout",
	}, ApprovalWaitOptions{
		Timeout: time.Millisecond, PollInterval: 2 * time.Millisecond, MaxPollInterval: 5 * time.Millisecond,
		BackoffMultiplier: 1.5, JitterFraction: 0,
	})
	var pending *PendingApprovalError
	if !errors.As(err, &pending) || response.Decision != "approval_required" || pending.ApprovalID != "apr_timeout" || evaluationCalls != 1 || statusCalls == 0 {
		t.Fatalf("timed out wait should preserve one pending challenge, response=%+v err=%v evals=%d status=%d", response, err, evaluationCalls, statusCalls)
	}
}

func TestClientAuthorizeAndWaitPropagatesScopeDenialDuringPolling(t *testing.T) {
	statusCalls := 0
	expiresAt := time.Now().UTC().Add(time.Hour)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost && r.URL.Path == "/v1/evaluate" {
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(DecisionResponse{
				Decision: "approval_required", DecisionID: "dec_scope", ApprovalID: "apr_scope",
				PayloadHash: "sha256:" + strings.Repeat("f", 64), ApprovalExpiresAt: &expiresAt,
			})
			return
		}
		if r.Method == http.MethodGet && r.URL.Path == "/v1/approvals/apr_scope" {
			statusCalls++
			if statusCalls == 1 {
				_ = json.NewEncoder(w).Encode(Approval{ID: "apr_scope", Status: "pending"})
				return
			}
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"code":"insufficient_scope","error":"api key scope not permitted"}`))
			return
		}
		t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()
	client := NewClient(server.URL, "opk_live_test", time.Second)
	_, err := client.AuthorizeAndWaitWithOptions(context.Background(), AuthorizationRequest{
		AssetID: "ast_scope", OperationID: "refund-scope",
	}, ApprovalWaitOptions{
		Timeout: time.Second, PollInterval: 2 * time.Millisecond, MaxPollInterval: 5 * time.Millisecond,
		BackoffMultiplier: 1.5, JitterFraction: 0,
	})
	var scopeErr *ApprovalStatusAccessError
	var pending *PendingApprovalError
	if !errors.As(err, &scopeErr) {
		t.Fatalf("scope denial during wait should surface as ApprovalStatusAccessError, got %T: %v", err, err)
	}
	if errors.As(err, &pending) {
		t.Fatalf("scope denial during wait must not be reported as a pending challenge")
	}
	if statusCalls != 2 {
		t.Fatalf("expected two status polls, got %d", statusCalls)
	}
}

func TestClientIngestAssetDiscovery(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/asset-discoveries" || r.Method != http.MethodPost {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		var request map[string]any
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if request["discovery_id"] != "dsc_test" || request["observed_at"] == nil {
			t.Fatalf("unexpected discovery request: %+v", request)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"discoveryId": "dsc_test", "status": "accepted"})
	}))
	defer server.Close()

	client := NewClient(server.URL, "opk_live_test", time.Second)
	response, err := client.IngestAssetDiscovery(context.Background(), IngestAssetDiscoveryRequest{
		DiscoveryID: "dsc_test", Asset: DiscoveredAsset{Key: "billing.refund", Kind: "rest_api", Environment: "production"},
		Metadata: map[string]interface{}{"operation": "refund"}, Source: DiscoverySource{Kind: "detection_point", ID: "dp_1"},
		Evidence: DiscoveryEvidence{Kind: "http_request"}, ObservedAt: time.Now().UTC(),
	})
	if err != nil || response["status"] != "accepted" {
		t.Fatalf("ingest discovery failed response=%+v err=%v", response, err)
	}
}

func TestClientGetApprovalStatusClassifiesScopeAndNotFound(t *testing.T) {
	for _, testCase := range []struct {
		name       string
		statusCode int
		body       string
		check      func(error) bool
	}{
		{
			name: "insufficient scope", statusCode: http.StatusForbidden,
			body:  `{"code":"insufficient_scope","error":"api key scope not permitted"}`,
			check: func(err error) bool { _, ok := err.(*ApprovalStatusAccessError); return ok },
		},
		{
			name: "not found", statusCode: http.StatusNotFound,
			body:  `{"error":"approval not found"}`,
			check: func(err error) bool { _, ok := err.(*ApprovalNotFoundError); return ok },
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(testCase.statusCode)
				_, _ = w.Write([]byte(testCase.body))
			}))
			defer server.Close()
			client := NewClient(server.URL, "opk_test", time.Second)
			_, err := client.GetApprovalStatus(context.Background(), "apr_1")
			if err == nil || !testCase.check(err) {
				t.Fatalf("unexpected status error type %T: %v", err, err)
			}
		})
	}
}

func TestClientRequestCode(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/request-code" {
			t.Fatalf("expected path /auth/request-code, got %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if got := r.Header.Get("Authorization"); got != "" {
			t.Fatalf("expected no auth header, got %q", got)
		}

		var req RequestCodeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if req.Email != "ops@example.com" {
			t.Fatalf("unexpected request payload: %+v", req)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"sent": true})
	}))
	defer server.Close()

	client := NewClient(server.URL, "opk_live_test", 2*time.Second)
	resp, err := client.RequestCode(context.Background(), RequestCodeRequest{Email: "ops@example.com"})
	if err != nil {
		t.Fatalf("request code failed: %v", err)
	}
	if sent, ok := resp["sent"].(bool); !ok || !sent {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestClientBootstrapUsesInternalAdminToken(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/bootstrap" {
			t.Fatalf("expected path /v1/bootstrap, got %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer internal-admin-token" {
			t.Fatalf("unexpected auth header: %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"organizationId": "org_test"})
	}))
	defer server.Close()

	client := NewClient(server.URL, "internal-admin-token", 2*time.Second)
	resp, err := client.Bootstrap(context.Background(), BootstrapRequest{
		OrganizationName: "Sandbox Test",
		OwnerEmail:       "owner@example.com",
		Tier:             "free",
		Mode:             "saas",
	})
	if err != nil {
		t.Fatalf("bootstrap failed: %v", err)
	}
	if resp["organizationId"] != "org_test" {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestClientUploadEntitlementArtifact(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/entitlement/upload" {
			t.Fatalf("expected path /v1/entitlement/upload, got %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer opk_live_test" {
			t.Fatalf("unexpected auth header: %q", got)
		}

		mr, err := r.MultipartReader()
		if err != nil {
			t.Fatalf("multipart reader: %v", err)
		}
		part, err := mr.NextPart()
		if err != nil {
			t.Fatalf("next part: %v", err)
		}
		if part.FormName() != "license" || part.FileName() != "license.json" {
			t.Fatalf("unexpected multipart part: form=%s file=%s", part.FormName(), part.FileName())
		}
		content, err := io.ReadAll(part)
		if err != nil {
			t.Fatalf("read part: %v", err)
		}
		if string(content) != "signed-license" {
			t.Fatalf("unexpected content: %q", string(content))
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"uploaded": true})
	}))
	defer server.Close()

	client := NewClient(server.URL, "opk_live_test", 2*time.Second)
	resp, err := client.UploadEntitlementArtifact(context.Background(), "license.json", []byte("signed-license"))
	if err != nil {
		t.Fatalf("upload failed: %v", err)
	}
	if uploaded, ok := resp["uploaded"].(bool); !ok || !uploaded {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestClientLifecycleEvidenceRequests(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/policies/pol_test/activation":
			if r.Method != http.MethodPatch {
				t.Fatalf("expected PATCH, got %s", r.Method)
			}
			_ = json.NewEncoder(w).Encode(Policy{ID: "pol_test", IsActive: false})
		case "/v1/decision-explorer":
			if r.URL.Query().Get("limit") != "10" || r.URL.Query().Get("status") != "failed" || r.URL.Query().Get("assetId") != "ast_test" {
				t.Fatalf("unexpected decision query: %s", r.URL.RawQuery)
			}
			_ = json.NewEncoder(w).Encode(DecisionExplorerResponse{Limit: 10})
		case "/v1/audit":
			if r.URL.Query().Get("limit") != "10" || r.URL.Query().Get("offset") != "5" || r.URL.Query().Get("eventType") != "policy" {
				t.Fatalf("unexpected audit query: %s", r.URL.RawQuery)
			}
			_ = json.NewEncoder(w).Encode(AuditPage{Limit: 10, Offset: 5})
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	client := NewClient(server.URL, "opk_live_test", 2*time.Second)
	policy, err := client.SetPolicyActive(context.Background(), "pol_test", false)
	if err != nil || policy.IsActive {
		t.Fatalf("unexpected activation response: %+v err=%v", policy, err)
	}
	decisions, err := client.ListDecisionExplorer(context.Background(), DecisionQuery{Limit: 10, Status: "failed", AssetID: "ast_test"})
	if err != nil || decisions.Limit != 10 {
		t.Fatalf("unexpected decision page: %+v err=%v", decisions, err)
	}
	page, err := client.ListAuditEvents(context.Background(), AuditQuery{Limit: 10, Offset: 5, EventType: "policy"})
	if err != nil || page.Limit != 10 || page.Offset != 5 {
		t.Fatalf("unexpected audit page: %+v err=%v", page, err)
	}
}
