package refund

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	governance "github.com/OpenProdkt/governance-sdk-go/governance"
)

const (
	testSecret = "test-webhook-secret"
	testAPIKey = "test-api-key"
)

var testHash = "sha256:" + strings.Repeat("a", 64)

// fakeAPI implements the subset of the governance HTTP contract used by the refund flow.
type fakeAPI struct {
	mu      sync.Mutex
	status  string
	retries int
}

func (f *fakeAPI) setStatus(status string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status = status
}

func (f *fakeAPI) retryCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.retries
}

func (f *fakeAPI) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/evaluate", f.evaluate)
	mux.HandleFunc("/v1/approvals/apr-1", f.approval)
	return mux
}

func (f *fakeAPI) evaluate(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"decision": "deny", "code": "invalid_request"})
		return
	}
	operationID, _ := body["operation_id"].(string)
	approvalID, _ := body["approval_id"].(string)
	switch operationID {
	case "op-allow":
		writeJSON(w, http.StatusOK, map[string]any{"decision": "allow", "decisionId": "dec-allow"})
	case "op-deny":
		writeJSON(w, http.StatusForbidden, map[string]any{"decision": "deny", "code": "policy_denied", "reason": "policy_denied"})
	case "op-approve":
		if approvalID == "" {
			writeJSON(w, http.StatusAccepted, map[string]any{
				"decision":            "approval_required",
				"decisionId":          "dec-approve",
				"approvalId":          "apr-1",
				"payload_hash":        testHash,
				"approval_expires_at": time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
			})
			return
		}
		if approvalID != "apr-1" || body["payload_hash"] != testHash {
			writeJSON(w, http.StatusForbidden, map[string]any{"decision": "deny", "code": "payload_mismatch", "reason": "payload_mismatch"})
			return
		}
		f.mu.Lock()
		f.retries++
		f.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"decision": "allow", "decisionId": "dec-approve", "approvalStatus": "consumed"})
	default:
		writeJSON(w, http.StatusBadRequest, map[string]any{"decision": "deny", "code": "invalid_request"})
	}
}

func (f *fakeAPI) approval(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"id": "apr-1", "status": f.status})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

type recorder struct {
	mu   sync.Mutex
	runs []string
}

func (r *recorder) execute(_ context.Context, refund Refund) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.runs = append(r.runs, refund.OperationID)
	return nil
}

func (r *recorder) executed() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.runs...)
}

func setup(t *testing.T, status string) (*Service, *fakeAPI, *recorder) {
	t.Helper()
	api := &fakeAPI{status: status}
	server := httptest.NewServer(api.handler())
	t.Cleanup(server.Close)
	client := governance.NewClient(server.URL, testAPIKey, 5*time.Second)
	rec := &recorder{}
	asset := governance.AssetIdentity{Application: "refunds", Service: "payments", Environment: "test"}
	return New(client, asset, rec.execute), api, rec
}

func signedWebhook(eventType, approvalID string, now time.Time) ([]byte, http.Header) {
	eventID := "evt-" + string(eventType) + "-" + approvalID
	body, _ := json.Marshal(map[string]any{
		"eventId":        eventID,
		"eventType":      eventType,
		"organizationId": "org-1",
		"aggregateId":    approvalID,
		"data":           map[string]any{"approvalId": approvalID},
	})
	timestamp := now.UTC().Format(time.RFC3339)
	mac := hmac.New(sha256.New, []byte(testSecret))
	_, _ = mac.Write([]byte(timestamp + "."))
	_, _ = mac.Write(body)
	headers := http.Header{}
	headers.Set("X-OpenProdkt-Event-Id", eventID)
	headers.Set("X-OpenProdkt-Timestamp", timestamp)
	headers.Set("X-OpenProdkt-Signature", "v1=sha256="+hex.EncodeToString(mac.Sum(nil)))
	return body, headers
}

func TestAllowedRefundExecutesOnce(t *testing.T) {
	svc, _, rec := setup(t, "pending")
	ctx := context.Background()

	outcome, err := svc.Create(ctx, Refund{OperationID: "op-allow", AmountCents: 1200, Currency: "USD"}, 100*time.Millisecond)
	if err != nil || outcome != Executed {
		t.Fatalf("Create() = %q, %v; want %q", outcome, err, Executed)
	}
	outcome, err = svc.Create(ctx, Refund{OperationID: "op-allow", AmountCents: 1200, Currency: "USD"}, 100*time.Millisecond)
	if err != nil || outcome != Executed {
		t.Fatalf("second Create() = %q, %v; want %q", outcome, err, Executed)
	}
	if runs := rec.executed(); len(runs) != 1 || runs[0] != "op-allow" {
		t.Fatalf("executions = %v; want exactly one op-allow", runs)
	}
}

func TestDeniedRefundIsNotExecuted(t *testing.T) {
	svc, _, rec := setup(t, "pending")

	outcome, err := svc.Create(context.Background(), Refund{OperationID: "op-deny", AmountCents: 99999, Currency: "USD"}, 100*time.Millisecond)
	if err != nil || outcome != Denied {
		t.Fatalf("Create() = %q, %v; want %q", outcome, err, Denied)
	}
	if runs := rec.executed(); len(runs) != 0 {
		t.Fatalf("denied refund executed: %v", runs)
	}
}

func TestBoundedWaitReturnsPendingWithoutExecuting(t *testing.T) {
	svc, api, rec := setup(t, "pending")

	outcome, err := svc.Create(context.Background(), Refund{OperationID: "op-approve", AmountCents: 5000, Currency: "USD"}, 50*time.Millisecond)
	if err != nil || outcome != Pending {
		t.Fatalf("Create() = %q, %v; want %q", outcome, err, Pending)
	}
	if runs := rec.executed(); len(runs) != 0 {
		t.Fatalf("pending refund executed before approval: %v", runs)
	}
	if api.retryCount() != 0 {
		t.Fatalf("retry sent before approval: %d", api.retryCount())
	}
}

func TestBoundedWaitExecutesWhenApprovalArrives(t *testing.T) {
	svc, api, rec := setup(t, "pending")
	go func() {
		time.Sleep(30 * time.Millisecond)
		api.setStatus("approved")
	}()

	outcome, err := svc.Create(context.Background(), Refund{OperationID: "op-approve", AmountCents: 5000, Currency: "USD"}, 3*time.Second)
	if err != nil || outcome != Executed {
		t.Fatalf("Create() = %q, %v; want %q", outcome, err, Executed)
	}
	if runs := rec.executed(); len(runs) != 1 {
		t.Fatalf("executions = %v; want one", runs)
	}
}

func TestApprovalWebhookResumesOnce(t *testing.T) {
	svc, api, rec := setup(t, "pending")
	ctx := context.Background()
	now := time.Now()

	if outcome, err := svc.Create(ctx, Refund{OperationID: "op-approve", AmountCents: 5000, Currency: "USD"}, 20*time.Millisecond); err != nil || outcome != Pending {
		t.Fatalf("Create() = %q, %v; want %q", outcome, err, Pending)
	}
	api.setStatus("approved")

	body, headers := signedWebhook("approval.approved", "apr-1", now)
	processed, err := svc.HandleApprovalWebhook(ctx, body, headers, testSecret, now)
	if err != nil || !processed {
		t.Fatalf("first delivery processed=%v err=%v; want processed", processed, err)
	}
	if runs := rec.executed(); len(runs) != 1 || runs[0] != "op-approve" {
		t.Fatalf("executions = %v; want one op-approve", runs)
	}
	if api.retryCount() != 1 {
		t.Fatalf("retries = %d; want exactly one exact-tuple retry", api.retryCount())
	}

	processed, err = svc.HandleApprovalWebhook(ctx, body, headers, testSecret, now)
	if err != nil || processed {
		t.Fatalf("duplicate delivery processed=%v err=%v; want duplicate", processed, err)
	}
	if runs := rec.executed(); len(runs) != 1 {
		t.Fatalf("duplicate delivery re-executed refund: %v", runs)
	}
	if api.retryCount() != 1 {
		t.Fatalf("duplicate delivery re-sent retry: %d", api.retryCount())
	}
}

func TestWebhookWithInvalidSignatureIsRejected(t *testing.T) {
	svc, api, rec := setup(t, "pending")
	ctx := context.Background()
	now := time.Now()
	if _, err := svc.Create(ctx, Refund{OperationID: "op-approve", AmountCents: 5000, Currency: "USD"}, 20*time.Millisecond); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	api.setStatus("approved")

	body, headers := signedWebhook("approval.approved", "apr-1", now)
	if _, err := svc.HandleApprovalWebhook(ctx, body, headers, "wrong-secret", now); err == nil {
		t.Fatal("webhook with wrong secret was accepted")
	}
	if runs := rec.executed(); len(runs) != 0 {
		t.Fatalf("unsigned webhook executed refund: %v", runs)
	}
	if api.retryCount() != 0 {
		t.Fatalf("unsigned webhook sent retry: %d", api.retryCount())
	}
}

func TestRejectedApprovalDiscardsPendingRefund(t *testing.T) {
	svc, api, rec := setup(t, "pending")
	ctx := context.Background()
	now := time.Now()
	if outcome, err := svc.Create(ctx, Refund{OperationID: "op-approve", AmountCents: 5000, Currency: "USD"}, 20*time.Millisecond); err != nil || outcome != Pending {
		t.Fatalf("Create() = %q, %v; want %q", outcome, err, Pending)
	}

	body, headers := signedWebhook("approval.rejected", "apr-1", now)
	if processed, err := svc.HandleApprovalWebhook(ctx, body, headers, testSecret, now); err != nil || !processed {
		t.Fatalf("rejection processed=%v err=%v; want processed", processed, err)
	}
	api.setStatus("approved")
	body, headers = signedWebhook("approval.approved", "apr-1", now)
	if processed, err := svc.HandleApprovalWebhook(ctx, body, headers, testSecret, now); err != nil || processed {
		t.Fatalf("approval after rejection processed=%v err=%v; want duplicate", processed, err)
	}
	if runs := rec.executed(); len(runs) != 0 {
		t.Fatalf("rejected refund executed: %v", runs)
	}
	if api.retryCount() != 0 {
		t.Fatalf("rejected refund sent retry: %d", api.retryCount())
	}
}

func TestPollPendingKeepsRefundWithoutRetry(t *testing.T) {
	svc, api, rec := setup(t, "pending")
	ctx := context.Background()
	if outcome, err := svc.Create(ctx, Refund{OperationID: "op-approve", AmountCents: 5000, Currency: "USD"}, 20*time.Millisecond); err != nil || outcome != Pending {
		t.Fatalf("Create() = %q, %v; want %q", outcome, err, Pending)
	}

	if outcome, err := svc.Poll(ctx, "apr-1"); err != nil || outcome != Pending {
		t.Fatalf("Poll() = %q, %v; want %q", outcome, err, Pending)
	}
	if runs := rec.executed(); len(runs) != 0 {
		t.Fatalf("pending refund executed by poll: %v", runs)
	}
	if api.retryCount() != 0 {
		t.Fatalf("poll sent retry before approval: %d", api.retryCount())
	}
}

func TestPollApprovedExecutesOnce(t *testing.T) {
	svc, api, rec := setup(t, "pending")
	ctx := context.Background()
	if outcome, err := svc.Create(ctx, Refund{OperationID: "op-approve", AmountCents: 5000, Currency: "USD"}, 20*time.Millisecond); err != nil || outcome != Pending {
		t.Fatalf("Create() = %q, %v; want %q", outcome, err, Pending)
	}
	api.setStatus("approved")

	if outcome, err := svc.Poll(ctx, "apr-1"); err != nil || outcome != Executed {
		t.Fatalf("Poll() = %q, %v; want %q", outcome, err, Executed)
	}
	if runs := rec.executed(); len(runs) != 1 || runs[0] != "op-approve" {
		t.Fatalf("executions = %v; want one op-approve", runs)
	}
	if api.retryCount() != 1 {
		t.Fatalf("retries = %d; want exactly one exact-tuple retry", api.retryCount())
	}
	if _, err := svc.Poll(ctx, "apr-1"); err == nil {
		t.Fatal("second poll for a resumed approval was accepted")
	}
	if runs := rec.executed(); len(runs) != 1 {
		t.Fatalf("second poll re-executed refund: %v", runs)
	}
}

func TestPollRejectedDiscardsRefund(t *testing.T) {
	svc, api, rec := setup(t, "pending")
	ctx := context.Background()
	if outcome, err := svc.Create(ctx, Refund{OperationID: "op-approve", AmountCents: 5000, Currency: "USD"}, 20*time.Millisecond); err != nil || outcome != Pending {
		t.Fatalf("Create() = %q, %v; want %q", outcome, err, Pending)
	}
	api.setStatus("rejected")

	if outcome, err := svc.Poll(ctx, "apr-1"); err != nil || outcome != Denied {
		t.Fatalf("Poll() = %q, %v; want %q", outcome, err, Denied)
	}
	api.setStatus("approved")
	if _, err := svc.Poll(ctx, "apr-1"); err == nil {
		t.Fatal("poll after rejection resumed the refund")
	}
	if runs := rec.executed(); len(runs) != 0 {
		t.Fatalf("rejected refund executed: %v", runs)
	}
	if api.retryCount() != 0 {
		t.Fatalf("rejected refund sent retry: %d", api.retryCount())
	}
}
