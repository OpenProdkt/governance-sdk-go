package governance

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func signedApprovalWebhook(t *testing.T, eventType ApprovalWebhookEventType, eventID string) ([]byte, http.Header, time.Time) {
	t.Helper()
	secret := "whsec_test"
	timestamp := "2026-10-04T12:00:00Z"
	body, err := json.Marshal(map[string]any{
		"eventId": eventID, "eventType": eventType, "organizationId": "org_1", "aggregateId": "apr_1",
		"data": map[string]any{"approvalId": "apr_1", "operation_id": "refund-1", "status": "approved"},
	})
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(timestamp + "."))
	_, _ = mac.Write(body)
	headers := make(http.Header)
	headers.Set("X-OpenProdkt-Event-Id", eventID)
	headers.Set("X-OpenProdkt-Timestamp", timestamp)
	headers.Set("X-OpenProdkt-Signature", "v1=sha256="+hex.EncodeToString(mac.Sum(nil)))
	return body, headers, time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
}

func TestVerifyApprovalWebhookRawBodyAndLifecycleEvents(t *testing.T) {
	for _, eventType := range []ApprovalWebhookEventType{
		ApprovalWebhookPending, ApprovalWebhookApproved, ApprovalWebhookRejected, ApprovalWebhookExpired, ApprovalWebhookRevoked,
	} {
		t.Run(string(eventType), func(t *testing.T) {
			body, headers, now := signedApprovalWebhook(t, eventType, "obx_1")
			event, err := VerifyApprovalWebhook(body, headers, "whsec_test", WebhookVerificationOptions{Now: now})
			if err != nil || event.EventID != "obx_1" || event.EventType != eventType || event.ApprovalID() != "apr_1" {
				t.Fatalf("unexpected verified webhook event=%+v err=%v", event, err)
			}
		})
	}
}

func TestVerifyApprovalWebhookSharedPEPVector(t *testing.T) {
	fixtureBytes, err := os.ReadFile("../../testdata/pep-conformance.json")
	if err != nil {
		t.Fatalf("read PEP conformance fixture: %v", err)
	}
	var fixture struct {
		Webhook struct {
			Secret    string `json:"secret"`
			Timestamp string `json:"timestamp"`
			RawBody   string `json:"raw_body"`
			EventID   string `json:"event_id"`
			Signature string `json:"signature"`
		} `json:"webhook"`
	}
	if err := json.Unmarshal(fixtureBytes, &fixture); err != nil {
		t.Fatalf("decode PEP conformance fixture: %v", err)
	}
	headers := make(http.Header)
	headers.Set("X-OpenProdkt-Event-Id", fixture.Webhook.EventID)
	headers.Set("X-OpenProdkt-Timestamp", fixture.Webhook.Timestamp)
	headers.Set("X-OpenProdkt-Signature", fixture.Webhook.Signature)
	now, err := time.Parse(time.RFC3339, fixture.Webhook.Timestamp)
	if err != nil {
		t.Fatal(err)
	}
	event, err := VerifyApprovalWebhook([]byte(fixture.Webhook.RawBody), headers, fixture.Webhook.Secret, WebhookVerificationOptions{Now: now})
	if err != nil || event.EventID != fixture.Webhook.EventID || event.ApprovalID() != "apr_vector_1" {
		t.Fatalf("shared PEP webhook vector failed: event=%+v err=%v", event, err)
	}
	rotated, err := VerifyApprovalWebhookWithSecrets(
		[]byte(fixture.Webhook.RawBody), headers,
		[]string{"pep-conformance-rotated", fixture.Webhook.Secret}, WebhookVerificationOptions{Now: now},
	)
	if err != nil || rotated.EventID != fixture.Webhook.EventID {
		t.Fatalf("shared webhook vector did not verify during secret rotation: event=%+v err=%v", rotated, err)
	}
}

func TestVerifyApprovalWebhookRejectsTamperReplayAndMalformedInput(t *testing.T) {
	body, headers, now := signedApprovalWebhook(t, ApprovalWebhookApproved, "obx_1")
	if _, err := VerifyApprovalWebhook(body, headers, "wrong", WebhookVerificationOptions{Now: now}); err == nil {
		t.Fatal("expected wrong secret to fail")
	}
	if _, err := VerifyApprovalWebhook(append(body, ' '), headers, "whsec_test", WebhookVerificationOptions{Now: now}); err == nil {
		t.Fatal("expected raw-body tampering to fail")
	}
	if _, err := VerifyApprovalWebhook(body, headers, "whsec_test", WebhookVerificationOptions{Now: now.Add(6 * time.Minute)}); err == nil || !strings.Contains(err.Error(), "replay window") {
		t.Fatalf("expected stale timestamp rejection, got %v", err)
	}
	wrongEventID := headers.Clone()
	wrongEventID.Set("X-OpenProdkt-Event-Id", "obx_other")
	if _, err := VerifyApprovalWebhook(body, wrongEventID, "whsec_test", WebhookVerificationOptions{Now: now}); err == nil {
		t.Fatal("expected mismatched event ID rejection")
	}
	wrongVersion := headers.Clone()
	wrongVersion.Set("X-OpenProdkt-Signature", "v2=sha256=deadbeef")
	if _, err := VerifyApprovalWebhook(body, wrongVersion, "whsec_test", WebhookVerificationOptions{Now: now}); err == nil {
		t.Fatal("expected unsupported signature version rejection")
	}
	if _, err := VerifyApprovalWebhook(make([]byte, maxApprovalWebhookBodyBytes+1), headers, "whsec_test", WebhookVerificationOptions{Now: now}); err == nil {
		t.Fatal("expected oversized webhook rejection")
	}
	if _, err := VerifyApprovalWebhook(make([]byte, maxApprovalWebhookBodyBytes+1), headers, "whsec_test", WebhookVerificationOptions{Now: now, MaxBodyBytes: maxApprovalWebhookBodyBytes * 2}); err == nil {
		t.Fatal("configured webhook body limit must not exceed the hard cap")
	}
}

func TestDispatchApprovalWebhookDelegatesDurableDeduplication(t *testing.T) {
	body, headers, now := signedApprovalWebhook(t, ApprovalWebhookApproved, "obx_1")
	seen := map[string]bool{}
	dispatch := func(_ context.Context, event ApprovalWebhookEvent) (bool, error) {
		if seen[event.EventID] {
			return false, nil
		}
		seen[event.EventID] = true
		return true, nil
	}
	options := WebhookVerificationOptions{Now: now}
	first, err := DispatchApprovalWebhook(context.Background(), body, headers, "whsec_test", options, dispatch)
	if err != nil || first.Duplicate || first.Event.EventID != "obx_1" {
		t.Fatalf("unexpected first webhook dispatch=%+v err=%v", first, err)
	}
	duplicate, err := DispatchApprovalWebhook(context.Background(), body, headers, "whsec_test", options, dispatch)
	if err != nil || !duplicate.Duplicate || duplicate.Event.EventID != "obx_1" {
		t.Fatalf("unexpected duplicate webhook dispatch=%+v err=%v", duplicate, err)
	}
}

func TestApprovalWebhookHTTPHandlerVerifiesAndDeduplicates(t *testing.T) {
	fixtureBytes, err := os.ReadFile("../../testdata/pep-conformance.json")
	if err != nil {
		t.Fatalf("read PEP conformance fixture: %v", err)
	}
	var fixture struct {
		Webhook struct {
			Secret    string `json:"secret"`
			Timestamp string `json:"timestamp"`
			RawBody   string `json:"raw_body"`
			EventID   string `json:"event_id"`
			Signature string `json:"signature"`
		} `json:"webhook"`
	}
	if err := json.Unmarshal(fixtureBytes, &fixture); err != nil {
		t.Fatalf("decode PEP conformance fixture: %v", err)
	}
	now, err := time.Parse(time.RFC3339, fixture.Webhook.Timestamp)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	handler := NewApprovalWebhookHandler([]string{"rotated-secret", fixture.Webhook.Secret}, WebhookVerificationOptions{Now: now}, func(_ context.Context, event ApprovalWebhookEvent) (bool, error) {
		if seen[event.EventID] {
			return false, nil
		}
		seen[event.EventID] = true
		return true, nil
	})
	request := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/webhooks/approvals", strings.NewReader(body))
		req.Header.Set("X-OpenProdkt-Event-Id", fixture.Webhook.EventID)
		req.Header.Set("X-OpenProdkt-Timestamp", fixture.Webhook.Timestamp)
		req.Header.Set("X-OpenProdkt-Signature", fixture.Webhook.Signature)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		return response
	}
	first := request(fixture.Webhook.RawBody)
	duplicate := request(fixture.Webhook.RawBody)
	invalid := request(fixture.Webhook.RawBody + " ")
	if first.Code != http.StatusOK || !strings.Contains(first.Body.String(), `"duplicate":false`) {
		t.Fatalf("unexpected initial webhook response %d %s", first.Code, first.Body.String())
	}
	if duplicate.Code != http.StatusOK || !strings.Contains(duplicate.Body.String(), `"duplicate":true`) {
		t.Fatalf("unexpected duplicate webhook response %d %s", duplicate.Code, duplicate.Body.String())
	}
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("tampered webhook expected 400, got %d", invalid.Code)
	}
}
