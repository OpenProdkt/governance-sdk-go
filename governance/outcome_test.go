package governance

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func sampleOutcomeRequest() OperationOutcomeRequest {
	return OperationOutcomeRequest{
		OperationID: "op-1",
		Status:      "succeeded",
		CompletedAt: time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC),
		ResultHash:  "sha256:" + "0000000000000000000000000000000000000000000000000000000000000000",
	}
}

func TestReportOperationOutcomePostsWithPrincipalBearer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/proxy/outcomes" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer opk_principal" {
			t.Fatalf("Authorization = %q", got)
		}
		var body OperationOutcomeRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if body.OperationID != "op-1" || body.Status != "succeeded" {
			t.Fatalf("body = %+v", body)
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(OperationOutcomeResponse{OperationID: "op-1", Status: "succeeded", Recorded: true})
	}))
	defer server.Close()

	client := NewClient(server.URL, "opk_live_test", time.Second)
	response, err := client.ReportOperationOutcome(context.Background(), sampleOutcomeRequest(), &PrincipalContext{BearerToken: "opk_principal"})
	if err != nil {
		t.Fatalf("ReportOperationOutcome() error = %v", err)
	}
	if !response.Recorded || response.OperationID != "op-1" {
		t.Fatalf("response = %+v", response)
	}
}

func TestReportOperationOutcomeReplayIsSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(OperationOutcomeResponse{OperationID: "op-1", Status: "succeeded", Recorded: false})
	}))
	defer server.Close()

	client := NewClient(server.URL, "opk_live_test", time.Second)
	response, err := client.ReportOperationOutcome(context.Background(), sampleOutcomeRequest(), &PrincipalContext{BearerToken: "opk_principal"})
	if err != nil {
		t.Fatalf("replay should succeed, got %v", err)
	}
	if response.Recorded {
		t.Fatalf("replay should report Recorded=false")
	}
}

func TestReportOperationOutcomeConflictIsDefinitiveRejection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
	}))
	defer server.Close()

	client := NewClient(server.URL, "opk_live_test", time.Second)
	_, err := client.ReportOperationOutcome(context.Background(), sampleOutcomeRequest(), &PrincipalContext{BearerToken: "opk_principal"})
	var rejected *OperationOutcomeRejectedError
	if !errors.As(err, &rejected) || rejected.HTTPStatus != http.StatusConflict {
		t.Fatalf("error = %v, want OperationOutcomeRejectedError 409", err)
	}
}

func TestReportOperationOutcomeNotFoundIsDefinitiveRejection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := NewClient(server.URL, "opk_live_test", time.Second)
	_, err := client.ReportOperationOutcome(context.Background(), sampleOutcomeRequest(), &PrincipalContext{BearerToken: "opk_principal"})
	var rejected *OperationOutcomeRejectedError
	if !errors.As(err, &rejected) || rejected.HTTPStatus != http.StatusNotFound {
		t.Fatalf("error = %v, want OperationOutcomeRejectedError 404", err)
	}
}

func TestReportOperationOutcomeServerErrorIsRetryable(t *testing.T) {
	for _, status := range []int{http.StatusInternalServerError, http.StatusServiceUnavailable, http.StatusTooManyRequests, http.StatusRequestTimeout} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
		}))
		client := NewClient(server.URL, "opk_live_test", time.Second)
		_, err := client.ReportOperationOutcome(context.Background(), sampleOutcomeRequest(), &PrincipalContext{BearerToken: "opk_principal"})
		server.Close()
		var rejected *OperationOutcomeRejectedError
		if errors.As(err, &rejected) {
			t.Fatalf("status %d must stay retryable, got rejection %v", status, err)
		}
		if err == nil {
			t.Fatalf("status %d should return an error", status)
		}
	}
}

func TestReportOperationOutcomeRequiresPrincipal(t *testing.T) {
	client := NewClient("http://127.0.0.1:1", "opk_live_test", time.Second)
	_, err := client.ReportOperationOutcome(context.Background(), sampleOutcomeRequest(), nil)
	var invalid *InvalidAuthorizationInputError
	if !errors.As(err, &invalid) {
		t.Fatalf("error = %v, want InvalidAuthorizationInputError", err)
	}
}

func TestGetOperationStatusIsReadOnlyAndPreservesRecoveryFields(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/proxy/operations/op-1" || r.Header.Get("Authorization") != "Bearer principal" {
			t.Errorf("unexpected status request: %s %s", r.Method, r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"operation_id":"op-1","approval_status":"consumed","grant_expires_at":"2026-10-18T12:02:00Z","reason":"execution_unknown","next_action":"reconcile_upstream","outcome":{"operation_id":"op-1","status":"unknown","completed_at":"2026-10-18T12:01:00Z"}}`))
	}))
	defer server.Close()
	client := NewClient(server.URL, "fallback", time.Second)
	status, err := client.GetOperationStatus(context.Background(), "op-1", &PrincipalContext{BearerToken: "principal"})
	if err != nil || status.NextAction != "reconcile_upstream" || status.GrantExpiresAt == nil || status.Outcome == nil || status.Outcome.Status != "unknown" {
		t.Fatalf("recovery fields missing: %+v err=%v", status, err)
	}
}
