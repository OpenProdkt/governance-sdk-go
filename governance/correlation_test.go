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
	"testing"
	"time"
)

type phase2Vectors struct {
	Profile     string `json:"profile"`
	Traceparent []struct {
		Name    string
		Headers []string
		Valid   bool
	} `json:"traceparent"`
	OutcomeFields []struct {
		Name       string
		FieldsJSON string `json:"fields_json"`
		Valid      bool
	} `json:"outcome_fields"`
	SDKRequests []struct {
		Name   string
		Fields json.RawMessage `json:"outcome_fields"`
	} `json:"sdk_requests"`
	Forbidden []struct {
		Name      string
		Transport TransportContext
	} `json:"sdk_forbidden_transports"`
}

func loadPhase2(t *testing.T) phase2Vectors {
	t.Helper()
	data, err := os.ReadFile("../../testdata/phase2-correlation.json")
	if os.IsNotExist(err) {
		data, err = os.ReadFile("../testdata/phase2-correlation.json")
	}
	if err != nil {
		t.Fatal(err)
	}
	var vectors phase2Vectors
	if err = json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	if vectors.Profile != "opk.phase2-correlation/1" {
		t.Fatal("unexpected profile")
	}
	return vectors
}

func TestPhase2TraceRequestCapture(t *testing.T) {
	for _, vector := range loadPhase2(t).Traceparent {
		t.Run(vector.Name, func(t *testing.T) {
			trace := strings.Join(vector.Headers, ",")
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				expected := ""
				if vector.Valid {
					expected = trace
				}
				if r.Header.Get("traceparent") != expected {
					t.Errorf("trace header = %q", r.Header.Get("traceparent"))
				}
				if r.Header.Get("Authorization") != "Bearer explicit-principal" {
					t.Error("principal fallback")
				}
				body, _ := io.ReadAll(r.Body)
				lower := strings.ToLower(string(body))
				for _, forbidden := range []string{"traceparent", "authorization", "arguments", "execution_id", "attempt", "upstream_request_id", "explicit-principal"} {
					if strings.Contains(lower, forbidden) {
						t.Errorf("JSON contains forbidden field: %s", forbidden)
					}
				}
				w.Header().Set("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-1111111111111111-01")
				w.Header().Set("Content-Type", "application/json")
				io.WriteString(w, `{"decision":"allow","operation_id":"op-1"}`)
			}))
			defer server.Close()
			client := NewClient(server.URL, "must-not-fallback", time.Second)
			principal := &PrincipalContext{BearerToken: "explicit-principal"}
			for _, proxy := range []bool{false, true} {
				var result DecisionResponse
				var err error
				if proxy {
					result, err = client.EvaluateProxy(context.Background(), EvaluateRequest{Version: "v1", Asset: EvaluateAsset{Key: "app.svc.prod"}, OperationID: "op-1", Transport: TransportContext{Kind: "http"}, Traceparent: trace}, principal)
				} else {
					result, err = client.Authorize(context.Background(), AuthorizationRequest{AssetKey: "app.svc.prod", OperationID: "op-1", PrincipalContext: principal, Traceparent: trace})
				}
				if err != nil {
					t.Fatal(err)
				}
				if result.Traceparent == "" {
					t.Fatal("missing response trace")
				}
				encoded, _ := json.Marshal(result)
				if strings.Contains(string(encoded), "traceparent") {
					t.Fatal("response JSON changed")
				}
			}
			if calls != 2 {
				t.Fatalf("calls = %d", calls)
			}
		})
	}
}

func TestPhase2OutcomeVectors(t *testing.T) {
	for _, vector := range loadPhase2(t).OutcomeFields {
		t.Run(vector.Name, func(t *testing.T) {
			var fields map[string]json.RawMessage
			if err := json.Unmarshal([]byte(vector.FieldsJSON), &fields); err != nil {
				t.Fatal(err)
			}
			var request OperationOutcomeRequest
			err := json.Unmarshal([]byte(vector.FieldsJSON), &request)
			// Typed pointer inputs cannot represent explicit JSON null: nil means omission.
			for key, raw := range fields {
				if string(raw) == "null" {
					encoded, marshalErr := json.Marshal(request)
					if marshalErr != nil || strings.Contains(string(encoded), `"`+key+`"`) {
						t.Fatal("nil optional field must be omitted")
					}
					return
				}
			}
			if err == nil {
				err = validateOutcomeCorrelation(request)
			}
			if (err == nil) != vector.Valid {
				t.Fatalf("valid=%v, error=%v", vector.Valid, err)
			}
		})
	}
}

func TestPhase2OutcomeRequestCapture(t *testing.T) {
	for _, vector := range loadPhase2(t).SDKRequests {
		t.Run(vector.Name, func(t *testing.T) {
			calls := 0
			var first string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.URL.Path != "/v1/proxy/outcomes" || r.Header.Get("Authorization") != "Bearer principal" {
					t.Error("invalid route/principal")
				}
				body, _ := io.ReadAll(r.Body)
				if calls == 1 {
					first = string(body)
				} else if string(body) != first {
					t.Error("report retry changed tuple")
				}
				var actual map[string]json.RawMessage
				json.Unmarshal(body, &actual)
				var expected map[string]json.RawMessage
				json.Unmarshal(vector.Fields, &expected)
				for _, key := range []string{"execution_id", "attempt", "upstream_request_id"} {
					if string(actual[key]) != string(expected[key]) {
						t.Errorf("field %s: %s != %s", key, actual[key], expected[key])
					}
				}
				for _, key := range []string{"execution", "traceparent", "authorization", "arguments"} {
					if _, ok := actual[key]; ok {
						t.Errorf("forbidden JSON field %s", key)
					}
				}
				io.WriteString(w, `{"operation_id":"op-1","status":"succeeded","recorded":`+map[bool]string{true: "true", false: "false"}[calls == 1]+`}`)
			}))
			defer server.Close()
			var request OperationOutcomeRequest
			if err := json.Unmarshal(vector.Fields, &request); err != nil {
				t.Fatal(err)
			}
			request.OperationID = "op-1"
			request.Status = "succeeded"
			request.CompletedAt = time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
			client := NewClient(server.URL, "fallback", time.Second)
			for i := 0; i < 2; i++ {
				result, err := client.ReportOperationOutcome(context.Background(), request, &PrincipalContext{BearerToken: "principal"})
				if err != nil {
					t.Fatal(err)
				}
				if result.Recorded != (i == 0) {
					t.Fatal("first outcome response changed")
				}
			}
			if calls != 2 {
				t.Fatal("unexpected automatic report retry")
			}
		})
	}
}

func TestPhase2NoCredentialFallbackOrRawArguments(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; t.Error("invalid request reached server") }))
	defer server.Close()
	client := NewClient(server.URL, "configured-key", time.Second)
	for _, principal := range []*PrincipalContext{nil, {}, {BearerToken: "\r\n"}} {
		if _, err := client.EvaluateProxy(context.Background(), EvaluateRequest{OperationID: "op"}, principal); err == nil {
			t.Fatal("missing principal accepted")
		}
		if _, err := client.ReportOperationOutcome(context.Background(), OperationOutcomeRequest{}, principal); err == nil {
			t.Fatal("missing outcome principal accepted")
		}
	}
	for _, vector := range loadPhase2(t).Forbidden {
		t.Run(vector.Name, func(t *testing.T) {
			principal := &PrincipalContext{BearerToken: "principal"}
			if _, err := client.EvaluateProxy(context.Background(), EvaluateRequest{OperationID: "op", Transport: vector.Transport}, principal); err == nil {
				t.Fatal("unsafe proxy transport accepted")
			}
			if _, err := client.Authorize(context.Background(), AuthorizationRequest{OperationID: "op", AssetKey: "app.svc.prod", Transport: &vector.Transport}); err == nil {
				t.Fatal("unsafe authorize transport accepted")
			}
		})
	}
	zero := 0
	empty := ""
	uppercase := "0196F111-1234-7123-8123-123456789ABC"
	for _, request := range []OperationOutcomeRequest{{Attempt: &zero}, {ExecutionID: &empty}, {ExecutionID: &uppercase}, {UpstreamRequestID: &empty}} {
		if _, err := client.ReportOperationOutcome(context.Background(), request, &PrincipalContext{BearerToken: "principal"}); err == nil {
			t.Fatal("invalid outcome sent")
		}
	}
	if calls != 0 {
		t.Fatal("unexpected network call")
	}
}

func TestPhase2ResponseTraceOnEvaluationErrors(t *testing.T) {
	for _, status := range []int{202, 403, 409, 503} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("traceparent", "response-context")
			w.WriteHeader(status)
			if status == 202 {
				io.WriteString(w, `{"decision":"approval_required","approvalId":"approval","payload_hash":"sha256:`+strings.Repeat("a", 64)+`","approval_expires_at":"2026-11-09T12:00:00Z"}`)
			} else {
				io.WriteString(w, `{"decision":"deny","code":"test"}`)
			}
		}))
		client := NewClient(server.URL, "key", time.Second)
		_, err := client.EvaluateProxy(context.Background(), EvaluateRequest{OperationID: "op", Transport: TransportContext{Kind: "http"}}, &PrincipalContext{BearerToken: "principal"})
		var outcome *EvaluationOutcomeError
		if !errors.As(err, &outcome) || outcome.Response.Traceparent != "response-context" {
			t.Fatalf("status %d lost trace: %v", status, err)
		}
		server.Close()
	}
}

func TestPhase2OutcomeRejectionClassification(t *testing.T) {
	for _, status := range []int{400, 401, 403, 404, 409, 408, 429, 500, 503} {
		calls := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(status); io.WriteString(w, `{}`) }))
		_, err := NewClient(server.URL, "fallback", time.Second).ReportOperationOutcome(context.Background(), OperationOutcomeRequest{}, &PrincipalContext{BearerToken: "principal"})
		var rejected *OperationOutcomeRejectedError
		definitive := status >= 400 && status < 500 && status != 408 && status != 429
		if errors.As(err, &rejected) != definitive || err == nil || calls != 1 {
			t.Fatalf("status %d classification/retry incorrect: %v", status, err)
		}
		server.Close()
	}
}
