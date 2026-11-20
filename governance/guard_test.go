package governance

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestGuardSharedVectors(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/phase4-guard.json")
	if os.IsNotExist(err) {
		raw, err = os.ReadFile("../testdata/phase4-guard.json")
	}
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Profile string
		Tuple   struct {
			ExecutionID string `json:"execution_id"`
			Attempt     int
			UpstreamID  string `json:"upstream_request_id"`
		}
		Cases []struct {
			Name           string
			EvaluateStatus int             `json:"evaluate_status"`
			EvaluateBody   json.RawMessage `json:"evaluate_body"`
			CallbackError  bool            `json:"callback_error"`
			ReportStatus   int             `json:"report_status"`
			Calls          int
			Outcome        string
		}
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	if vectors.Profile != "opk.phase4-guard/1" {
		t.Fatal(vectors.Profile)
	}
	for _, v := range vectors.Cases {
		t.Run(v.Name, func(t *testing.T) {
			var reports []map[string]any
			evals := 0
			execute := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				if strings.Contains(string(body), "raw-secret") || strings.Contains(string(body), "bearer") {
					t.Error("payload/credential leak")
				}
				if r.Header.Get("Authorization") != "Bearer explicit" {
					t.Error("implicit principal used")
				}
				if r.URL.Path == "/v1/proxy/evaluate" {
					evals++
					w.WriteHeader(v.EvaluateStatus)
					w.Write(v.EvaluateBody)
					return
				}
				if r.URL.Path != "/v1/proxy/outcomes" {
					t.Error(r.URL.Path)
				}
				var report map[string]any
				json.Unmarshal(body, &report)
				reports = append(reports, report)
				w.WriteHeader(v.ReportStatus)
				w.Write([]byte(`{"recorded":true}`))
			}))
			defer server.Close()
			c := NewClient(server.URL, "configured-must-not-fallback", time.Second)
			callbackErr := errors.New("raw-secret-error")
			eid := vectors.Tuple.ExecutionID
			attempt := vectors.Tuple.Attempt
			upstream := vectors.Tuple.UpstreamID
			principal := &PrincipalContext{BearerToken: "explicit"}
			result, err := Guard(context.Background(), c, EvaluateRequest{Version: "v1", Asset: EvaluateAsset{Key: "app.svc.prod"}, OperationID: "guard-op", Transport: TransportContext{Kind: "http"}}, principal, GuardOptions{ExecutionID: &eid, Attempt: &attempt, UpstreamRequestID: &upstream}, func(context.Context) (string, error) {
				execute++
				eid = "changed"
				attempt = 9
				principal.BearerToken = "changed"
				if v.CallbackError {
					return "", callbackErr
				}
				return "raw-secret-result", nil
			})
			if execute != v.Calls || evals != 1 {
				t.Fatalf("execution/evaluate count %d/%d", execute, evals)
			}
			if v.Calls == 0 {
				if err == nil || len(reports) != 0 {
					t.Fatalf("denied callback/report: %v %v", err, reports)
				}
				return
			}
			if v.CallbackError && err != callbackErr {
				t.Fatalf("masked callback error %v", err)
			}
			if !v.CallbackError && err != nil {
				t.Fatalf("report delivery masked success %v", err)
			}
			if (result.ReportingError != nil) != (v.ReportStatus == 503) {
				t.Fatal("wrong report error", result.ReportingError)
			}
			if len(reports) != 1 || reports[0]["status"] != v.Outcome || reports[0]["execution_id"] != vectors.Tuple.ExecutionID || reports[0]["attempt"] != float64(1) {
				t.Fatalf("unstable report %v", reports)
			}
			if result.Report.CompletedAt.IsZero() {
				t.Fatal("missing completion")
			}
			if !v.CallbackError && result.Value != "raw-secret-result" {
				t.Fatal("lost value")
			}
			// Retry only the detached report, never Guard/callback. Body is identical.
			_, _ = c.ReportOperationOutcome(context.Background(), result.Report, &PrincipalContext{BearerToken: "explicit"})
			if len(reports) != 2 || !reflect.DeepEqual(reports[0], reports[1]) || execute != 1 {
				t.Fatal("report retry changed execution/report")
			}
		})
	}
}

func TestGuardPreflightAndPanic(t *testing.T) {
	reports := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/proxy/evaluate" {
			w.Write([]byte(`{"decision":"allow"}`))
			return
		}
		reports++
		var report OperationOutcomeRequest
		json.NewDecoder(r.Body).Decode(&report)
		if report.Status != "unknown" {
			t.Error(report.Status)
		}
		w.WriteHeader(503)
	}))
	defer server.Close()
	c := NewClient(server.URL, "key", time.Second)
	req := EvaluateRequest{Version: "v1", OperationID: "op", Transport: TransportContext{Kind: "http"}}
	bad := 0
	_, err := Guard(context.Background(), c, req, &PrincipalContext{BearerToken: "explicit"}, GuardOptions{Attempt: &bad}, func(context.Context) (int, error) { t.Fatal("invalid tuple invoked callback"); return 0, nil })
	if err == nil {
		t.Fatal("invalid tuple accepted")
	}
	_, err = Guard(context.Background(), c, req, nil, GuardOptions{}, func(context.Context) (int, error) { t.Fatal("missing principal invoked"); return 0, nil })
	if err == nil {
		t.Fatal("missing principal accepted")
	}
	marker := errors.New("private panic")
	defer func() {
		if recover() != marker || reports != 1 {
			t.Fatal("panic masked or not reported")
		}
	}()
	_, _ = Guard(context.Background(), c, req, &PrincipalContext{BearerToken: "explicit"}, GuardOptions{}, func(context.Context) (int, error) { panic(marker) })
}
