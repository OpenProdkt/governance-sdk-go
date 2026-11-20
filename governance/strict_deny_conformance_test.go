package governance

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type strictDenyCase struct {
	Name       string         `json:"name"`
	HTTPStatus int            `json:"http_status"`
	Body       map[string]any `json:"body"`
	Expected   struct {
		Decision       string `json:"decision"`
		Reason         string `json:"reason"`
		Allowed        bool   `json:"allowed"`
		PDPUnavailable bool   `json:"pdp_unavailable"`
	} `json:"expected"`
}

func loadStrictDenyCases(t *testing.T) []strictDenyCase {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/strict-deny-conformance.json")
	if os.IsNotExist(err) {
		raw, err = os.ReadFile("../testdata/strict-deny-conformance.json")
	}
	if err != nil {
		t.Fatalf("read strict deny conformance fixture: %v", err)
	}
	var fixture struct {
		SchemaVersion string           `json:"schema_version"`
		Cases         []strictDenyCase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("decode strict deny conformance fixture: %v", err)
	}
	if fixture.SchemaVersion != "v1" || len(fixture.Cases) == 0 {
		t.Fatalf("unexpected strict deny fixture: version=%q cases=%d", fixture.SchemaVersion, len(fixture.Cases))
	}
	return fixture.Cases
}

func strictDenyServer(t *testing.T, tc strictDenyCase) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(tc.HTTPStatus)
		_ = json.NewEncoder(w).Encode(tc.Body)
	}))
}

// assertStrictDenyOutcome checks the SDK-level verdict shared by every adapter.
func assertStrictDenyOutcome(t *testing.T, tc strictDenyCase, response DecisionResponse, err error) {
	t.Helper()
	if err == nil || response.Decision == "allow" {
		t.Fatalf("%s: must never be an allow, response=%+v err=%v", tc.Name, response, err)
	}
	var denied *AuthorizationDeniedError
	var outcome *EvaluationOutcomeError
	isDenied := errors.As(err, &denied)
	isOutcome := errors.As(err, &outcome)
	unavailable := !isDenied && (!isOutcome || outcome.Outcome == "pdp_unavailable")
	if unavailable != tc.Expected.PDPUnavailable {
		t.Fatalf("%s: pdp_unavailable=%v, want %v (err=%v)", tc.Name, unavailable, tc.Expected.PDPUnavailable, err)
	}
	if tc.Expected.PDPUnavailable {
		return
	}
	if !isDenied || denied.Outcome != "authorization_denied" || denied.HTTPStatus != http.StatusForbidden {
		t.Fatalf("%s: expected authorization_denied error, got %T %v", tc.Name, err, err)
	}
	if response.Decision != tc.Expected.Decision || response.Reason != tc.Expected.Reason {
		t.Fatalf("%s: decision/reason = %q/%q, want %q/%q", tc.Name, response.Decision, response.Reason, tc.Expected.Decision, tc.Expected.Reason)
	}
	if denied.Response.Reason != tc.Expected.Reason || denied.Response.Decision != tc.Expected.Decision {
		t.Fatalf("%s: error response lost the reason: %+v", tc.Name, denied.Response)
	}
	if wantID, _ := tc.Body["decisionId"].(string); response.DecisionID != wantID {
		t.Fatalf("%s: decisionId = %q, want %q", tc.Name, response.DecisionID, wantID)
	}
}

func TestStrictDenyConformanceAuthorizeAndProxy(t *testing.T) {
	for _, tc := range loadStrictDenyCases(t) {
		t.Run(tc.Name, func(t *testing.T) {
			server := strictDenyServer(t, tc)
			defer server.Close()
			client := NewClient(server.URL, "opk_test", time.Second)

			response, err := client.Authorize(context.Background(), AuthorizationRequest{AssetID: "ast_1", OperationID: "op_strict"})
			assertStrictDenyOutcome(t, tc, response, err)

			response, err = client.EvaluateProxy(context.Background(),
				EvaluateRequest{Version: "v1", Asset: EvaluateAsset{ID: "ast_1"}, OperationID: "op_strict", Transport: TransportContext{Kind: "http"}},
				&PrincipalContext{BearerToken: "verified-user-token"})
			assertStrictDenyOutcome(t, tc, response, err)
		})
	}
}

func TestStrictDenyConformanceHTTPMiddlewareNeverCallsHandler(t *testing.T) {
	for _, tc := range loadStrictDenyCases(t) {
		t.Run(tc.Name, func(t *testing.T) {
			server := strictDenyServer(t, tc)
			defer server.Close()
			client := NewClient(server.URL, "opk_test", time.Second)
			options := HTTPAdapterOptions{
				ResolveAsset:       func(*http.Request) (HTTPAssetReference, error) { return HTTPAssetReference{AssetID: "ast_1"}, nil },
				ResolveOperationID: func(*http.Request) (string, error) { return "op_strict", nil },
			}
			handlerCalled, outcomeCalled := false, false
			handler := client.HTTPMiddleware(options, func(w http.ResponseWriter, r *http.Request, response DecisionResponse, err error) {
				outcomeCalled = true
				assertStrictDenyOutcome(t, tc, response, err)
				w.WriteHeader(http.StatusForbidden)
			})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				handlerCalled = true
				w.WriteHeader(http.StatusNoContent)
			}))
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "http://app.test/refunds/1", nil))
			if handlerCalled || !outcomeCalled || recorder.Code != http.StatusForbidden {
				t.Fatalf("%s: handlerCalled=%v outcomeCalled=%v status=%d", tc.Name, handlerCalled, outcomeCalled, recorder.Code)
			}
		})
	}
}

func TestStrictDenyConformanceGRPCInterceptorFailsClosed(t *testing.T) {
	for _, tc := range loadStrictDenyCases(t) {
		t.Run(tc.Name, func(t *testing.T) {
			server := strictDenyServer(t, tc)
			defer server.Close()
			client := NewClient(server.URL, "opk_test", time.Second)
			interceptor := client.UnaryClientInterceptor(grpcTestAdapterOptions())
			invoked := false
			ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("idempotency-key", "op_strict"))
			err := interceptor(ctx, "/payments.PaymentService/Refund", struct{}{}, &struct{}{}, nil,
				func(context.Context, string, any, any, *grpc.ClientConn, ...grpc.CallOption) error {
					invoked = true
					return nil
				})
			if invoked {
				t.Fatalf("%s: RPC must not be invoked", tc.Name)
			}
			wantCode, wantReason := codes.PermissionDenied, "authorization_denied"
			if tc.Expected.PDPUnavailable {
				wantCode, wantReason = codes.Unavailable, "pdp_unavailable"
			}
			if status.Code(err) != wantCode {
				t.Fatalf("%s: gRPC code = %v, want %v (err=%v)", tc.Name, status.Code(err), wantCode, err)
			}
			info, ok := status.Convert(err).Details()[0].(interface{ GetReason() string })
			if !ok || info.GetReason() != wantReason {
				t.Fatalf("%s: gRPC reason = %v, want %q", tc.Name, status.Convert(err).Details(), wantReason)
			}
		})
	}
}
