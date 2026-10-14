package governance

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestHTTPMiddlewareBuildsCanonicalContextFromTrustedResolvers(t *testing.T) {
	var wireBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer verified-user-token" {
			t.Fatalf("expected adapter-verified principal header, got %q", got)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read evaluation body: %v", err)
		}
		if strings.Contains(string(body), "verified-user-token") || strings.Contains(string(body), "principal_context") {
			t.Fatalf("principal credential must not be serialized: %s", body)
		}
		if err := json.Unmarshal(body, &wireBody); err != nil {
			t.Fatalf("decode evaluation body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(DecisionResponse{Decision: "allow", DecisionID: "dec_http"})
	}))
	defer server.Close()

	client := NewClient(server.URL, "opk_service_key", time.Second)
	options := HTTPAdapterOptions{
		ResolveAsset: func(*http.Request) (HTTPAssetReference, error) {
			return HTTPAssetReference{AssetIdentity: &AssetIdentity{Application: "billing", Service: "refund-api", Environment: "production"}}, nil
		},
		ResolveMetadata: func(*http.Request) (any, error) {
			return struct {
				Amount int    `json:"amount"`
				Actor  string `json:"actor"`
			}{Amount: 12, Actor: "untrusted-metadata"}, nil
		},
		ResolvePrincipalContext: func(*http.Request) (*PrincipalContext, error) {
			return &PrincipalContext{BearerToken: "verified-user-token"}, nil
		},
		ResolveHost:     func(*http.Request) string { return "billing.internal" },
		ResolveRouteID:  func(*http.Request) string { return "refund-by-id" },
		HeaderAllowlist: []string{"X-Request-ID"},
	}

	var handlerCalled bool
	middleware := client.HTTPMiddleware(options, nil)
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		decision, ok := DecisionFromHTTPRequest(r)
		if !ok || decision.Decision != "allow" {
			t.Fatalf("expected allow decision in handler context, decision=%+v ok=%v", decision, ok)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequest(http.MethodPost, "http://untrusted-host.test/refunds/123", nil)
	request.Header.Set("Idempotency-Key", "refund-123")
	request.Header.Set("X-Request-ID", "req-123")
	request.Header.Set("X-OpenProdkt-Principal", "spoofed-user")
	request.Header.Set("Authorization", "Bearer spoofed-token")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusNoContent || !handlerCalled {
		t.Fatalf("middleware did not continue allowed request, status=%d handlerCalled=%v body=%s", response.Code, handlerCalled, response.Body.String())
	}
	if wireBody["operation_id"] != "refund-123" || wireBody["asset"].(map[string]any)["key"] != "billing.refund-api.production" {
		t.Fatalf("unexpected canonical operation or asset: %+v", wireBody)
	}
	if wireBody["metadata"].(map[string]any)["actor"] != "untrusted-metadata" {
		t.Fatalf("application metadata should remain metadata: %+v", wireBody["metadata"])
	}
	transport := wireBody["transport"].(map[string]any)
	if transport["kind"] != "http" {
		t.Fatalf("expected tagged HTTP transport, got %+v", transport)
	}
	httpContext := transport["http"].(map[string]any)
	if httpContext["method"] != "POST" || httpContext["path"] != "/refunds/123" || httpContext["host"] != "billing.internal" || httpContext["route_id"] != "refund-by-id" {
		t.Fatalf("unexpected normalized HTTP context: %+v", httpContext)
	}
	if httpContext["headers"].(map[string]any)["x-request-id"] != "req-123" || len(httpContext["headers"].(map[string]any)) != 1 {
		t.Fatalf("only explicitly allowlisted headers should be forwarded: %+v", httpContext["headers"])
	}
}

func TestHTTPAdapterMatchesSharedPEPTransportVector(t *testing.T) {
	fixtureBytes, err := os.ReadFile("../../testdata/pep-conformance.json")
	if err != nil {
		t.Fatalf("read PEP conformance fixture: %v", err)
	}
	var fixture struct {
		HTTPTransport struct {
			Input struct {
				Method  string            `json:"method"`
				Path    string            `json:"path"`
				Host    string            `json:"host"`
				RouteID string            `json:"route_id"`
				Headers map[string]string `json:"headers"`
			} `json:"input"`
			Expected TransportContext `json:"expected"`
		} `json:"http_transport"`
	}
	if err := json.Unmarshal(fixtureBytes, &fixture); err != nil {
		t.Fatalf("decode PEP conformance fixture: %v", err)
	}
	var wireRequest EvaluateRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&wireRequest); err != nil {
			t.Fatalf("decode evaluation request: %v", err)
		}
		_ = json.NewEncoder(w).Encode(DecisionResponse{Decision: "allow"})
	}))
	defer server.Close()
	client := NewClient(server.URL, "opk_test", time.Second)
	input := fixture.HTTPTransport.Input
	request := httptest.NewRequest(strings.ToUpper(input.Method), "https://untrusted.invalid"+input.Path, nil)
	for name, value := range input.Headers {
		request.Header.Set(name, value)
	}
	_, err = client.AuthorizeHTTPRequest(request.Context(), request, HTTPAdapterOptions{
		ResolveAsset: func(*http.Request) (HTTPAssetReference, error) {
			return HTTPAssetReference{AssetID: "ast_vector"}, nil
		},
		ResolveOperationID: func(*http.Request) (string, error) { return "op_vector", nil },
		ResolveHost:        func(*http.Request) string { return input.Host },
		ResolveRouteID:     func(*http.Request) string { return input.RouteID },
		HeaderAllowlist:    []string{"x-request-id"},
	})
	if err != nil {
		t.Fatalf("authorize with shared HTTP vector: %v", err)
	}
	if !reflect.DeepEqual(wireRequest.Transport, fixture.HTTPTransport.Expected) {
		t.Fatalf("HTTP transport differs from shared fixture: got=%+v want=%+v", wireRequest.Transport, fixture.HTTPTransport.Expected)
	}
}

func TestHTTPAdapterSharedPEPConformanceVector(t *testing.T) {
	fixtureBytes, err := os.ReadFile("../../testdata/pep-conformance.json")
	if err != nil {
		t.Fatalf("read PEP conformance fixture: %v", err)
	}
	var fixture struct {
		HTTPTransport struct {
			Input struct {
				Method  string            `json:"method"`
				Path    string            `json:"path"`
				Host    string            `json:"host"`
				Scheme  string            `json:"scheme"`
				RouteID string            `json:"route_id"`
				Headers map[string]string `json:"headers"`
			} `json:"input"`
			Expected TransportContext `json:"expected"`
		} `json:"http_transport"`
	}
	if err := json.Unmarshal(fixtureBytes, &fixture); err != nil {
		t.Fatalf("decode PEP conformance fixture: %v", err)
	}
	var wireRequest EvaluateRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&wireRequest); err != nil {
			t.Fatalf("decode evaluation request: %v", err)
		}
		_ = json.NewEncoder(w).Encode(DecisionResponse{Decision: "allow"})
	}))
	defer server.Close()
	client := NewClient(server.URL, "opk_test", time.Second)
	input := fixture.HTTPTransport.Input
	request := httptest.NewRequest(strings.ToUpper(input.Method), "https://untrusted.invalid"+input.Path, nil)
	for name, value := range input.Headers {
		request.Header.Set(name, value)
	}
	_, err = client.AuthorizeHTTPRequest(request.Context(), request, HTTPAdapterOptions{
		ResolveAsset: func(*http.Request) (HTTPAssetReference, error) {
			return HTTPAssetReference{AssetID: "ast_vector"}, nil
		},
		ResolveOperationID: func(*http.Request) (string, error) { return "op_vector", nil },
		ResolveHost:        func(*http.Request) string { return input.Host },
		ResolveRouteID:     func(*http.Request) string { return input.RouteID },
		HeaderAllowlist:    []string{"x-request-id"},
	})
	if err != nil {
		t.Fatalf("authorize with shared HTTP vector: %v", err)
	}
	if !reflect.DeepEqual(wireRequest.Transport, fixture.HTTPTransport.Expected) {
		t.Fatalf("HTTP transport differs from shared fixture: got=%+v want=%+v", wireRequest.Transport, fixture.HTTPTransport.Expected)
	}
}
