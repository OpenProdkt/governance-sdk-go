package governance

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestGRPCUnaryClientInterceptorUsesCanonicalTrustedContext(t *testing.T) {
	var wireRequest EvaluateRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer verified-user-token" {
			t.Fatalf("expected adapter-verified principal header, got %q", got)
		}
		if err := json.NewDecoder(r.Body).Decode(&wireRequest); err != nil {
			t.Fatalf("decode evaluation request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(DecisionResponse{Decision: "allow", DecisionID: "dec_grpc"})
	}))
	defer server.Close()

	client := NewClient(server.URL, "opk_service_key", time.Second)
	interceptor := client.UnaryClientInterceptor(grpcTestAdapterOptions())
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs(
		"idempotency-key", "refund-123",
		"x-request-region", "west",
		"authorization", "Bearer spoofed-token",
		"x-openprodkt-principal", "spoofed-user",
	))
	invoked := false
	err := interceptor(ctx, "/payments.PaymentService/Refund", struct{}{}, &struct{}{}, nil,
		func(callContext context.Context, _ string, _, _ any, _ *grpc.ClientConn, _ ...grpc.CallOption) error {
			invoked = true
			decision, ok := GRPCDecisionFromContext(callContext)
			if !ok || decision.Decision != "allow" {
				t.Fatalf("expected allow decision in client context, decision=%+v ok=%v", decision, ok)
			}
			return nil
		},
	)
	if err != nil || !invoked {
		t.Fatalf("expected unary RPC invocation after allow, invoked=%v err=%v", invoked, err)
	}
	if wireRequest.OperationID != "refund-123" || wireRequest.Asset.Key != "billing.refund-api.production" {
		t.Fatalf("unexpected operation or asset: %+v", wireRequest)
	}
	if wireRequest.Transport.GRPC == nil || wireRequest.Transport.GRPC.FullMethod != "/payments.PaymentService/Refund" || wireRequest.Transport.GRPC.Service != "payments.PaymentService" || wireRequest.Transport.GRPC.Method != "Refund" || wireRequest.Transport.GRPC.RPCType != "unary" {
		t.Fatalf("unexpected gRPC transport: %+v", wireRequest.Transport)
	}
	if got := wireRequest.Transport.GRPC.Metadata["x-request-region"]; got != "west" || len(wireRequest.Transport.GRPC.Metadata) != 1 {
		t.Fatalf("only allowlisted metadata should be forwarded, got %+v", wireRequest.Transport.GRPC.Metadata)
	}
	encoded, err := json.Marshal(wireRequest)
	if err != nil || strings.Contains(string(encoded), "verified-user-token") || strings.Contains(string(encoded), "spoofed-user") {
		t.Fatalf("credential/spoofed principal leaked into canonical body: %s err=%v", encoded, err)
	}
}

func TestGRPCBidirectionalInterceptorsBlockBeforeStreamEstablishment(t *testing.T) {
	authorizationCalls := 0
	expiresAt := time.Now().UTC().Add(time.Hour)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		authorizationCalls++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(DecisionResponse{
			Decision: "approval_required", DecisionID: "dec_pending", ApprovalID: "apr_pending",
			PayloadHash: "sha256:" + strings.Repeat("c", 64), ApprovalExpiresAt: &expiresAt,
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "opk_service_key", time.Second)
	options := grpcTestAdapterOptions()
	streamDescription := &grpc.StreamDesc{ClientStreams: true, ServerStreams: true}
	streamerCalled := false
	streamContext := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("idempotency-key", "refund-stream"))
	clientStream, err := client.StreamClientInterceptor(options)(
		streamContext, streamDescription, nil, "/payments.PaymentService/RefundStream",
		func(context.Context, *grpc.StreamDesc, *grpc.ClientConn, string, ...grpc.CallOption) (grpc.ClientStream, error) {
			streamerCalled = true
			return nil, nil
		},
	)
	if clientStream != nil || streamerCalled || status.Code(err) != codes.PermissionDenied || authorizationCalls != 1 {
		t.Fatalf("pending client stream must be blocked before streamer, stream=%v called=%v code=%s calls=%d err=%v", clientStream, streamerCalled, status.Code(err), authorizationCalls, err)
	}

	serverHandlerCalled := false
	serverStream := &grpcTestServerStream{ctx: metadata.NewIncomingContext(context.Background(), metadata.Pairs("idempotency-key", "refund-server-stream"))}
	err = client.StreamServerInterceptor(options)(
		struct{}{}, serverStream,
		&grpc.StreamServerInfo{FullMethod: "/payments.PaymentService/RefundStream", IsClientStream: true, IsServerStream: true},
		func(any, grpc.ServerStream) error {
			serverHandlerCalled = true
			return nil
		},
	)
	if serverHandlerCalled || status.Code(err) != codes.PermissionDenied || authorizationCalls != 2 {
		t.Fatalf("pending server stream must be blocked before handler, called=%v code=%s calls=%d err=%v", serverHandlerCalled, status.Code(err), authorizationCalls, err)
	}
}

func TestGRPCStreamInterceptorsDenyBeforeStreamEstablishment(t *testing.T) {
	authorizationCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		authorizationCalls++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(DecisionResponse{Decision: "deny", Reason: "policy_denied"})
	}))
	defer server.Close()

	client := NewClient(server.URL, "opk_service_key", time.Second)
	options := grpcTestAdapterOptions()
	streamDescription := &grpc.StreamDesc{ClientStreams: true, ServerStreams: true}
	streamerCalled := false
	streamContext := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("idempotency-key", "refund-denied-stream"))
	clientStream, err := client.StreamClientInterceptor(options)(
		streamContext, streamDescription, nil, "/payments.PaymentService/RefundStream",
		func(context.Context, *grpc.StreamDesc, *grpc.ClientConn, string, ...grpc.CallOption) (grpc.ClientStream, error) {
			streamerCalled = true
			return nil, nil
		},
	)
	if clientStream != nil || streamerCalled || status.Code(err) != codes.PermissionDenied || authorizationCalls != 1 {
		t.Fatalf("denied client stream must not open, stream=%v called=%v code=%s calls=%d err=%v", clientStream, streamerCalled, status.Code(err), authorizationCalls, err)
	}

	serverHandlerCalled := false
	serverStream := &grpcTestServerStream{ctx: metadata.NewIncomingContext(context.Background(), metadata.Pairs("idempotency-key", "refund-denied-server-stream"))}
	err = client.StreamServerInterceptor(options)(
		struct{}{}, serverStream,
		&grpc.StreamServerInfo{FullMethod: "/payments.PaymentService/RefundStream", IsClientStream: true, IsServerStream: true},
		func(any, grpc.ServerStream) error {
			serverHandlerCalled = true
			return nil
		},
	)
	if serverHandlerCalled || status.Code(err) != codes.PermissionDenied || authorizationCalls != 2 {
		t.Fatalf("denied server stream must not reach handler, called=%v code=%s calls=%d err=%v", serverHandlerCalled, status.Code(err), authorizationCalls, err)
	}
}

func TestGRPCTypedOutcomesUseCanonicalCodesAndBoundedDetails(t *testing.T) {
	expected := map[string]codes.Code{
		"authorization_denied":    codes.PermissionDenied,
		"pending_approval":        codes.PermissionDenied,
		"approval_expired":        codes.PermissionDenied,
		"approval_rejected":       codes.PermissionDenied,
		"approval_revoked":        codes.PermissionDenied,
		"approval_consumed":       codes.PermissionDenied,
		"approval_not_found":      codes.NotFound,
		"operation_conflict":      codes.AlreadyExists,
		"asset_identity_conflict": codes.AlreadyExists,
		"quota_exceeded":          codes.ResourceExhausted,
		"invalid_request":         codes.InvalidArgument,
		"configuration_error":     codes.FailedPrecondition,
		"pdp_unavailable":         codes.Unavailable,
	}
	for outcome, expectedCode := range expected {
		t.Run(outcome, func(t *testing.T) {
			mapped := grpcAuthorizationError(&EvaluationOutcomeError{
				HTTPStatus: http.StatusForbidden, Outcome: outcome,
				Response: DecisionResponse{Error: "secret bearer token must not leak"},
			})
			if status.Code(mapped) != expectedCode {
				t.Fatalf("unexpected gRPC status: got=%s want=%s", status.Code(mapped), expectedCode)
			}
			converted := status.Convert(mapped)
			if strings.Contains(converted.Message(), "secret") || len(converted.Message()) > 128 {
				t.Fatalf("unsafe or unbounded gRPC status message: %q", converted.Message())
			}
			info, ok := converted.Details()[0].(*errdetails.ErrorInfo)
			if !ok || info.Reason != outcome || info.Domain != "governance.openprodkt" {
				t.Fatalf("unexpected structured status details: %+v", converted.Details())
			}
		})
	}
}

func TestGRPCSharedPEPConformanceVectors(t *testing.T) {
	fixtureBytes, err := os.ReadFile("../../testdata/pep-conformance.json")
	if err != nil {
		t.Fatalf("read PEP conformance fixture: %v", err)
	}
	var fixture struct {
		GRPCTransports []struct {
			FullMethod      string `json:"full_method"`
			ClientStreaming bool   `json:"client_streaming"`
			ServerStreaming bool   `json:"server_streaming"`
			Expected        struct {
				Service string `json:"service"`
				Method  string `json:"method"`
				RPCType string `json:"rpc_type"`
			} `json:"expected"`
		} `json:"grpc_transports"`
		Outcomes []struct {
			Outcome    string `json:"outcome"`
			GRPCStatus int    `json:"grpc_status"`
		} `json:"outcomes"`
	}
	if err := json.Unmarshal(fixtureBytes, &fixture); err != nil {
		t.Fatalf("decode PEP conformance fixture: %v", err)
	}
	for _, vector := range fixture.GRPCTransports {
		service, method, err := splitGRPCFullMethod(vector.FullMethod)
		if err != nil {
			t.Fatalf("split %s: %v", vector.FullMethod, err)
		}
		if service != vector.Expected.Service || method != vector.Expected.Method || grpcRPCType(vector.ClientStreaming, vector.ServerStreaming) != vector.Expected.RPCType {
			t.Fatalf("gRPC conformance mismatch for %s", vector.FullMethod)
		}
	}
	for _, vector := range fixture.Outcomes {
		mapped := grpcErrorForOutcome(vector.Outcome)
		if int(status.Code(mapped)) != vector.GRPCStatus {
			t.Fatalf("outcome %s mapped to %s, want code %d", vector.Outcome, status.Code(mapped), vector.GRPCStatus)
		}
	}
}

func TestGRPCStreamingInterceptorsAuthorizeEachCardinalityAtEstablishment(t *testing.T) {
	var rpcTypes []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request EvaluateRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("decode evaluation request: %v", err)
		}
		if request.Transport.GRPC == nil {
			t.Fatalf("expected gRPC transport: %+v", request.Transport)
		}
		rpcTypes = append(rpcTypes, request.Transport.GRPC.RPCType)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(DecisionResponse{Decision: "allow", DecisionID: "dec_stream"})
	}))
	defer server.Close()

	client := NewClient(server.URL, "opk_service_key", time.Second)
	options := grpcTestAdapterOptions()
	for _, testCase := range []struct {
		clientStreaming bool
		serverStreaming bool
		rpcType         string
	}{
		{clientStreaming: true, rpcType: "client_streaming"},
		{serverStreaming: true, rpcType: "server_streaming"},
		{clientStreaming: true, serverStreaming: true, rpcType: "bidirectional_streaming"},
	} {
		description := &grpc.StreamDesc{ClientStreams: testCase.clientStreaming, ServerStreams: testCase.serverStreaming}
		streamerCalled := false
		streamContext := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("idempotency-key", "client-"+testCase.rpcType))
		_, err := client.StreamClientInterceptor(options)(streamContext, description, nil, "/payments.PaymentService/Stream", func(context.Context, *grpc.StreamDesc, *grpc.ClientConn, string, ...grpc.CallOption) (grpc.ClientStream, error) {
			streamerCalled = true
			return nil, nil
		})
		if err != nil || !streamerCalled {
			t.Fatalf("client %s stream should open after authorization, called=%v err=%v", testCase.rpcType, streamerCalled, err)
		}

		serverHandlerCalled := false
		serverStream := &grpcTestServerStream{ctx: metadata.NewIncomingContext(context.Background(), metadata.Pairs("idempotency-key", "server-"+testCase.rpcType))}
		err = client.StreamServerInterceptor(options)(struct{}{}, serverStream, &grpc.StreamServerInfo{
			FullMethod: "/payments.PaymentService/Stream", IsClientStream: testCase.clientStreaming, IsServerStream: testCase.serverStreaming,
		}, func(any, grpc.ServerStream) error {
			serverHandlerCalled = true
			return nil
		})
		if err != nil || !serverHandlerCalled {
			t.Fatalf("server %s stream handler should run after authorization, called=%v err=%v", testCase.rpcType, serverHandlerCalled, err)
		}
	}
	if len(rpcTypes) != 6 {
		t.Fatalf("expected one authorization at establishment for six streams, got %d: %+v", len(rpcTypes), rpcTypes)
	}
	for index, expected := range []string{"client_streaming", "client_streaming", "server_streaming", "server_streaming", "bidirectional_streaming", "bidirectional_streaming"} {
		if rpcTypes[index] != expected {
			t.Fatalf("unexpected stream cardinality at authorization %d: got=%s want=%s", index, rpcTypes[index], expected)
		}
	}
}

func grpcTestAdapterOptions() GRPCAdapterOptions {
	return GRPCAdapterOptions{
		ResolveAsset: func(context.Context, GRPCRequestContext) (GRPCAssetReference, error) {
			return GRPCAssetReference{AssetIdentity: &AssetIdentity{Application: "billing", Service: "refund-api", Environment: "production"}}, nil
		},
		ResolveMetadata: func(_ context.Context, request GRPCRequestContext) (any, error) {
			return struct {
				Operation string `json:"operation"`
				Actor     string `json:"actor"`
			}{Operation: request.Method, Actor: "untrusted-metadata"}, nil
		},
		ResolvePrincipalContext: func(context.Context, GRPCRequestContext) (*PrincipalContext, error) {
			return &PrincipalContext{BearerToken: "verified-user-token"}, nil
		},
		MetadataAllowlist: []string{"x-request-region"},
	}
}

type canonicalEquivalenceFixture struct {
	AssetKey             string         `json:"asset_key"`
	OperationID          string         `json:"operation_id"`
	PrincipalBearerToken string         `json:"principal_bearer_token"`
	Metadata             map[string]any `json:"metadata"`
	ApprovalRetry        struct {
		ApprovalID  string `json:"approval_id"`
		PayloadHash string `json:"payload_hash"`
	} `json:"approval_retry"`
	HTTP struct {
		Method  string `json:"method"`
		Path    string `json:"path"`
		Host    string `json:"host"`
		Scheme  string `json:"scheme"`
		RouteID string `json:"route_id"`
	} `json:"http"`
	GRPC struct {
		FullMethod string `json:"full_method"`
		RPCType    string `json:"rpc_type"`
		RouteID    string `json:"route_id"`
	} `json:"grpc"`
}

func loadCanonicalEquivalenceFixture(t *testing.T) canonicalEquivalenceFixture {
	t.Helper()
	fixtureBytes, err := os.ReadFile("../../testdata/pep-conformance.json")
	if err != nil {
		t.Fatalf("read conformance fixture: %v", err)
	}
	var fixture struct {
		CanonicalEquivalence canonicalEquivalenceFixture `json:"canonical_equivalence"`
	}
	if err := json.Unmarshal(fixtureBytes, &fixture); err != nil {
		t.Fatalf("decode conformance fixture: %v", err)
	}
	return fixture.CanonicalEquivalence
}

func newRecordingPDP(t *testing.T, bodies *[]map[string]any) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode evaluation request: %v", err)
			return
		}
		*bodies = append(*bodies, body)
		response := DecisionResponse{Decision: "allow", DecisionID: "dec_equiv"}
		if approvalID, _ := body["approval_id"].(string); approvalID != "" {
			// An approved retry must be confirmed consumed, as the PDP does on first redemption.
			response.ApprovalID = approvalID
			response.PayloadHash, _ = body["payload_hash"].(string)
			response.ApprovalStatus = "consumed"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
}

func TestGRPCStreamEstablishmentCarriesApprovalRetryTuple(t *testing.T) {
	fixture := loadCanonicalEquivalenceFixture(t)
	var bodies []map[string]any
	server := newRecordingPDP(t, &bodies)
	defer server.Close()

	client := NewClient(server.URL, "opk_service_key", time.Second)
	options := grpcTestAdapterOptions()
	options.ResolveApprovalRetry = func(context.Context, GRPCRequestContext) (*ApprovalRetry, error) {
		return &ApprovalRetry{ApprovalID: fixture.ApprovalRetry.ApprovalID, PayloadHash: fixture.ApprovalRetry.PayloadHash}, nil
	}
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("idempotency-key", "refund-stream"))
	streamed := false
	_, err := client.StreamClientInterceptor(options)(ctx, &grpc.StreamDesc{ServerStreams: true}, nil, "/payments.PaymentService/Watch",
		func(context.Context, *grpc.StreamDesc, *grpc.ClientConn, string, ...grpc.CallOption) (grpc.ClientStream, error) {
			streamed = true
			return nil, nil
		},
	)
	if err != nil || !streamed {
		t.Fatalf("expected stream after allow, streamed=%v err=%v", streamed, err)
	}
	if len(bodies) != 1 {
		t.Fatalf("expected one PDP evaluation, got %d", len(bodies))
	}
	if bodies[0]["approval_id"] != fixture.ApprovalRetry.ApprovalID || bodies[0]["payload_hash"] != fixture.ApprovalRetry.PayloadHash {
		t.Fatalf("stream establishment must carry the stored tuple, got %+v", bodies[0])
	}
}

func TestGRPCIncompleteApprovalRetryIsRejectedBeforePDPCall(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := NewClient(server.URL, "opk_service_key", time.Second)
	options := grpcTestAdapterOptions()
	options.ResolveApprovalRetry = func(context.Context, GRPCRequestContext) (*ApprovalRetry, error) {
		return &ApprovalRetry{ApprovalID: "apr_stream", PayloadHash: " "}, nil
	}
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("idempotency-key", "refund-stream"))
	_, err := client.StreamClientInterceptor(options)(ctx, &grpc.StreamDesc{ServerStreams: true}, nil, "/payments.PaymentService/Watch",
		func(context.Context, *grpc.StreamDesc, *grpc.ClientConn, string, ...grpc.CallOption) (grpc.ClientStream, error) {
			t.Fatal("stream must not be created when the retry tuple is incomplete")
			return nil, nil
		},
	)
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v", err)
	}
	if calls != 0 {
		t.Fatalf("incomplete retry tuple must not reach the PDP, calls=%d", calls)
	}
}

func TestHTTPAndGRPCProduceEquivalentCanonicalRequests(t *testing.T) {
	fixture := loadCanonicalEquivalenceFixture(t)
	var bodies []map[string]any
	server := newRecordingPDP(t, &bodies)
	defer server.Close()

	client := NewClient(server.URL, "opk_service_key", time.Second)
	principal := func() (*PrincipalContext, error) {
		return &PrincipalContext{BearerToken: fixture.PrincipalBearerToken}, nil
	}
	retry := func() (*ApprovalRetry, error) {
		return &ApprovalRetry{ApprovalID: fixture.ApprovalRetry.ApprovalID, PayloadHash: fixture.ApprovalRetry.PayloadHash}, nil
	}

	httpRequest := httptest.NewRequest(fixture.HTTP.Method, "https://"+fixture.HTTP.Host+fixture.HTTP.Path, nil)
	httpResponse, err := client.AuthorizeHTTPRequest(context.Background(), httpRequest, HTTPAdapterOptions{
		ResolveAsset: func(*http.Request) (HTTPAssetReference, error) {
			return HTTPAssetReference{AssetKey: fixture.AssetKey}, nil
		},
		ResolveMetadata:         func(*http.Request) (any, error) { return fixture.Metadata, nil },
		ResolvePrincipalContext: func(*http.Request) (*PrincipalContext, error) { return principal() },
		ResolveOperationID:      func(*http.Request) (string, error) { return fixture.OperationID, nil },
		ResolveHost:             func(*http.Request) string { return fixture.HTTP.Host },
		ResolveRouteID:          func(*http.Request) string { return fixture.HTTP.RouteID },
		ResolveApprovalRetry:    func(*http.Request) (*ApprovalRetry, error) { return retry() },
	})
	if err != nil || httpResponse.Decision != "allow" {
		t.Fatalf("HTTP authorization failed: decision=%+v err=%v", httpResponse, err)
	}

	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("idempotency-key", fixture.OperationID))
	grpcInterceptor := client.UnaryClientInterceptor(GRPCAdapterOptions{
		ResolveAsset: func(context.Context, GRPCRequestContext) (GRPCAssetReference, error) {
			return GRPCAssetReference{AssetKey: fixture.AssetKey}, nil
		},
		ResolveMetadata:         func(context.Context, GRPCRequestContext) (any, error) { return fixture.Metadata, nil },
		ResolvePrincipalContext: func(context.Context, GRPCRequestContext) (*PrincipalContext, error) { return principal() },
		ResolveRouteID:          func(GRPCRequestContext) string { return fixture.GRPC.RouteID },
		ResolveApprovalRetry:    func(context.Context, GRPCRequestContext) (*ApprovalRetry, error) { return retry() },
	})
	err = grpcInterceptor(ctx, fixture.GRPC.FullMethod, struct{}{}, &struct{}{}, nil,
		func(context.Context, string, any, any, *grpc.ClientConn, ...grpc.CallOption) error { return nil },
	)
	if err != nil {
		t.Fatalf("gRPC authorization failed: %v", err)
	}
	if len(bodies) != 2 {
		t.Fatalf("expected two PDP evaluations, got %d", len(bodies))
	}
	httpBody, grpcBody := bodies[0], bodies[1]

	httpTransport, _ := httpBody["transport"].(map[string]any)
	grpcTransport, _ := grpcBody["transport"].(map[string]any)
	if httpTransport["kind"] != "http" || grpcTransport["kind"] != "grpc" {
		t.Fatalf("unexpected transport kinds: http=%v grpc=%v", httpTransport["kind"], grpcTransport["kind"])
	}
	for key := range httpBody {
		if key == "transport" {
			continue
		}
		if !reflect.DeepEqual(httpBody[key], grpcBody[key]) {
			t.Fatalf("canonical field %q differs: http=%v grpc=%v", key, httpBody[key], grpcBody[key])
		}
	}
	for key := range grpcBody {
		if _, ok := httpBody[key]; !ok && key != "transport" {
			t.Fatalf("gRPC-only canonical field %q", key)
		}
	}
	if grpcBody["operation_id"] != fixture.OperationID || grpcBody["approval_id"] != fixture.ApprovalRetry.ApprovalID || grpcBody["payload_hash"] != fixture.ApprovalRetry.PayloadHash {
		t.Fatalf("canonical body does not match fixture: %+v", grpcBody)
	}
}

type grpcTestServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *grpcTestServerStream) Context() context.Context { return s.ctx }
