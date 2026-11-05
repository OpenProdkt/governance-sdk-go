package governance

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestMetadataPreservesEveryNumericKind(t *testing.T) {
	type count int64
	for _, value := range []any{int(1), int8(1), int16(1), int32(1), int64(9007199254740993), uint(1), uint8(1), uint16(1), uint32(1), uint64(math.MaxUint64), float32(0.1), float64(0.1), count(9007199254740993), json.Number("0.1000000000000000000001")} {
		result, err := SanitizeMetadata(map[string]any{"n": value})
		if err != nil {
			t.Fatalf("%T: %v", value, err)
		}
		got, err := json.Marshal(result["n"])
		want, _ := json.Marshal(value)
		if err != nil || string(got) != string(want) {
			t.Fatalf("%T lost precision: %s vs %s (%v)", value, got, want, err)
		}
	}
	for _, value := range []any{json.Number("1e309"), json.Number("1e-309"), json.Number(strings.Repeat("9", 129)), json.Number("NaN"), math.NaN(), math.Inf(1)} {
		if _, err := SanitizeMetadata(map[string]any{"n": value}); err == nil {
			t.Fatalf("accepted invalid %T", value)
		}
	}
	for _, value := range []any{json.Number("1e-308"), json.Number("9.99e308"), json.Number(strings.Repeat("9", 128)), json.Number("-0e308")} {
		if _, err := SanitizeMetadata(map[string]any{"n": value}); err != nil {
			t.Fatalf("rejected valid boundary: %v", err)
		}
	}
}

func TestMetadataCountersRejectFractionsOverflowButNotNegatives(t *testing.T) {
	for _, value := range []any{json.Number("0.5"), -1.1, json.Number("9223372036854775808"), json.Number("-9223372036854775809"), math.Inf(1), true, "1"} {
		if _, err := SanitizeMetadata(map[string]any{"ai": map[string]any{"message_count": value}}); err == nil {
			t.Fatalf("accepted counter %v", value)
		}
	}
	for _, value := range []any{-1, json.Number("1.0"), json.Number("1e2"), json.Number("0e2147483647"), json.Number("-9223372036854775808")} {
		if _, err := SanitizeMetadata(map[string]any{"ai": map[string]any{"message_count": value}}); err != nil {
			t.Fatalf("valid counter %v: %v", value, err)
		}
	}
	if _, err := SanitizeMetadata(map[string]any{"ai": map[string]any{"attachment_count": 65}}); err == nil {
		t.Fatal("attachment cap removed")
	}
}

func TestSDKDecodedPolicyNumbersRemainExact(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"n":9007199254740993,"d":0.1000000000000000000001}`))
	}))
	defer server.Close()
	response, err := NewClient(server.URL, "key", time.Second).ListPolicies(context.Background())
	if err != nil || response["n"] != json.Number("9007199254740993") || response["d"] != json.Number("0.1000000000000000000001") {
		t.Fatalf("precision lost: %v %v", response, err)
	}
}

func TestSDKBadRequestOutcomesAndGRPCMapping(t *testing.T) {
	for _, code := range []string{"invalid_context", "invalid_request"} {
		t.Run(code, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(400)
				_ = json.NewEncoder(w).Encode(DecisionResponse{Code: code, Error: "invalid input"})
			}))
			defer server.Close()
			_, err := NewClient(server.URL, "key", time.Second).EvaluateProxy(context.Background(), EvaluateRequest{Version: "v1", OperationID: "op-1", Asset: EvaluateAsset{ID: "ast_1"}, Transport: TransportContext{Kind: "http"}}, &PrincipalContext{BearerToken: "principal"})
			var outcome *EvaluationOutcomeError
			if !errors.As(err, &outcome) || outcome.HTTPStatus != 400 || outcome.Code != code || outcome.Outcome != code {
				t.Fatalf("lost typed %s: %v", code, err)
			}
			grpcErr := grpcAuthorizationError(err)
			if grpcErr == nil || !strings.Contains(grpcErr.Error(), "InvalidArgument") {
				t.Fatalf("%s gRPC mapping: %v", code, grpcErr)
			}
		})
	}
}
