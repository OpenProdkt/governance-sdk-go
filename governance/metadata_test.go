package governance

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestSanitizeMetadataConformance(t *testing.T) {
	fixtureBytes, err := os.ReadFile("../../testdata/metadata-conformance.json")
	if err != nil {
		t.Fatalf("read metadata conformance fixtures: %v", err)
	}
	var cases []struct {
		Name     string                 `json:"name"`
		Input    map[string]interface{} `json:"input"`
		Expected map[string]interface{} `json:"expected"`
	}
	if err := json.Unmarshal(fixtureBytes, &cases); err != nil {
		t.Fatalf("decode metadata conformance fixtures: %v", err)
	}
	for _, testCase := range cases {
		t.Run(testCase.Name, func(t *testing.T) {
			actual, err := SanitizeMetadata(testCase.Input)
			if err != nil {
				t.Fatalf("sanitize metadata: %v", err)
			}
			actualJSON, err := json.Marshal(actual)
			if err != nil {
				t.Fatalf("encode sanitized metadata: %v", err)
			}
			expectedJSON, err := json.Marshal(testCase.Expected)
			if err != nil {
				t.Fatalf("encode expected metadata: %v", err)
			}
			if !bytes.Equal(actualJSON, expectedJSON) {
				t.Fatalf("expected %s, got %s", expectedJSON, actualJSON)
			}
		})
	}
}

func TestBuildOpenAIMetadata(t *testing.T) {
	metadata, err := BuildOpenAIMetadata("gpt-5", "chat", "prod", "svc-api", "payments", AIMetadata{
		MessageCount:        4,
		MessageSizeBytes:    18200,
		InputTokens:         4200,
		OutputTokenLimit:    2000,
		AttachmentCount:     2,
		AttachmentSizeBytes: 840000,
		ToolCount:           1,
		RequestSizeBytes:    22000,
	})
	if err != nil {
		t.Fatalf("build metadata: %v", err)
	}
	if metadata["provider"] != "openai" {
		t.Fatalf("unexpected provider: %v", metadata["provider"])
	}
}

func TestSanitizeMetadataRejectsForbiddenContent(t *testing.T) {
	_, err := SanitizeMetadata(map[string]interface{}{
		"provider":            "openai",
		"raw_message_content": "secret",
	})
	if err == nil {
		t.Fatalf("expected forbidden metadata error")
	}
}

func TestSanitizeMetadataRejectsNormalizedKeyCollisions(t *testing.T) {
	_, err := SanitizeMetadata(map[string]interface{}{"operation": "refund", " operation ": "cancel"})
	if err == nil {
		t.Fatalf("expected duplicate normalized key error")
	}
}

func TestSanitizeMetadataAllowsGenericPresetFields(t *testing.T) {
	metadata, err := SanitizeMetadata(map[string]interface{}{
		"request": map[string]interface{}{"method": "POST", "path": "/invoices"},
	})
	if err != nil {
		t.Fatalf("sanitize generic metadata: %v", err)
	}
	request := metadata["request"].(map[string]interface{})
	if request["method"] != "POST" {
		t.Fatalf("unexpected request metadata: %+v", request)
	}
}

func TestSanitizeMetadataAcceptsStructsThroughJSON(t *testing.T) {
	type RefundMetadata struct {
		Operation string         `json:"operation"`
		Amount    int            `json:"amount"`
		Tags      []string       `json:"tags"`
		Context   map[string]any `json:"context"`
	}
	metadata, err := SanitizeMetadata(RefundMetadata{
		Operation: " refund ", Amount: 42, Tags: []string{"priority"},
		Context: map[string]any{"method": "POST"},
	})
	if err != nil {
		t.Fatalf("sanitize struct metadata: %v", err)
	}
	if metadata["operation"] != "refund" || metadata["amount"] != float64(42) {
		t.Fatalf("unexpected struct metadata: %+v", metadata)
	}
}

func TestSanitizeMetadataRejectsNonObjectAndUnsupportedValues(t *testing.T) {
	if _, err := SanitizeMetadata([]string{"not", "an", "object"}); err == nil {
		t.Fatalf("expected top-level array to be rejected")
	}
	if _, err := SanitizeMetadata(map[string]interface{}{"value": make(chan int)}); err == nil {
		t.Fatalf("expected unsupported value to be rejected")
	}
}

func TestSanitizeMetadataEnforcesSerializedSizeLimit(t *testing.T) {
	if _, err := SanitizeMetadata(map[string]interface{}{"value": strings.Repeat("x", maxMetadataBytes)}); err == nil || !strings.Contains(err.Error(), "metadata exceeds") {
		t.Fatalf("expected serialized metadata size limit error, got %v", err)
	}
}
