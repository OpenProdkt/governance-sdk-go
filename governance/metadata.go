package governance

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
)

const (
	maxMetadataBytes      = 8 * 1024
	maxMetadataStringSize = 256
	maxAttachmentCount    = 64
)

var forbiddenMetadataKeys = map[string]struct{}{
	"raw_message_content": {},
	"attachment_content":  {},
}

var knownStringMetadataKeys = map[string]struct{}{
	"provider":    {},
	"model":       {},
	"operation":   {},
	"environment": {},
	"actor":       {},
	"application": {},
}

var allowedAIKeys = map[string]struct{}{
	"message_count":         {},
	"message_size_bytes":    {},
	"input_tokens":          {},
	"output_token_limit":    {},
	"attachment_count":      {},
	"attachment_size_bytes": {},
	"tool_count":            {},
	"request_size_bytes":    {},
}

type AIMetadata struct {
	MessageCount        int
	MessageSizeBytes    int
	InputTokens         int
	OutputTokenLimit    int
	AttachmentCount     int
	AttachmentSizeBytes int
	ToolCount           int
	RequestSizeBytes    int
}

func BuildProviderMetadata(provider, model, operation, environment, actor, application string, ai AIMetadata) (map[string]interface{}, error) {
	metadata := map[string]interface{}{
		"provider":    strings.TrimSpace(provider),
		"model":       strings.TrimSpace(model),
		"operation":   strings.TrimSpace(operation),
		"environment": strings.TrimSpace(environment),
		"actor":       strings.TrimSpace(actor),
		"application": strings.TrimSpace(application),
		"ai": map[string]interface{}{
			"message_count":         ai.MessageCount,
			"message_size_bytes":    ai.MessageSizeBytes,
			"input_tokens":          ai.InputTokens,
			"output_token_limit":    ai.OutputTokenLimit,
			"attachment_count":      ai.AttachmentCount,
			"attachment_size_bytes": ai.AttachmentSizeBytes,
			"tool_count":            ai.ToolCount,
			"request_size_bytes":    ai.RequestSizeBytes,
		},
	}
	return SanitizeMetadata(metadata)
}

func BuildOpenAIMetadata(model, operation, environment, actor, application string, ai AIMetadata) (map[string]interface{}, error) {
	return BuildProviderMetadata("openai", model, operation, environment, actor, application, ai)
}

func BuildAnthropicMetadata(model, operation, environment, actor, application string, ai AIMetadata) (map[string]interface{}, error) {
	return BuildProviderMetadata("anthropic", model, operation, environment, actor, application, ai)
}

func BuildGeminiMetadata(model, operation, environment, actor, application string, ai AIMetadata) (map[string]interface{}, error) {
	return BuildProviderMetadata("gemini", model, operation, environment, actor, application, ai)
}

func BuildOpenAICompatibleMetadata(model, operation, environment, actor, application string, ai AIMetadata) (map[string]interface{}, error) {
	return BuildProviderMetadata("openai_compatible", model, operation, environment, actor, application, ai)
}

func BuildLocalLLMMetadata(model, operation, environment, actor, application string, ai AIMetadata) (map[string]interface{}, error) {
	return BuildProviderMetadata("local", model, operation, environment, actor, application, ai)
}

func BuildGenericAPIMetadata(model, operation, environment, actor, application string, ai AIMetadata) (map[string]interface{}, error) {
	return BuildProviderMetadata("generic_api", model, operation, environment, actor, application, ai)
}

func SanitizeMetadata(metadata any) (map[string]interface{}, error) {
	if metadata == nil {
		return nil, nil
	}
	value := reflect.ValueOf(metadata)
	if value.Kind() == reflect.Map && value.IsNil() {
		return nil, nil
	}
	encodedInput, err := json.Marshal(metadata)
	if err != nil {
		return nil, fmt.Errorf("serialize metadata: %w", err)
	}
	var normalized map[string]interface{}
	if err := json.Unmarshal(encodedInput, &normalized); err != nil {
		return nil, fmt.Errorf("metadata must serialize to a JSON object: %w", err)
	}
	if normalized == nil {
		return nil, fmt.Errorf("metadata must serialize to a JSON object")
	}
	return sanitizeMetadataMap(normalized)
}

func sanitizeMetadataMap(metadata map[string]interface{}) (map[string]interface{}, error) {
	out := make(map[string]interface{}, len(metadata))
	for key, value := range metadata {
		trimmedKey := strings.TrimSpace(key)
		if _, exists := out[trimmedKey]; exists {
			return nil, fmt.Errorf("metadata contains duplicate normalized key %q", trimmedKey)
		}
		if _, forbidden := forbiddenMetadataKeys[trimmedKey]; forbidden {
			return nil, fmt.Errorf("metadata key %q is forbidden", trimmedKey)
		}
		if trimmedKey == "ai" {
			aiMap, ok := value.(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf("metadata.ai must be an object")
			}
			sanitizedAI, err := sanitizeAIMap(aiMap)
			if err != nil {
				return nil, err
			}
			out[trimmedKey] = sanitizedAI
			continue
		}

		var sanitized interface{}
		var err error
		if _, known := knownStringMetadataKeys[trimmedKey]; known {
			sanitized, err = sanitizeStringValue(trimmedKey, value)
		} else {
			sanitized, err = sanitizeMetadataValue(value)
		}
		if err != nil {
			return nil, err
		}
		out[trimmedKey] = sanitized
	}

	encoded, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	if len(encoded) > maxMetadataBytes {
		return nil, fmt.Errorf("metadata exceeds %d bytes", maxMetadataBytes)
	}

	return out, nil
}

func sanitizeMetadataValue(value interface{}) (interface{}, error) {
	switch typed := value.(type) {
	case nil, bool, string, int, int32, int64, float32, float64:
		return typed, nil
	case []interface{}:
		out := make([]interface{}, 0, len(typed))
		for _, item := range typed {
			sanitized, err := sanitizeMetadataValue(item)
			if err != nil {
				return nil, err
			}
			out = append(out, sanitized)
		}
		return out, nil
	case map[string]interface{}:
		out := make(map[string]interface{}, len(typed))
		for key, nested := range typed {
			trimmedKey := strings.TrimSpace(key)
			if _, exists := out[trimmedKey]; exists {
				return nil, fmt.Errorf("metadata contains duplicate normalized key %q", trimmedKey)
			}
			if _, forbidden := forbiddenMetadataKeys[trimmedKey]; forbidden {
				return nil, fmt.Errorf("metadata key %q is forbidden", trimmedKey)
			}
			sanitized, err := sanitizeMetadataValue(nested)
			if err != nil {
				return nil, err
			}
			out[trimmedKey] = sanitized
		}
		return out, nil
	default:
		return nil, fmt.Errorf("metadata value type %T is not supported", value)
	}
}

func sanitizeAIMap(ai map[string]interface{}) (map[string]interface{}, error) {
	out := make(map[string]interface{}, len(ai))
	for key, value := range ai {
		trimmedKey := strings.TrimSpace(key)
		if _, exists := out[trimmedKey]; exists {
			return nil, fmt.Errorf("metadata.ai contains duplicate normalized key %q", trimmedKey)
		}
		if _, forbidden := forbiddenMetadataKeys[trimmedKey]; forbidden {
			return nil, fmt.Errorf("metadata.ai key %q is forbidden", trimmedKey)
		}
		if _, ok := allowedAIKeys[trimmedKey]; !ok {
			return nil, fmt.Errorf("metadata.ai key %q is not allowed", trimmedKey)
		}
		number, ok := asInt(value)
		if !ok {
			return nil, fmt.Errorf("metadata.ai.%s must be numeric", trimmedKey)
		}
		if trimmedKey == "attachment_count" && number > maxAttachmentCount {
			return nil, fmt.Errorf("metadata.ai.attachment_count exceeds %d", maxAttachmentCount)
		}
		out[trimmedKey] = number
	}
	return out, nil
}

func sanitizeStringValue(key string, value interface{}) (interface{}, error) {
	s, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("metadata.%s must be a string", key)
	}
	s = strings.TrimSpace(s)
	if len(s) > maxMetadataStringSize {
		s = s[:maxMetadataStringSize]
	}
	return s, nil
}

func asInt(v interface{}) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int32:
		return int(n), true
	case int64:
		return int(n), true
	case float32:
		return int(n), true
	case float64:
		return int(n), true
	default:
		return 0, false
	}
}
