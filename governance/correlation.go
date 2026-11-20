package governance

import (
	"regexp"
	"strings"
)

var traceparentPrefix = regexp.MustCompile(`^[0-9a-f]{2}-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}`)
var executionIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
var upstreamRequestIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

// Invalid trace context is omitted; the PDP creates its own context. No SDK IDs are generated.
func validTraceparent(s string) bool {
	if len(s) < 55 || len(s) > 512 || strings.ContainsAny(s, ",\r\n\t ") || !traceparentPrefix.MatchString(s) {
		return false
	}
	if s[:2] == "ff" || s[3:35] == strings.Repeat("0", 32) || s[36:52] == strings.Repeat("0", 16) {
		return false
	}
	return (s[:2] != "00" || len(s) == 55) && (len(s) == 55 || (s[55] == '-' && len(s) > 56))
}

func validateOutcomeCorrelation(r OperationOutcomeRequest) error {
	if r.ExecutionID != nil && !executionIDPattern.MatchString(*r.ExecutionID) {
		return &InvalidAuthorizationInputError{Message: "execution_id must be a lowercase UUIDv7"}
	}
	if r.Attempt != nil && (*r.Attempt < 1 || int64(*r.Attempt) > 2147483647) {
		return &InvalidAuthorizationInputError{Message: "attempt must be an integer between 1 and 2147483647"}
	}
	if r.UpstreamRequestID != nil && !upstreamRequestIDPattern.MatchString(*r.UpstreamRequestID) {
		return &InvalidAuthorizationInputError{Message: "invalid upstream_request_id"}
	}
	return nil
}

// Credentials and raw arguments are never policy input, even for direct canonical callers.
func validateEvaluationTransport(t TransportContext) error {
	if t.MCP != nil && t.MCP.Arguments != nil {
		return &InvalidAuthorizationInputError{Message: "raw MCP arguments must not be sent; use a payload digest"}
	}
	var headers map[string]string
	if t.HTTP != nil {
		headers = t.HTTP.Headers
	}
	if err := validateTransportHeaders(headers); err != nil {
		return err
	}
	if t.GRPC != nil {
		return validateTransportHeaders(t.GRPC.Metadata)
	}
	return nil
}

func validateTransportHeaders(headers map[string]string) error {
	for key := range headers {
		switch strings.ToLower(key) {
		case "authorization", "proxy-authorization", "cookie", "set-cookie":
			return &InvalidAuthorizationInputError{Message: "credentials must not be sent in transport metadata"}
		}
	}
	return nil
}
