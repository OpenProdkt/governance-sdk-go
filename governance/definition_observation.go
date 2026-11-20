package governance

import (
	"encoding/json"
	"regexp"
	"unicode"
	"unicode/utf8"
)

// DefinitionObservationCanon is the only digest profile the evaluate endpoints accept.
const DefinitionObservationCanon = "mcp-tool-definition:v1"

const (
	maxDefinitionObservationBytes   = 512
	maxDefinitionServerVersionRunes = 128
)

var definitionDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// DefinitionObservation is optional, caller-supplied evidence about the definition of the
// MCP tool being called. It carries a digest only, never the description or schema.
// The SDK does not compute digests, and the observation is untrusted caller evidence:
// the control plane records and compares it but never treats it as proof.
//
// Digest is "sha256:" plus 64 lowercase hex characters. Canon must be
// DefinitionObservationCanon. ServerVersion is optional (1 to 128 characters, no
// control characters). The encoded object (as sent on the wire) is at most 512 bytes. Leave
// EvaluateRequest.DefinitionObservation nil when the digest is unknown.
type DefinitionObservation struct {
	Digest        string `json:"digest"`
	Canon         string `json:"canon"`
	ServerVersion string `json:"server_version,omitempty"`
}

func validateDefinitionObservation(o *DefinitionObservation) error {
	if o == nil {
		return nil
	}
	if !definitionDigestPattern.MatchString(o.Digest) {
		return &InvalidAuthorizationInputError{Message: "definition_observation digest must be sha256: followed by 64 lowercase hex characters"}
	}
	if o.Canon != DefinitionObservationCanon {
		return &InvalidAuthorizationInputError{Message: "definition_observation canon must be " + DefinitionObservationCanon}
	}
	if o.ServerVersion != "" {
		if !utf8.ValidString(o.ServerVersion) || utf8.RuneCountInString(o.ServerVersion) > maxDefinitionServerVersionRunes {
			return &InvalidAuthorizationInputError{Message: "definition_observation server_version must be 1 to 128 valid characters"}
		}
		for _, r := range o.ServerVersion {
			if unicode.IsControl(r) {
				return &InvalidAuthorizationInputError{Message: "definition_observation server_version must not contain control characters"}
			}
		}
	}
	encoded, err := json.Marshal(o)
	if err != nil || len(encoded) > maxDefinitionObservationBytes {
		return &InvalidAuthorizationInputError{Message: "definition_observation must be at most 512 bytes"}
	}
	return nil
}
