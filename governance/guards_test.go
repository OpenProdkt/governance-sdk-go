package governance

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNumericTokenAndZeroExponentGuards(t *testing.T) {
	for _, token := range []string{
		"1." + strings.Repeat("0", 4094),
		"-0e" + strings.Repeat("9", 4093),
		"1e" + strings.Repeat("0", 4093) + "1",
	} {
		if len(token) != 4096 {
			t.Fatal("bad boundary fixture")
		}
		if err := validateNumber(json.Number(token)); err != nil {
			t.Fatalf("valid boundary: %v", err)
		}
		if err := validateNumber(json.Number(token + "0")); err == nil {
			t.Fatal("accepted oversized raw token")
		}
		if _, err := SanitizeMetadata(map[string]any{"n": json.Number(token)}); err != nil {
			t.Fatal(err)
		}
	}
	for _, exponent := range []string{"2147483648", "9223372036854775808", strings.Repeat("9", 4000), "-" + strings.Repeat("9", 4000)} {
		if n, ok := numberInt(json.Number("-0e" + exponent)); !ok || n != 0 {
			t.Fatal("zero with huge written exponent rejected")
		}
		if err := validateNumber(json.Number("1e" + exponent)); err == nil {
			t.Fatal("accepted nonzero exponent outside domain")
		}
	}
}

func TestMetadataAndPolicyValueDepthRoots(t *testing.T) {
	for _, leaf := range []any{nil, "text", map[string]any{}, []any{}} {
		for _, depth := range []int{64, 65} {
			value := leaf
			for i := 1; i < depth; i++ {
				value = []any{value}
			}

			_, err := SanitizeMetadata(map[string]any{"n": value})
			if (err == nil) != (depth == 64) {
				t.Fatalf("metadata depth %d: %v", depth, err)
			}
			// The condition value has one more allowed edge than a member
			// of metadata, because the value itself is its depth-zero root.
			condition := map[string]any{"value": []any{value}}
			for i := 0; i < 80; i++ {
				condition = map[string]any{"all": []any{condition}}
			}
			body, _ := json.Marshal(map[string]any{"condition": condition})
			err = validateRequestValues(body)
			if (err == nil) != (depth == 64) {
				t.Fatalf("condition value depth %d: %v", depth, err)
			}
		}
	}
	cycle := map[string]any{}
	cycle["self"] = cycle
	if _, err := SanitizeMetadata(cycle); err == nil {
		t.Fatal("accepted metadata cycle")
	}
	var unrelated any = nil
	for i := 0; i < 90; i++ {
		unrelated = []any{unrelated}
	}
	body, _ := json.Marshal(map[string]any{"unrelated": unrelated})
	if err := validateRequestValues(body); err != nil {
		t.Fatalf("unrelated envelope incorrectly depth limited: %v", err)
	}
}

func TestNotConditionValueGuardsAndOmission(t *testing.T) {
	for _, wire := range []string{
		`{"not":{"field":"metadata.n","operator":"exists"}}`,
		`{"not":{"field":"metadata.n","operator":"=","value":9007199254740993}}`,
	} {
		if err := validateRequestValues([]byte(`{"condition":` + wire + `}`)); err != nil {
			t.Fatal(err)
		}
	}
	for _, value := range []string{
		`1e309`, `5e-324`, `1.` + strings.Repeat("0", 4095),
		strings.Repeat("[", 65) + `null` + strings.Repeat("]", 65),
	} {
		wire := `{"condition":{"all":[{"not":{"field":"metadata.n","operator":"=","value":` + value + `}}]}}`
		if err := validateRequestValues([]byte(wire)); err == nil {
			t.Fatalf("not hid invalid value %s", value)
		}
	}
	wire := `{"not":{"field":"metadata.n","operator":"exists"}}`
	var condition map[string]any
	if err := json.Unmarshal([]byte(wire), &condition); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(condition)
	if err != nil || string(encoded) != wire {
		t.Fatal(string(encoded), err)
	}
}
