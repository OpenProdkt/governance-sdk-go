package governance

import (
	"bytes"
	"encoding/json"
	"errors"
	"math/big"
	"regexp"
	"strconv"
	"strings"
)

// Keep these wire-domain guards aligned with the PDP. The SDK preserves source
// number text; canonical approval hashing is exclusively a PDP responsibility.
var decimalToken = regexp.MustCompile(`^-?(0|[1-9][0-9]*)(?:\.([0-9]+))?(?:[eE]([+-]?[0-9]+))?$`)

func validateNumber(n json.Number) error {
	text := string(n)
	if len(text) > 4096 {
		return errors.New("metadata number exceeds decimal limits")
	}
	m := decimalToken.FindStringSubmatch(text)
	if m == nil {
		return errors.New("metadata number must be a finite decimal")
	}
	digits := strings.TrimLeft(m[1]+m[2], "0")
	if digits == "" {
		return nil
	}
	exp := int64(0)
	if m[3] != "" {
		var err error
		exp, err = strconv.ParseInt(m[3], 10, 64)
		if err != nil || exp < -int64(len(text))-308 || exp > int64(len(text))+308 {
			return errors.New("metadata number exceeds decimal limits")
		}
	}
	adjusted := exp - int64(len(m[2])) + int64(len(digits)) - 1
	if len(strings.TrimRight(digits, "0")) > 128 || adjusted < -308 || adjusted > 308 {
		return errors.New("metadata number exceeds decimal limits")
	}
	return nil
}

func numberInt(n json.Number) (int, bool) {
	if validateNumber(n) != nil {
		return 0, false
	}
	m := decimalToken.FindStringSubmatch(string(n))
	if strings.Trim(m[1]+m[2], "0") == "" {
		return 0, true
	}
	r, ok := new(big.Rat).SetString(string(n))
	if !ok || !r.IsInt() || !r.Num().IsInt64() {
		return 0, false
	}
	v := r.Num().Int64()
	if strconv.IntSize == 32 && (v < -1<<31 || v > 1<<31-1) {
		return 0, false
	}
	return int(v), true
}

// Validate only metadata and individual condition values. Envelope and "all"
// wrappers do not count toward their depth budgets. JSON marshaling has already
// rejected in-memory cycles before this wire validator runs.
func validateRequestValues(data []byte) error {
	var decoded any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&decoded); err != nil {
		return err
	}
	roots, _ := decoded.(map[string]any)
	if err := validateWireValue(roots["metadata"], 0); err != nil {
		return err
	}
	pending := []any{roots["condition"]}
	for len(pending) > 0 {
		node, _ := pending[len(pending)-1].(map[string]any)
		pending = pending[:len(pending)-1]
		if value, present := node["value"]; present {
			if err := validateWireValue(value, 0); err != nil {
				return err
			}
		}
		if children, ok := node["all"].([]any); ok {
			pending = append(pending, children...)
		}
		if child, ok := node["not"]; ok {
			pending = append(pending, child)
		}
	}
	return nil
}

func validateWireValue(value any, depth int) error {
	if depth > 64 {
		return errors.New("value nesting exceeds 64 levels")
	}
	switch v := value.(type) {
	case json.Number:
		return validateNumber(v)
	case map[string]any:
		for _, child := range v {
			if err := validateWireValue(child, depth+1); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range v {
			if err := validateWireValue(child, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}
