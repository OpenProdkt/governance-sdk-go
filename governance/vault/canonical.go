package vault

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// Canonical JSON (RFC 8785, "JCS") for envelope headers, the authenticated data and
// the record. Numbers follow an exact-safe-integer profile: a record may hold integers
// within +/-(2^53-1) (integral spellings such as 1.0, 1e2 and -0 normalize to an
// integer); a fraction, an exponent beyond that range, NaN or Infinity is refused.
// Nothing is approximated, so every language produces the same bytes.

const maxCanonicalDepth = 256

const maxSafeInteger int64 = 9007199254740991

var errUnsupportedRecord = errors.New("record is outside the supported JSON profile")

// canonicalRecord returns the canonical JSON of a record. []byte and json.RawMessage
// are treated as JSON text of the record object; any other value is encoded with
// encoding/json first. The result is always an object.
func canonicalRecord(record any) ([]byte, error) {
	var raw []byte
	switch v := record.(type) {
	case nil:
		return nil, errUnsupportedRecord
	case []byte:
		raw = v
	case json.RawMessage:
		raw = v
	default:
		encoded, err := json.Marshal(record)
		if err != nil {
			return nil, errUnsupportedRecord
		}
		raw = encoded
	}
	if len(raw) > MaxRecordSize {
		return nil, errUnsupportedRecord
	}
	parsed, err := parseJSON(raw)
	if err != nil {
		return nil, errUnsupportedRecord
	}
	object, ok := parsed.(map[string]any)
	if !ok {
		return nil, errUnsupportedRecord
	}
	return appendCanonical(nil, object)
}

// canonicalStrings returns the canonical JSON of an object whose members are all strings.
func canonicalStrings(members map[string]string) []byte {
	object := make(map[string]any, len(members))
	for k, v := range members {
		object[k] = v
	}
	out, err := appendCanonical(nil, object)
	if err != nil {
		// Only unpaired surrogates fail; callers validate strings first.
		return nil
	}
	return out
}

// jsonNumber keeps the source spelling until a value is canonicalized.
type jsonNumber string

func parseJSON(raw []byte) (any, error) {
	if !utf8.Valid(raw) {
		return nil, errors.New("invalid UTF-8")
	}
	// encoding/json replaces unpaired UTF-16 escapes with U+FFFD, so reject them first.
	if err := checkSurrogates(raw); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	value, err := readValue(decoder, 0)
	if err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, errors.New("trailing JSON")
	}
	return value, nil
}

func checkSurrogates(raw []byte) error {
	inString := false
	for i := 0; i < len(raw); i++ {
		if raw[i] == '"' {
			inString = !inString
			continue
		}
		if !inString || raw[i] != '\\' {
			continue
		}
		i++
		if i >= len(raw) {
			return errors.New("incomplete escape")
		}
		if raw[i] != 'u' {
			continue
		}
		if i+4 >= len(raw) {
			return errors.New("incomplete Unicode escape")
		}
		n, err := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
		if err != nil {
			return errors.New("invalid Unicode escape")
		}
		i += 4
		if n >= 0xdc00 && n <= 0xdfff {
			return errors.New("unpaired low surrogate")
		}
		if n < 0xd800 || n > 0xdbff {
			continue
		}
		if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
			return errors.New("unpaired high surrogate")
		}
		low, err := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
		if err != nil || low < 0xdc00 || low > 0xdfff {
			return errors.New("unpaired high surrogate")
		}
		i += 6
	}
	return nil
}

func readValue(d *json.Decoder, depth int) (any, error) {
	if depth > maxCanonicalDepth {
		return nil, errors.New("JSON is too deep")
	}
	token, err := d.Token()
	if err != nil {
		return nil, err
	}
	switch t := token.(type) {
	case json.Number:
		return jsonNumber(t), nil
	case json.Delim:
		switch t {
		case '{':
			object := make(map[string]any)
			for d.More() {
				keyToken, err := d.Token()
				if err != nil {
					return nil, err
				}
				key, ok := keyToken.(string)
				if !ok {
					return nil, errors.New("object key must be a string")
				}
				if _, exists := object[key]; exists {
					return nil, fmt.Errorf("duplicate key")
				}
				value, err := readValue(d, depth+1)
				if err != nil {
					return nil, err
				}
				object[key] = value
			}
			if end, err := d.Token(); err != nil || end != json.Delim('}') {
				return nil, errors.New("invalid object end")
			}
			return object, nil
		case '[':
			array := make([]any, 0)
			for d.More() {
				value, err := readValue(d, depth+1)
				if err != nil {
					return nil, err
				}
				array = append(array, value)
			}
			if end, err := d.Token(); err != nil || end != json.Delim(']') {
				return nil, errors.New("invalid array end")
			}
			return array, nil
		}
		return nil, errors.New("unexpected delimiter")
	default:
		return token, nil
	}
}

// exactSafeInteger normalizes a JSON number exactly, without floating point: integral
// spellings such as 1.0, 1e2 or -0 become integers, and a fraction or an integer
// outside +/-(2^53-1) is an error. Exponent-sized allocations are avoided.
func exactSafeInteger(raw string) (int64, error) {
	negative := strings.HasPrefix(raw, "-")
	s := strings.TrimPrefix(raw, "-")
	exponent := int64(0)
	if i := strings.IndexAny(s, "eE"); i >= 0 {
		exp := s[i+1:]
		s = s[:i]
		expNegative := strings.HasPrefix(exp, "-")
		exp = strings.TrimLeft(exp, "+-")
		for _, c := range exp {
			if exponent < 1000000 {
				exponent = exponent*10 + int64(c-'0')
			}
		}
		if expNegative {
			exponent = -exponent
		}
	}
	if i := strings.IndexByte(s, '.'); i >= 0 {
		exponent -= int64(len(s) - i - 1)
		s = s[:i] + s[i+1:]
	}
	s = strings.TrimLeft(s, "0")
	if s == "" {
		return 0, nil
	}
	trimmed := strings.TrimRight(s, "0")
	exponent += int64(len(s) - len(trimmed))
	s = trimmed
	if exponent < 0 {
		return 0, errUnsupportedRecord
	}
	if exponent > 16 || int64(len(s))+exponent > 16 {
		return 0, errUnsupportedRecord
	}
	s += strings.Repeat("0", int(exponent))
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n > maxSafeInteger {
		return 0, errUnsupportedRecord
	}
	if negative {
		n = -n
	}
	return n, nil
}

// appendCanonical appends the RFC 8785 canonical form of a parsed JSON value.
func appendCanonical(dst []byte, value any) ([]byte, error) {
	switch v := value.(type) {
	case nil:
		return append(dst, "null"...), nil
	case bool:
		return strconv.AppendBool(dst, v), nil
	case jsonNumber:
		n, err := exactSafeInteger(string(v))
		if err != nil {
			return nil, err
		}
		return strconv.AppendInt(dst, n, 10), nil
	case string:
		if !utf8.ValidString(v) {
			return nil, errUnsupportedRecord
		}
		return appendCanonicalString(dst, v), nil
	case []any:
		dst = append(dst, '[')
		for i, item := range v {
			if i != 0 {
				dst = append(dst, ',')
			}
			var err error
			if dst, err = appendCanonical(dst, item); err != nil {
				return nil, err
			}
		}
		return append(dst, ']'), nil
	case map[string]any:
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Slice(keys, func(i, j int) bool { return utf16Less(keys[i], keys[j]) })
		dst = append(dst, '{')
		for i, key := range keys {
			if i != 0 {
				dst = append(dst, ',')
			}
			if !utf8.ValidString(key) {
				return nil, errUnsupportedRecord
			}
			dst = appendCanonicalString(dst, key)
			dst = append(dst, ':')
			var err error
			if dst, err = appendCanonical(dst, v[key]); err != nil {
				return nil, err
			}
		}
		return append(dst, '}'), nil
	default:
		return nil, errUnsupportedRecord
	}
}

// utf16Less orders object keys by UTF-16 code unit, as RFC 8785 requires.
func utf16Less(a, b string) bool {
	x, y := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(x) && i < len(y); i++ {
		if x[i] != y[i] {
			return x[i] < y[i]
		}
	}
	return len(x) < len(y)
}

// appendCanonicalString writes the ECMAScript JSON.stringify form: no HTML, solidus or
// U+2028/U+2029 escaping, and no Unicode normalization.
func appendCanonicalString(dst []byte, s string) []byte {
	dst = append(dst, '"')
	const digits = "0123456789abcdef"
	for _, c := range s {
		switch c {
		case '"', '\\':
			dst = append(dst, '\\', byte(c))
		case '\b':
			dst = append(dst, '\\', 'b')
		case '\t':
			dst = append(dst, '\\', 't')
		case '\n':
			dst = append(dst, '\\', 'n')
		case '\f':
			dst = append(dst, '\\', 'f')
		case '\r':
			dst = append(dst, '\\', 'r')
		default:
			if c < 0x20 {
				dst = append(dst, '\\', 'u', '0', '0', digits[c>>4], digits[c&15])
			} else {
				dst = utf8.AppendRune(dst, c)
			}
		}
	}
	return append(dst, '"')
}
