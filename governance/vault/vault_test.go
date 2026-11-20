package vault

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The expected values in sdk/testdata/vault-envelope-vectors.json come from an independent reference
// (generate_vault_envelope_vectors.py: the Python `cryptography` package and its own RFC 8785
// canonicalizer), not from this package, so these tests check the implementation against bytes it did not
// produce.

type vectorFile struct {
	Positive []struct {
		Name            string `json:"name"`
		Kind            Kind   `json:"kind"`
		OrganizationID  string `json:"organization_id"`
		OperationID     string `json:"operation_id"`
		KeyRef          string `json:"key_ref"`
		DataKeyHex      string `json:"data_key_hex"`
		WrappedKeyB64   string `json:"wrapped_key_b64"`
		NonceHex        string `json:"nonce_hex"`
		RecordJSON      string `json:"record_json"`
		CanonicalRecord string `json:"canonical_record"`
		Header          string `json:"header"`
		AAD             string `json:"aad"`
		CiphertextHex   string `json:"ciphertext_hex"`
		EnvelopeB64     string `json:"envelope_b64"`
		CiphertextDig   string `json:"ciphertext_digest"`
	} `json:"positive"`
	Negative []struct {
		Name        string `json:"name"`
		Base        string `json:"base"`
		EnvelopeB64 string `json:"envelope_b64"`
	} `json:"negative"`
	InvalidRecords []struct {
		Name       string `json:"name"`
		RecordJSON string `json:"record_json"`
	} `json:"invalid_records"`
	InvalidIDs []struct {
		Name           string `json:"name"`
		OrganizationID string `json:"organization_id"`
		OperationID    string `json:"operation_id"`
	} `json:"invalid_ids"`
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "vault-envelope-vectors.json"))
	if os.IsNotExist(err) {
		// A standalone mirror keeps the shared fixtures in a testdata directory at its root.
		raw, err = os.ReadFile(filepath.Join("..", "..", "testdata", "vault-envelope-vectors.json"))
	}
	if err != nil {
		t.Fatal(err)
	}
	var vectors vectorFile
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors.Positive) == 0 || len(vectors.Negative) == 0 {
		t.Fatal("the vector file is empty")
	}
	return vectors
}

// fixedBackend returns one known data key for one known wrapped key, like a key service holding that key.
type fixedBackend struct {
	wrapped []byte
	key     []byte
}

func (f fixedBackend) GenerateDataKey(context.Context, string) ([]byte, []byte, error) {
	return nil, nil, errors.New("not used")
}

func (f fixedBackend) Decrypt(_ context.Context, _ string, wrapped []byte) ([]byte, error) {
	if !bytes.Equal(wrapped, f.wrapped) {
		return nil, ErrInvalidWrappedKey
	}
	return append([]byte(nil), f.key...), nil
}

func mustDecode(t *testing.T, text string, decode func(string) ([]byte, error)) []byte {
	t.Helper()
	out, err := decode(text)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestVectorsReproduceTheReferenceBytesAndOpen(t *testing.T) {
	for _, v := range loadVectors(t).Positive {
		t.Run(v.Name, func(t *testing.T) {
			dataKey := mustDecode(t, v.DataKeyHex, hex.DecodeString)
			wrapped := mustDecode(t, v.WrappedKeyB64, base64.StdEncoding.DecodeString)
			nonce := mustDecode(t, v.NonceHex, hex.DecodeString)

			plaintext, err := canonicalRecord(json.RawMessage(v.RecordJSON))
			if err != nil {
				t.Fatal(err)
			}
			if string(plaintext) != v.CanonicalRecord {
				t.Fatalf("canonical record\n got %s\nwant %s", plaintext, v.CanonicalRecord)
			}
			if got := aad(v.Kind, v.OrganizationID, v.OperationID, v.KeyRef); string(got) != v.AAD {
				t.Fatalf("aad\n got %s\nwant %s", got, v.AAD)
			}
			envelope, err := seal(v.Kind, v.OrganizationID, v.OperationID, v.KeyRef, dataKey, wrapped, nonce, plaintext)
			if err != nil {
				t.Fatal(err)
			}
			want := mustDecode(t, v.EnvelopeB64, base64.StdEncoding.DecodeString)
			if !bytes.Equal(envelope, want) {
				t.Fatalf("envelope differs from the reference\n got %x\nwant %x", envelope, want)
			}
			if !bytes.Contains(envelope, []byte(v.Header)) || !strings.HasSuffix(hex.EncodeToString(envelope), v.CiphertextHex) {
				t.Fatal("header or ciphertext not found in the envelope")
			}
			header, opened, err := Open(context.Background(), fixedBackend{wrapped: wrapped, key: dataKey}, want)
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			if string(opened) != v.CanonicalRecord || header.Kind != v.Kind || header.OrganizationID != v.OrganizationID ||
				header.OperationID != v.OperationID || header.KeyRef != v.KeyRef {
				t.Fatalf("opened %s with %+v", opened, header)
			}
		})
	}
}

func TestVectorsRejectEveryNegativeCase(t *testing.T) {
	vectors := loadVectors(t)
	base := vectors.Positive[0]
	backend := fixedBackend{
		wrapped: mustDecode(t, base.WrappedKeyB64, base64.StdEncoding.DecodeString),
		key:     mustDecode(t, base.DataKeyHex, hex.DecodeString),
	}
	for _, n := range vectors.Negative {
		t.Run(n.Name, func(t *testing.T) {
			blob := mustDecode(t, n.EnvelopeB64, base64.StdEncoding.DecodeString)
			_, plaintext, err := Open(context.Background(), backend, blob)
			if err == nil || plaintext != nil {
				t.Fatalf("expected a rejection, got plaintext=%q err=%v", plaintext, err)
			}
			if !errors.Is(err, ErrEnvelope) {
				t.Fatalf("expected ErrEnvelope, got %v", err)
			}
		})
	}
}

func TestSealRefusesInvalidRecordsAndIdentifiers(t *testing.T) {
	backend := NewMemoryBackend()
	vectors := loadVectors(t)
	for _, r := range vectors.InvalidRecords {
		t.Run("record/"+r.Name, func(t *testing.T) {
			if _, err := Seal(context.Background(), backend, "alias/k", KindInput, "org_1", "op-1", json.RawMessage(r.RecordJSON)); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("expected ErrInvalidInput, got %v", err)
			}
		})
	}
	for _, id := range vectors.InvalidIDs {
		t.Run("id/"+id.Name, func(t *testing.T) {
			if _, err := Seal(context.Background(), backend, "alias/k", KindInput, id.OrganizationID, id.OperationID, map[string]any{"a": 1}); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("expected ErrInvalidInput, got %v", err)
			}
		})
	}
	for name, call := range map[string]func() error{
		"nil record": func() error {
			_, err := Seal(context.Background(), backend, "alias/k", KindInput, "org_1", "op-1", nil)
			return err
		},
		"bad kind": func() error {
			_, err := Seal(context.Background(), backend, "alias/k", Kind("both"), "org_1", "op-1", map[string]any{})
			return err
		},
		"empty key": func() error {
			_, err := Seal(context.Background(), backend, "", KindInput, "org_1", "op-1", map[string]any{})
			return err
		},
		"nil backend": func() error {
			_, err := Seal(context.Background(), nil, "alias/k", KindInput, "org_1", "op-1", map[string]any{})
			return err
		},
		"record 8MiB+": func() error {
			big := map[string]any{"a": strings.Repeat("x", MaxRecordSize)}
			_, err := Seal(context.Background(), backend, "alias/k", KindInput, "org_1", "op-1", big)
			return err
		},
	} {
		if err := call(); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("%s: expected ErrInvalidInput, got %v", name, err)
		}
	}
	if len(backend.Calls()) != 0 {
		t.Fatal("a refused record must never reach the key backend")
	}
}

func TestRoundTripUsesAFreshKeyAndNonceEachTime(t *testing.T) {
	backend := NewMemoryBackend()
	ctx := context.Background()
	record := map[string]any{"tool": "pay", "amount": 12}
	first, err := Seal(ctx, backend, "alias/team-a", KindInput, "org_1", "op-1", record)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Seal(ctx, backend, "alias/team-a", KindInput, "org_1", "op-1", record)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("two seals of the same record must differ")
	}
	h1, _, _ := parseEnvelope(first)
	h2, _, _ := parseEnvelope(second)
	if bytes.Equal(h1.Nonce, h2.Nonce) || bytes.Equal(h1.WrappedKey, h2.WrappedKey) {
		t.Fatal("each seal needs its own nonce and data key")
	}
	header, plaintext, err := Open(ctx, backend, first)
	if err != nil {
		t.Fatal(err)
	}
	if string(plaintext) != `{"amount":12,"tool":"pay"}` || header.KeyRef != "alias/team-a" {
		t.Fatalf("got %s %+v", plaintext, header)
	}
	generate, decrypt := 0, 0
	for _, call := range backend.Calls() {
		if call.Context["organization_id"] != "org_1" || call.Context["operation_id"] != "op-1" {
			t.Fatalf("the key service must see the encryption context: %+v", call)
		}
		if call.Op == "GenerateDataKey" {
			generate++
		} else {
			decrypt++
		}
	}
	if generate != 2 || decrypt != 1 {
		t.Fatalf("calls: %d generate, %d decrypt", generate, decrypt)
	}
}

func TestDestroyedKeyMakesTheEnvelopeUnreadable(t *testing.T) {
	backend := NewMemoryBackend()
	ctx := context.Background()
	canary := "CANARY-plaintext-7f3a"
	envelope, err := Seal(ctx, backend, "alias/person-1", KindInput, "org_1", "op-1", map[string]any{"secret": canary})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(envelope, []byte(canary)) {
		t.Fatal("the envelope must not hold the plaintext")
	}
	backend.DestroyKey("alias/person-1")
	_, plaintext, err := Open(ctx, backend, envelope)
	if !errors.Is(err, ErrKeyDestroyed) || !errors.Is(err, ErrKeyBackend) || plaintext != nil {
		t.Fatalf("expected a destroyed-key error and no plaintext, got %q %v", plaintext, err)
	}
	if _, err := Seal(ctx, backend, "alias/person-1", KindInput, "org_1", "op-2", map[string]any{"a": 1}); err == nil {
		t.Fatal("a destroyed key must not wrap new data keys")
	}
	// Another key is unaffected.
	if _, err := Seal(ctx, backend, "alias/person-2", KindInput, "org_1", "op-3", map[string]any{"a": 1}); err != nil {
		t.Fatalf("other keys keep working: %v", err)
	}
}

func TestErrorsNeverCarryKeyOrPlaintextMaterial(t *testing.T) {
	backend := NewMemoryBackend()
	ctx := context.Background()
	canary := "CANARY-plaintext-91bc"
	envelope, err := Seal(ctx, backend, "alias/k", KindOutput, "org_1", "op-1", map[string]any{"v": canary})
	if err != nil {
		t.Fatal(err)
	}
	header, _, _ := parseEnvelope(envelope)
	wrappedText := base64.StdEncoding.EncodeToString(header.WrappedKey)
	tampered := bytes.Clone(envelope)
	tampered[len(tampered)-1] ^= 1
	backend.DestroyKey("alias/k")
	failures := []error{}
	_, _, e1 := Open(ctx, backend, tampered)
	_, _, e2 := Open(ctx, backend, envelope)
	_, _, e3 := Open(ctx, backend, []byte("garbage"))
	_, e4 := Seal(ctx, NewMemoryBackend(), "alias/k", KindInput, "org_1", "op-1", json.RawMessage(`{"v":"`+canary+`","bad":1.5}`))
	failures = append(failures, e1, e2, e3, e4)
	for i, err := range failures {
		if err == nil {
			t.Fatalf("case %d: expected an error", i)
		}
		text := err.Error()
		if strings.Contains(text, canary) || strings.Contains(text, wrappedText) || strings.Contains(text, hex.EncodeToString(header.WrappedKey)) {
			t.Fatalf("case %d leaks material: %s", i, text)
		}
	}
}

func TestOpenBindsTheEnvelopeToItsKeyReference(t *testing.T) {
	backend := NewMemoryBackend()
	ctx := context.Background()
	envelope, err := Seal(ctx, backend, "alias/a", KindInput, "org_1", "op-1", map[string]any{"a": 1})
	if err != nil {
		t.Fatal(err)
	}
	// A header rewritten to name another key is rejected: the wrapped key is bound to its own key.
	rewritten := bytes.Replace(envelope, []byte(`"key_ref":"alias/a"`), []byte(`"key_ref":"alias/b"`), 1)
	if _, _, err := Open(ctx, backend, rewritten); err == nil {
		t.Fatal("a rewritten key reference must not open")
	}
}

type stubObjects struct {
	version string
	err     error
	calls   []string
	body    []byte
	until   time.Time
	mode    RetentionMode
}

func (s *stubObjects) PutLocked(_ context.Context, key string, body []byte, r Retention) (string, error) {
	s.calls = append(s.calls, key)
	s.body, s.until, s.mode = body, r.Until, r.Mode
	return s.version, s.err
}

func TestWriterReturnsAPointerWithoutContentOrKeyMaterial(t *testing.T) {
	backend := NewMemoryBackend()
	objects := NewMemoryObjectWriter()
	now := time.Date(2026, 11, 9, 23, 59, 59, 0, time.FixedZone("x", -5*3600))
	writer, err := NewWriter(WriterConfig{Backend: backend, Objects: objects, KeyRef: "alias/team", RetentionMode: RetentionCompliance, RetentionPeriod: 24 * time.Hour, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	canary := "CANARY-record-55aa"
	ptr, err := writer.Write(context.Background(), KindInput, "org_1", "op-9", 1, map[string]any{"text": canary})
	if err != nil {
		t.Fatal(err)
	}
	if ptr.ObjectKey != "vault/org_1/2026/11/op-9/input-1.opkv" || ptr.VersionID == "" || ptr.KeyRef != "alias/team" || ptr.Kind != KindInput {
		t.Fatalf("pointer %+v", ptr)
	}
	stored, ok := objects.Get(ptr.ObjectKey)
	if !ok || stored.Retention.Mode != RetentionCompliance || !stored.Retention.Until.Equal(now.UTC().Add(24*time.Hour)) {
		t.Fatalf("stored %+v", stored)
	}
	if ptr.CiphertextDigest != "sha256:"+sha256Hex(stored.Body) {
		t.Fatalf("digest %s", ptr.CiphertextDigest)
	}
	pointerJSON, _ := json.Marshal(ptr)
	if strings.Contains(string(pointerJSON), canary) || bytes.Contains(stored.Body, []byte(canary)) {
		t.Fatal("neither the pointer nor the stored object may hold the record text")
	}
	if _, err := writer.Write(context.Background(), KindInput, "org_1", "op-9", 1, map[string]any{"text": "again"}); err == nil {
		t.Fatal("writing the same object key twice must fail")
	}
}

func TestWriterNeverSkipsAFailedWrite(t *testing.T) {
	for name, objects := range map[string]*stubObjects{
		"store error":      {err: errors.New("bucket unavailable CANARY-store")},
		"empty version id": {version: ""},
	} {
		t.Run(name, func(t *testing.T) {
			writer, err := NewWriter(WriterConfig{Backend: NewMemoryBackend(), Objects: objects, KeyRef: "alias/k", RetentionMode: RetentionGovernance, RetentionPeriod: time.Hour})
			if err != nil {
				t.Fatal(err)
			}
			ptr, err := writer.Write(context.Background(), KindOutput, "org_1", "op-1", 2, map[string]any{"a": 1})
			if !errors.Is(err, ErrObjectWrite) || ptr != (Pointer{}) {
				t.Fatalf("expected ErrObjectWrite and no pointer, got %+v %v", ptr, err)
			}
			if len(objects.calls) != 1 {
				t.Fatalf("expected one write attempt, got %d", len(objects.calls))
			}
		})
	}
	failing := &failingBackend{}
	writer, _ := NewWriter(WriterConfig{Backend: failing, Objects: &stubObjects{version: "v1"}, KeyRef: "alias/k", RetentionMode: RetentionGovernance, RetentionPeriod: time.Hour})
	if _, err := writer.Write(context.Background(), KindInput, "org_1", "op-1", 1, map[string]any{"a": 1}); !errors.Is(err, ErrKeyBackend) {
		t.Fatalf("a key service failure must fail the write, got %v", err)
	}
}

type failingBackend struct{}

func (failingBackend) GenerateDataKey(context.Context, string) ([]byte, []byte, error) {
	return nil, nil, errors.New("key service down")
}
func (failingBackend) Decrypt(context.Context, string, []byte) ([]byte, error) {
	return nil, errors.New("key service down")
}

func TestNewWriterValidatesItsConfiguration(t *testing.T) {
	ok := WriterConfig{Backend: NewMemoryBackend(), Objects: NewMemoryObjectWriter(), KeyRef: "alias/k", RetentionMode: RetentionCompliance, RetentionPeriod: time.Hour}
	if _, err := NewWriter(ok); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*WriterConfig){
		"no backend":     func(c *WriterConfig) { c.Backend = nil },
		"no objects":     func(c *WriterConfig) { c.Objects = nil },
		"no key":         func(c *WriterConfig) { c.KeyRef = "" },
		"bad mode":       func(c *WriterConfig) { c.RetentionMode = "NONE" },
		"zero retention": func(c *WriterConfig) { c.RetentionPeriod = 0 },
		"long key":       func(c *WriterConfig) { c.KeyRef = strings.Repeat("k", 257) },
	} {
		cfg := ok
		mutate(&cfg)
		if _, err := NewWriter(cfg); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("%s: expected ErrInvalidInput, got %v", name, err)
		}
	}
}

func TestObjectKeyValidation(t *testing.T) {
	when := time.Date(2026, 1, 31, 23, 30, 0, 0, time.UTC)
	got, err := ObjectKey("org_1", when, "op-1", KindOutput, 3)
	if err != nil || got != "vault/org_1/2026/01/op-1/output-3.opkv" {
		t.Fatalf("got %q %v", got, err)
	}
	for name, call := range map[string]func() (string, error){
		"zero n":        func() (string, error) { return ObjectKey("org_1", when, "op-1", KindInput, 0) },
		"bad kind":      func() (string, error) { return ObjectKey("org_1", when, "op-1", Kind("x"), 1) },
		"slash in org":  func() (string, error) { return ObjectKey("a/b", when, "op-1", KindInput, 1) },
		"dot operation": func() (string, error) { return ObjectKey("org_1", when, "..", KindInput, 1) },
		"dot org":       func() (string, error) { return ObjectKey(".", when, "op-1", KindInput, 1) },
		"empty op":      func() (string, error) { return ObjectKey("org_1", when, "", KindInput, 1) },
	} {
		if _, err := call(); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("%s: expected ErrInvalidInput, got %v", name, err)
		}
	}
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
