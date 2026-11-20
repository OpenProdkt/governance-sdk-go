package governance

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/OpenProdkt/governance-sdk-go/governance/vault"
)

const vaultTestDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

func validTestRef(kind string) *VaultRef {
	return &VaultRef{Kind: kind, ObjectKey: "vault/org_1/2026/10/op-1/" + kind + "-1.opkv", VersionID: "v1", KeyRef: "alias/test", CiphertextDigest: vaultTestDigest}
}

type vaultFixture struct {
	backend *vault.MemoryBackend
	objects *vault.MemoryObjectWriter
	writer  *vault.Writer
}

func newVaultFixture(t *testing.T) *vaultFixture {
	t.Helper()
	backend := vault.NewMemoryBackend()
	objects := vault.NewMemoryObjectWriter()
	writer, err := vault.NewWriter(vault.WriterConfig{Backend: backend, Objects: objects, KeyRef: "alias/test", RetentionMode: vault.RetentionGovernance, RetentionPeriod: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	return &vaultFixture{backend: backend, objects: objects, writer: writer}
}

// openAll opens every stored object and returns its record text, keyed by object key.
func (f *vaultFixture) openAll(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, key := range f.objects.Keys() {
		object, _ := f.objects.Get(key)
		_, plaintext, err := vault.Open(context.Background(), f.backend, object.Body)
		if err != nil {
			t.Fatalf("open %s: %v", key, err)
		}
		out[key] = string(plaintext)
	}
	return out
}

// recordingServer is a PDP stand-in that records the path and body of every request.
type recordingServer struct {
	mu       sync.Mutex
	requests []recordedRequest
	server   *httptest.Server
}

type recordedRequest struct {
	path string
	body []byte
}

func newRecordingServer(t *testing.T, evaluateStatus int, evaluateBody string) *recordingServer {
	t.Helper()
	rs := &recordingServer{}
	rs.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		rs.mu.Lock()
		rs.requests = append(rs.requests, recordedRequest{path: r.URL.Path, body: body})
		rs.mu.Unlock()
		if r.URL.Path == "/v1/proxy/evaluate" {
			w.WriteHeader(evaluateStatus)
			_, _ = w.Write([]byte(evaluateBody))
			return
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"recorded":true}`))
	}))
	t.Cleanup(rs.server.Close)
	return rs
}

func (rs *recordingServer) all() []recordedRequest {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return append([]recordedRequest(nil), rs.requests...)
}

func (rs *recordingServer) byPath(path string) []recordedRequest {
	var out []recordedRequest
	for _, r := range rs.all() {
		if r.path == path {
			out = append(out, r)
		}
	}
	return out
}

func vaultTestRequest() EvaluateRequest {
	return EvaluateRequest{Version: "v1", Asset: EvaluateAsset{Key: "app.svc.prod"}, OperationID: "op-1", Transport: TransportContext{Kind: "http"}}
}

func TestVaultMembersWireShape(t *testing.T) {
	ref := validTestRef("input")
	encoded, err := json.Marshal(EvaluateRequest{Version: "v1", OperationID: "op-1", VaultRef: ref})
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if _, present := decoded["vault_gap"]; present {
		t.Fatalf("vault_gap must be omitted: %s", encoded)
	}
	var wireRef map[string]string
	if err := json.Unmarshal(decoded["vault_ref"], &wireRef); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"kind": "input", "object_key": ref.ObjectKey, "version_id": "v1", "key_ref": "alias/test", "ciphertext_digest": vaultTestDigest}
	if fmt.Sprint(wireRef) != fmt.Sprint(want) || len(wireRef) != 5 {
		t.Fatalf("vault_ref = %v", wireRef)
	}

	encoded, err = json.Marshal(OperationOutcomeRequest{OperationID: "op-1", Status: "succeeded", VaultGap: &VaultGap{Reason: VaultGapStorageUnavailable}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"vault_gap":{"reason":"storage_unavailable"}`) || strings.Contains(string(encoded), "vault_ref") {
		t.Fatalf("outcome body = %s", encoded)
	}

	for _, body := range []any{vaultTestRequest(), sampleOutcomeRequest()} {
		encoded, _ := json.Marshal(body)
		if strings.Contains(string(encoded), "vault") {
			t.Fatalf("absent members must be omitted: %s", encoded)
		}
	}
}

func TestNewVaultRefCopiesThePointer(t *testing.T) {
	pointer := vault.Pointer{ObjectKey: "k", VersionID: "v", KeyRef: "r", CiphertextDigest: vaultTestDigest, Kind: vault.KindOutput}
	ref := NewVaultRef(pointer)
	if ref != (VaultRef{Kind: "output", ObjectKey: "k", VersionID: "v", KeyRef: "r", CiphertextDigest: vaultTestDigest}) {
		t.Fatalf("ref = %+v", ref)
	}
}

func TestInvalidVaultMembersAreRefusedBeforeAnyRequest(t *testing.T) {
	rs := newRecordingServer(t, http.StatusOK, `{"decision":"allow"}`)
	client := NewClient(rs.server.URL, "key", time.Second)
	principal := &PrincipalContext{BearerToken: "explicit"}
	cases := []struct {
		name  string
		build func(kind string) (*VaultRef, *VaultGap)
	}{
		{"both set", func(k string) (*VaultRef, *VaultGap) {
			return validTestRef(k), &VaultGap{Reason: VaultGapWriteFailed}
		}},
		{"unknown reason", func(string) (*VaultRef, *VaultGap) { return nil, &VaultGap{Reason: "disk full"} }},
		{"empty reason", func(string) (*VaultRef, *VaultGap) { return nil, &VaultGap{} }},
		{"bad digest", func(k string) (*VaultRef, *VaultGap) {
			ref := validTestRef(k)
			ref.CiphertextDigest = "sha256:ABC"
			return ref, nil
		}},
		{"missing key ref", func(k string) (*VaultRef, *VaultGap) {
			ref := validTestRef(k)
			ref.KeyRef = ""
			return ref, nil
		}},
		{"unknown kind", func(k string) (*VaultRef, *VaultGap) {
			ref := validTestRef(k)
			ref.Kind = "side"
			return ref, nil
		}},
	}
	for _, tc := range cases {
		t.Run("evaluate "+tc.name, func(t *testing.T) {
			request := vaultTestRequest()
			request.VaultRef, request.VaultGap = tc.build("input")
			_, err := client.EvaluateProxy(context.Background(), request, principal)
			var invalid *InvalidAuthorizationInputError
			if !errors.As(err, &invalid) {
				t.Fatalf("err = %v", err)
			}
		})
		t.Run("outcome "+tc.name, func(t *testing.T) {
			report := sampleOutcomeRequest()
			report.VaultRef, report.VaultGap = tc.build("output")
			_, err := client.ReportOperationOutcome(context.Background(), report, principal)
			var invalid *InvalidAuthorizationInputError
			if !errors.As(err, &invalid) {
				t.Fatalf("err = %v", err)
			}
		})
	}
	// Direction: an output reference on an evaluate request and an input reference on a report.
	request := vaultTestRequest()
	request.VaultRef = validTestRef("output")
	if _, err := client.EvaluateProxy(context.Background(), request, principal); err == nil {
		t.Fatal("output ref accepted on evaluate")
	}
	report := sampleOutcomeRequest()
	report.VaultRef = validTestRef("input")
	if _, err := client.ReportOperationOutcome(context.Background(), report, principal); err == nil {
		t.Fatal("input ref accepted on report")
	}
	if n := len(rs.all()); n != 0 {
		t.Fatalf("%d network calls for invalid input", n)
	}
}

func TestValidVaultMembersAreSent(t *testing.T) {
	rs := newRecordingServer(t, http.StatusOK, `{"decision":"allow"}`)
	client := NewClient(rs.server.URL, "key", time.Second)
	principal := &PrincipalContext{BearerToken: "explicit"}
	request := vaultTestRequest()
	request.VaultRef = validTestRef("input")
	if _, err := client.EvaluateProxy(context.Background(), request, principal); err != nil {
		t.Fatal(err)
	}
	report := sampleOutcomeRequest()
	report.VaultGap = &VaultGap{Reason: VaultGapRecordTooLarge}
	if _, err := client.ReportOperationOutcome(context.Background(), report, principal); err != nil {
		t.Fatal(err)
	}
	if body := string(rs.byPath("/v1/proxy/evaluate")[0].body); !strings.Contains(body, `"vault_ref":{"kind":"input"`) {
		t.Fatalf("evaluate body = %s", body)
	}
	if body := string(rs.byPath("/v1/proxy/outcomes")[0].body); !strings.Contains(body, `"vault_gap":{"reason":"record_too_large"}`) {
		t.Fatalf("outcome body = %s", body)
	}
}

func TestVaultRequestsWithoutVaultAreUnchanged(t *testing.T) {
	// The body below is what the request encoded to before the vault members existed.
	request := vaultTestRequest()
	encoded, _ := json.Marshal(request)
	want := `{"version":"v1","asset":{"key":"app.svc.prod"},"operation_id":"op-1","transport":{"kind":"http"}}`
	if string(encoded) != want {
		t.Fatalf("evaluate body = %s", encoded)
	}
	report := OperationOutcomeRequest{OperationID: "op-1", Status: "succeeded", CompletedAt: time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)}
	encoded, _ = json.Marshal(report)
	want = `{"operation_id":"op-1","status":"succeeded","completed_at":"2026-10-18T12:00:00Z"}`
	if string(encoded) != want {
		t.Fatalf("outcome body = %s", encoded)
	}

	rs := newRecordingServer(t, http.StatusOK, `{"decision":"allow"}`)
	client := NewClient(rs.server.URL, "key", time.Second)
	if _, err := Guard(context.Background(), client, vaultTestRequest(), &PrincipalContext{BearerToken: "explicit"}, GuardOptions{}, func(context.Context) (int, error) { return 1, nil }); err != nil {
		t.Fatal(err)
	}
	for _, r := range rs.all() {
		if bytes.Contains(r.body, []byte("vault")) {
			t.Fatalf("vault-less guard sent %s", r.body)
		}
	}
}

type failingObjects struct{ err error }

func (f failingObjects) PutLocked(context.Context, string, []byte, vault.Retention) (string, error) {
	return "", f.err
}

func TestVaultGapReasonMapping(t *testing.T) {
	big := json.RawMessage(`{"k":"` + strings.Repeat("a", vault.MaxRecordSize) + `"}`)
	cases := []struct {
		name   string
		err    error
		record any
		want   string
	}{
		{"key backend", fmt.Errorf("%w: detail", vault.ErrKeyBackend), nil, VaultGapKeyServiceUnavailable},
		{"key destroyed", vault.ErrKeyDestroyed, nil, VaultGapKeyServiceUnavailable},
		{"key not found", vault.ErrKeyNotFound, nil, VaultGapKeyServiceUnavailable},
		{"wrapped key", vault.ErrInvalidWrappedKey, nil, VaultGapKeyServiceUnavailable},
		{"object write", fmt.Errorf("%w: x", vault.ErrObjectWrite), nil, VaultGapStorageUnavailable},
		{"too large raw", vault.ErrInvalidInput, big, VaultGapRecordTooLarge},
		{"too large map", vault.ErrInvalidInput, map[string]string{"k": strings.Repeat("a", vault.MaxRecordSize)}, VaultGapRecordTooLarge},
		{"invalid record", vault.ErrInvalidInput, map[string]any{"n": 1.5}, VaultGapWriteFailed},
		{"other", errors.New("boom"), nil, VaultGapWriteFailed},
		{"context", context.Canceled, nil, VaultGapWriteFailed},
	}
	for _, tc := range cases {
		if got := VaultGapReason(tc.err, tc.record); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestWriteVaultRecordMapsRealVaultFailures(t *testing.T) {
	ctx := context.Background()
	f := newVaultFixture(t)
	record := map[string]any{"v": 1, "x": "y"}

	ref, err := WriteVaultRecord(ctx, f.writer, vault.KindInput, "org_1", "op-1", record)
	if err != nil || ref.Kind != "input" || ref.KeyRef != "alias/test" {
		t.Fatalf("ref = %+v err = %v", ref, err)
	}
	if _, ok := f.objects.Get(ref.ObjectKey); !ok {
		t.Fatal("object not stored")
	}

	f.backend.DestroyKey("alias/test")
	assertReason := func(w VaultWriter, record any, want string) {
		t.Helper()
		_, err := WriteVaultRecord(ctx, w, vault.KindInput, "org_1", "op-2", record)
		var writeErr *VaultWriteError
		if !errors.As(err, &writeErr) || writeErr.Reason != want {
			t.Fatalf("err = %v, want reason %s", err, want)
		}
	}
	assertReason(f.writer, record, VaultGapKeyServiceUnavailable)

	storage, _ := vault.NewWriter(vault.WriterConfig{Backend: vault.NewMemoryBackend(), Objects: failingObjects{err: errors.New("secret-bucket-detail")}, KeyRef: "alias/test", RetentionMode: vault.RetentionGovernance, RetentionPeriod: time.Hour})
	assertReason(storage, record, VaultGapStorageUnavailable)
	assertReason(storage, json.RawMessage(`{"k":"`+strings.Repeat("a", vault.MaxRecordSize)+`"}`), VaultGapRecordTooLarge)
	assertReason(storage, map[string]any{"n": 1.5}, VaultGapWriteFailed)
}

type panicWriter struct{}

func (panicWriter) Write(context.Context, vault.Kind, string, string, int, any) (vault.Pointer, error) {
	panic("writer panic with secret-detail")
}

type fixedWriter struct{ pointer vault.Pointer }

func (w fixedWriter) Write(context.Context, vault.Kind, string, string, int, any) (vault.Pointer, error) {
	return w.pointer, nil
}

func TestWriteVaultRecordGuardsAgainstBadWriters(t *testing.T) {
	ctx := context.Background()
	_, err := WriteVaultRecord(ctx, panicWriter{}, vault.KindInput, "org_1", "op-1", map[string]any{"a": 1})
	var writeErr *VaultWriteError
	if !errors.As(err, &writeErr) || writeErr.Reason != VaultGapWriteFailed || strings.Contains(err.Error(), "secret") {
		t.Fatalf("panic err = %v", err)
	}
	_, err = WriteVaultRecord(ctx, fixedWriter{vault.Pointer{ObjectKey: "k", VersionID: "v", KeyRef: "r", CiphertextDigest: "bad", Kind: vault.KindInput}}, vault.KindInput, "org_1", "op-1", map[string]any{"a": 1})
	if !errors.As(err, &writeErr) {
		t.Fatalf("bad pointer accepted: %v", err)
	}
	_, err = WriteVaultRecord(ctx, fixedWriter{vault.Pointer{ObjectKey: "k", VersionID: "v", KeyRef: "r", CiphertextDigest: vaultTestDigest, Kind: vault.KindOutput}}, vault.KindInput, "org_1", "op-1", map[string]any{"a": 1})
	if !errors.As(err, &writeErr) {
		t.Fatalf("wrong kind accepted: %v", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	f := newVaultFixture(t)
	_, err = WriteVaultRecord(cancelled, f.writer, vault.KindInput, "org_1", "op-1", map[string]any{"a": 1})
	if !errors.Is(err, context.Canceled) || len(f.objects.Keys()) != 0 {
		t.Fatalf("cancelled write ran: %v", err)
	}
}

func TestVaultWriteErrorTextHasNoDetail(t *testing.T) {
	text := (&VaultWriteError{Reason: VaultGapStorageUnavailable}).Error()
	if text != "evidence vault write failed: storage_unavailable" {
		t.Fatal(text)
	}
}

func TestRecordNumbersAreUnique(t *testing.T) {
	seen := map[int]bool{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 500; j++ {
				n := nextRecordNumber()
				mu.Lock()
				if seen[n] {
					t.Errorf("duplicate record number %d", n)
				}
				seen[n] = true
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
}

// orderWriter records the order of writes together with the server's requests.
type orderWriter struct {
	inner  VaultWriter
	mu     sync.Mutex
	events *[]string
}

func (w *orderWriter) Write(ctx context.Context, kind vault.Kind, org, op string, n int, record any) (vault.Pointer, error) {
	w.mu.Lock()
	*w.events = append(*w.events, "write:"+string(kind))
	w.mu.Unlock()
	return w.inner.Write(ctx, kind, org, op, n, record)
}

func guardVaultServer(t *testing.T, events *[]string, mu *sync.Mutex) *recordingServer {
	t.Helper()
	rs := &recordingServer{}
	rs.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		rs.mu.Lock()
		rs.requests = append(rs.requests, recordedRequest{path: r.URL.Path, body: body})
		rs.mu.Unlock()
		mu.Lock()
		*events = append(*events, r.URL.Path)
		mu.Unlock()
		if r.URL.Path == "/v1/proxy/evaluate" {
			_, _ = w.Write([]byte(`{"decision":"allow"}`))
			return
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"recorded":true}`))
	}))
	t.Cleanup(rs.server.Close)
	return rs
}

func TestGuardVaultOrderAndReferences(t *testing.T) {
	f := newVaultFixture(t)
	var events []string
	var mu sync.Mutex
	rs := guardVaultServer(t, &events, &mu)
	client := NewClient(rs.server.URL, "key", time.Second)
	writer := &orderWriter{inner: f.writer, events: &events}
	executed := false
	result, err := Guard(context.Background(), client, vaultTestRequest(), &PrincipalContext{BearerToken: "explicit"}, GuardOptions{Vault: &GuardVault{
		Writer: writer, OrganizationID: "org_1",
		Input:  map[string]any{"v": 1, "type": "test.input", "amount_text": "12.50"},
		Output: func(result any) any { return map[string]any{"v": 1, "type": "test.output", "text": result} },
	}}, func(context.Context) (string, error) {
		mu.Lock()
		events = append(events, "callback")
		mu.Unlock()
		executed = true
		return "done", nil
	})
	if err != nil || result.ReportingError != nil || !executed {
		t.Fatalf("err = %v reporting = %v", err, result.ReportingError)
	}
	want := []string{"write:input", "/v1/proxy/evaluate", "callback", "write:output", "/v1/proxy/outcomes"}
	if fmt.Sprint(events) != fmt.Sprint(want) {
		t.Fatalf("order = %v", events)
	}

	var evaluate EvaluateRequest
	if err := json.Unmarshal(rs.byPath("/v1/proxy/evaluate")[0].body, &evaluate); err != nil {
		t.Fatal(err)
	}
	var report OperationOutcomeRequest
	if err := json.Unmarshal(rs.byPath("/v1/proxy/outcomes")[0].body, &report); err != nil {
		t.Fatal(err)
	}
	if evaluate.VaultRef == nil || evaluate.VaultRef.Kind != "input" || evaluate.VaultGap != nil {
		t.Fatalf("evaluate = %+v", evaluate)
	}
	if report.VaultRef == nil || report.VaultRef.Kind != "output" || report.VaultGap != nil || report.Status != "succeeded" {
		t.Fatalf("report = %+v", report)
	}
	records := f.openAll(t)
	if len(records) != 2 || !strings.Contains(records[evaluate.VaultRef.ObjectKey], `"amount_text":"12.50"`) || !strings.Contains(records[report.VaultRef.ObjectKey], `"text":"done"`) {
		t.Fatalf("records = %v", records)
	}
	if result.Report.VaultRef == nil || *result.Report.VaultRef != *report.VaultRef {
		t.Fatal("returned report differs from the sent one")
	}
}

func TestGuardVaultInputFailureFailsClosedByDefault(t *testing.T) {
	var events []string
	var mu sync.Mutex
	rs := guardVaultServer(t, &events, &mu)
	client := NewClient(rs.server.URL, "key", time.Second)
	f := newVaultFixture(t)
	f.backend.DestroyKey("alias/test")
	_, err := Guard(context.Background(), client, vaultTestRequest(), &PrincipalContext{BearerToken: "explicit"}, GuardOptions{Vault: &GuardVault{
		Writer: f.writer, OrganizationID: "org_1", Input: map[string]any{"v": 1},
	}}, func(context.Context) (int, error) { t.Fatal("callback ran"); return 0, nil })
	var writeErr *VaultWriteError
	if !errors.As(err, &writeErr) || writeErr.Reason != VaultGapKeyServiceUnavailable {
		t.Fatalf("err = %v", err)
	}
	if n := len(rs.all()); n != 0 {
		t.Fatalf("%d requests after a failed input write", n)
	}
}

func TestGuardVaultContinueWithoutVaultSendsGapReasons(t *testing.T) {
	huge := json.RawMessage(`{"k":"` + strings.Repeat("a", vault.MaxRecordSize) + `"}`)
	storage, _ := vault.NewWriter(vault.WriterConfig{Backend: vault.NewMemoryBackend(), Objects: failingObjects{err: errors.New("down")}, KeyRef: "alias/test", RetentionMode: vault.RetentionGovernance, RetentionPeriod: time.Hour})
	destroyed := newVaultFixture(t)
	destroyed.backend.DestroyKey("alias/test")
	healthy := newVaultFixture(t)
	cases := []struct {
		name   string
		writer VaultWriter
		input  any
		reason string
	}{
		{"key", destroyed.writer, map[string]any{"v": 1}, VaultGapKeyServiceUnavailable},
		{"storage", storage, map[string]any{"v": 1}, VaultGapStorageUnavailable},
		{"too large", healthy.writer, huge, VaultGapRecordTooLarge},
		{"invalid record", healthy.writer, map[string]any{"n": 1.5}, VaultGapWriteFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var events []string
			var mu sync.Mutex
			rs := guardVaultServer(t, &events, &mu)
			client := NewClient(rs.server.URL, "key", time.Second)
			called := 0
			result, err := Guard(context.Background(), client, vaultTestRequest(), &PrincipalContext{BearerToken: "explicit"}, GuardOptions{Vault: &GuardVault{
				Writer: tc.writer, OrganizationID: "org_1", Input: tc.input, ContinueWithoutVault: true,
			}}, func(context.Context) (int, error) { called++; return 1, nil })
			if err != nil || called != 1 || result.ReportingError != nil {
				t.Fatalf("err = %v called = %d", err, called)
			}
			var evaluate EvaluateRequest
			_ = json.Unmarshal(rs.byPath("/v1/proxy/evaluate")[0].body, &evaluate)
			if evaluate.VaultGap == nil || evaluate.VaultGap.Reason != tc.reason || evaluate.VaultRef != nil {
				t.Fatalf("evaluate = %+v", evaluate)
			}
			if strings.Contains(string(rs.byPath("/v1/proxy/outcomes")[0].body), "vault") {
				t.Fatal("report carries vault members without an output function")
			}
		})
	}
}

func TestGuardVaultOutputFailureKeepsTheResultAndReportsAGap(t *testing.T) {
	var events []string
	var mu sync.Mutex
	rs := guardVaultServer(t, &events, &mu)
	client := NewClient(rs.server.URL, "key", time.Second)
	f := newVaultFixture(t)
	failOutput := &switchWriter{inner: f.writer, failKind: vault.KindOutput}
	called := 0
	result, err := Guard(context.Background(), client, vaultTestRequest(), &PrincipalContext{BearerToken: "explicit"}, GuardOptions{Vault: &GuardVault{
		Writer: failOutput, OrganizationID: "org_1", Input: map[string]any{"v": 1},
		Output: func(any) any { return map[string]any{"v": 1} },
	}}, func(context.Context) (string, error) { called++; return "value", nil })
	if err != nil || result.Value != "value" || called != 1 {
		t.Fatalf("err = %v value = %v called = %d", err, result.Value, called)
	}
	var report OperationOutcomeRequest
	_ = json.Unmarshal(rs.byPath("/v1/proxy/outcomes")[0].body, &report)
	if report.Status != "succeeded" || report.VaultRef != nil || report.VaultGap == nil || report.VaultGap.Reason != VaultGapStorageUnavailable {
		t.Fatalf("report = %+v", report)
	}
	if len(rs.byPath("/v1/proxy/outcomes")) != 1 || len(rs.byPath("/v1/proxy/evaluate")) != 1 {
		t.Fatal("a failed output write must not replay anything")
	}
}

type switchWriter struct {
	inner    VaultWriter
	failKind vault.Kind
}

func (w *switchWriter) Write(ctx context.Context, kind vault.Kind, org, op string, n int, record any) (vault.Pointer, error) {
	if kind == w.failKind {
		return vault.Pointer{}, fmt.Errorf("%w: down", vault.ErrObjectWrite)
	}
	return w.inner.Write(ctx, kind, org, op, n, record)
}

func TestGuardVaultOutputRules(t *testing.T) {
	run := func(t *testing.T, output func(any) any, callback func(context.Context) (string, error)) (*recordingServer, *vaultFixture) {
		var events []string
		var mu sync.Mutex
		rs := guardVaultServer(t, &events, &mu)
		client := NewClient(rs.server.URL, "key", time.Second)
		f := newVaultFixture(t)
		func() {
			defer func() { _ = recover() }()
			_, _ = Guard(context.Background(), client, vaultTestRequest(), &PrincipalContext{BearerToken: "explicit"}, GuardOptions{Vault: &GuardVault{
				Writer: f.writer, OrganizationID: "org_1", Input: map[string]any{"v": 1}, Output: output,
			}}, callback)
		}()
		return rs, f
	}
	reportOf := func(rs *recordingServer) OperationOutcomeRequest {
		var report OperationOutcomeRequest
		_ = json.Unmarshal(rs.byPath("/v1/proxy/outcomes")[0].body, &report)
		return report
	}
	t.Run("nil record skips without a gap", func(t *testing.T) {
		rs, f := run(t, func(any) any { return nil }, func(context.Context) (string, error) { return "x", nil })
		if r := reportOf(rs); r.VaultRef != nil || r.VaultGap != nil || len(f.objects.Keys()) != 1 {
			t.Fatalf("report = %+v objects = %d", r, len(f.objects.Keys()))
		}
	})
	t.Run("callback error writes no output", func(t *testing.T) {
		called := false
		rs, f := run(t, func(any) any { called = true; return map[string]any{"v": 1} }, func(context.Context) (string, error) { return "", errors.New("failed") })
		if r := reportOf(rs); r.Status != "unknown" || r.VaultRef != nil || r.VaultGap != nil || called || len(f.objects.Keys()) != 1 {
			t.Fatalf("report = %+v", r)
		}
	})
	t.Run("callback panic writes no output", func(t *testing.T) {
		called := false
		rs, f := run(t, func(any) any { called = true; return map[string]any{"v": 1} }, func(context.Context) (string, error) { panic("private") })
		if r := reportOf(rs); r.Status != "unknown" || r.VaultRef != nil || r.VaultGap != nil || called || len(f.objects.Keys()) != 1 {
			t.Fatalf("report = %+v", r)
		}
	})
	t.Run("output function panic is a gap", func(t *testing.T) {
		rs, _ := run(t, func(any) any { panic("private") }, func(context.Context) (string, error) { return "x", nil })
		if r := reportOf(rs); r.Status != "succeeded" || r.VaultGap == nil || r.VaultGap.Reason != VaultGapWriteFailed {
			t.Fatalf("report = %+v", r)
		}
	})
	t.Run("without an output function the callback value is never read", func(t *testing.T) {
		const canary = "CANARY-callback-value"
		rs, f := run(t, nil, func(context.Context) (string, error) { return canary, nil })
		for _, r := range rs.all() {
			if strings.Contains(string(r.body), canary) {
				t.Fatalf("canary in %s", r.path)
			}
		}
		if len(f.objects.Keys()) != 1 {
			t.Fatal("only the input record may be stored")
		}
	})
}

func TestGuardVaultOptionValidation(t *testing.T) {
	rs := newRecordingServer(t, http.StatusOK, `{"decision":"allow"}`)
	client := NewClient(rs.server.URL, "key", time.Second)
	f := newVaultFixture(t)
	principal := &PrincipalContext{BearerToken: "explicit"}
	withRef := vaultTestRequest()
	withRef.VaultRef = validTestRef("input")
	noOp := vaultTestRequest()
	noOp.OperationID = ""
	cases := map[string]struct {
		request EvaluateRequest
		vault   *GuardVault
	}{
		"no writer":       {vaultTestRequest(), &GuardVault{OrganizationID: "org_1", Input: map[string]any{"v": 1}}},
		"no organization": {vaultTestRequest(), &GuardVault{Writer: f.writer, Input: map[string]any{"v": 1}}},
		"no input":        {vaultTestRequest(), &GuardVault{Writer: f.writer, OrganizationID: "org_1"}},
		"preset ref":      {withRef, &GuardVault{Writer: f.writer, OrganizationID: "org_1", Input: map[string]any{"v": 1}}},
		"no operation id": {noOp, &GuardVault{Writer: f.writer, OrganizationID: "org_1", Input: map[string]any{"v": 1}}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Guard(context.Background(), client, tc.request, principal, GuardOptions{Vault: tc.vault}, func(context.Context) (int, error) { t.Fatal("callback ran"); return 0, nil })
			var invalid *InvalidAuthorizationInputError
			if !errors.As(err, &invalid) {
				t.Fatalf("err = %v", err)
			}
		})
	}
	if len(f.objects.Keys()) != 0 || len(rs.all()) != 0 {
		t.Fatal("invalid options must not write or call the network")
	}
}

func TestGuardVaultCancelledContextWritesNothing(t *testing.T) {
	rs := newRecordingServer(t, http.StatusOK, `{"decision":"allow"}`)
	client := NewClient(rs.server.URL, "key", time.Second)
	f := newVaultFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, continueWithout := range []bool{false, true} {
		_, err := Guard(ctx, client, vaultTestRequest(), &PrincipalContext{BearerToken: "explicit"}, GuardOptions{Vault: &GuardVault{
			Writer: f.writer, OrganizationID: "org_1", Input: map[string]any{"v": 1}, ContinueWithoutVault: continueWithout,
		}}, func(context.Context) (int, error) { t.Fatal("callback ran"); return 0, nil })
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v", err)
		}
	}
	if len(f.objects.Keys()) != 0 || len(rs.all()) != 0 {
		t.Fatal("a cancelled call must not write or call the network")
	}
}

// TestGuardVaultCanaryStaysInTheVault checks that a plaintext marker supplied in the
// records leaves the process only inside the encrypted envelopes.
func TestGuardVaultCanaryStaysInTheVault(t *testing.T) {
	const canary = "CANARY-7f3a9c-plaintext"
	f := newVaultFixture(t)
	var events []string
	var mu sync.Mutex
	rs := guardVaultServer(t, &events, &mu)
	client := NewClient(rs.server.URL, "key", time.Second)
	result, err := Guard(context.Background(), client, vaultTestRequest(), &PrincipalContext{BearerToken: "explicit"}, GuardOptions{Vault: &GuardVault{
		Writer: f.writer, OrganizationID: "org_1",
		Input:  map[string]any{"v": 1, "secret": canary},
		Output: func(any) any { return map[string]any{"v": 1, "secret": canary} },
	}}, func(context.Context) (string, error) { return "ok", nil })
	if err != nil || result.ReportingError != nil {
		t.Fatalf("err = %v", err)
	}
	for _, r := range rs.all() {
		if strings.Contains(string(r.body), canary) {
			t.Fatalf("canary reached %s", r.path)
		}
	}
	reportText, _ := json.Marshal(result.Report)
	if strings.Contains(string(reportText), canary) {
		t.Fatal("canary in the report")
	}
	keys := f.objects.Keys()
	if len(keys) != 2 {
		t.Fatalf("objects = %v", keys)
	}
	for _, key := range keys {
		object, _ := f.objects.Get(key)
		if bytes.Contains(object.Body, []byte(canary)) {
			t.Fatalf("envelope %s holds the plaintext", key)
		}
	}
	for key, record := range f.openAll(t) {
		if !strings.Contains(record, canary) {
			t.Fatalf("%s does not open to the record: %s", key, record)
		}
	}

	// A failed write never echoes the record in its error either.
	broken := newVaultFixture(t)
	broken.backend.DestroyKey("alias/test")
	_, err = Guard(context.Background(), client, vaultTestRequest(), &PrincipalContext{BearerToken: "explicit"}, GuardOptions{Vault: &GuardVault{
		Writer: broken.writer, OrganizationID: "org_1", Input: map[string]any{"v": 1, "secret": canary},
	}}, func(context.Context) (int, error) { return 0, nil })
	if err == nil || strings.Contains(err.Error(), canary) || strings.Contains(fmt.Sprintf("%+v %#v", err, err), canary) {
		t.Fatalf("err = %v", err)
	}
}

func TestGuardVaultConcurrentCalls(t *testing.T) {
	f := newVaultFixture(t)
	var events []string
	var mu sync.Mutex
	rs := guardVaultServer(t, &events, &mu)
	client := NewClient(rs.server.URL, "key", time.Second)
	const calls = 16
	var wg sync.WaitGroup
	for i := 0; i < calls; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			request := vaultTestRequest()
			request.OperationID = fmt.Sprintf("op-%d", i)
			_, err := Guard(context.Background(), client, request, &PrincipalContext{BearerToken: "explicit"}, GuardOptions{Vault: &GuardVault{
				Writer: f.writer, OrganizationID: "org_1", Input: map[string]any{"v": 1, "i": i},
				Output: func(any) any { return map[string]any{"v": 1, "i": i} },
			}}, func(context.Context) (int, error) { return i, nil })
			if err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	if n := len(f.objects.Keys()); n != 2*calls {
		t.Fatalf("objects = %d", n)
	}
}
