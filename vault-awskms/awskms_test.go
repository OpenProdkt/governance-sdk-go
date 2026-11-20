package awskms

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/OpenProdkt/governance-sdk-go/governance/vault"
)

const (
	keyARN   = "arn:aws:kms:eu-west-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab"
	otherARN = "arn:aws:kms:eu-west-1:123456789012:key/99999999-12ab-34cd-56ef-1234567890ab"
	aliasARN = "arn:aws:kms:eu-west-1:123456789012:alias/records"
	aliasRef = "alias/records"
)

// scriptedClient returns fixed outputs and records the requests it receives.
type scriptedClient struct {
	genOut *kms.GenerateDataKeyOutput
	genErr error
	decOut *kms.DecryptOutput
	decErr error

	genIn []*kms.GenerateDataKeyInput
	decIn []*kms.DecryptInput
}

func (c *scriptedClient) GenerateDataKey(_ context.Context, in *kms.GenerateDataKeyInput, _ ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error) {
	c.genIn = append(c.genIn, in)
	return c.genOut, c.genErr
}

func (c *scriptedClient) Decrypt(_ context.Context, in *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	c.decIn = append(c.decIn, in)
	return c.decOut, c.decErr
}

func goodGen(keyID string) *kms.GenerateDataKeyOutput {
	return &kms.GenerateDataKeyOutput{
		Plaintext:      bytes.Repeat([]byte{7}, 32),
		CiphertextBlob: []byte("opaque-wrapped-blob"),
		KeyId:          aws.String(keyID),
	}
}

func goodDec(keyID string) *kms.DecryptOutput {
	return &kms.DecryptOutput{Plaintext: bytes.Repeat([]byte{7}, 32), KeyId: aws.String(keyID)}
}

func ctxWith(org, op string) context.Context {
	return vault.WithEncryptionContext(context.Background(), map[string]string{"organization_id": org, "operation_id": op})
}

func TestGenerateDataKeyRequestAndResult(t *testing.T) {
	client := &scriptedClient{genOut: goodGen(keyARN)}
	plaintext, wrapped, err := New(client).GenerateDataKey(ctxWith("org_1", "op-1"), keyARN)
	if err != nil {
		t.Fatal(err)
	}
	if len(plaintext) != 32 || string(wrapped) != "opaque-wrapped-blob" {
		t.Fatalf("unexpected result: %d bytes, %q", len(plaintext), wrapped)
	}
	if len(client.genIn) != 1 {
		t.Fatalf("expected one request, got %d", len(client.genIn))
	}
	in := client.genIn[0]
	if aws.ToString(in.KeyId) != keyARN || in.KeySpec != types.DataKeySpecAes256 || in.NumberOfBytes != nil {
		t.Fatalf("unexpected request: %+v", in)
	}
	if in.EncryptionContext["organization_id"] != "org_1" || in.EncryptionContext["operation_id"] != "op-1" || len(in.EncryptionContext) != 2 {
		t.Fatalf("unexpected encryption context: %v", in.EncryptionContext)
	}
}

func TestGenerateDataKeyReturnsCopiesAndZeroesItsBuffers(t *testing.T) {
	out := goodGen(keyARN)
	source := out.Plaintext
	client := &scriptedClient{genOut: out}
	plaintext, wrapped, err := New(client).GenerateDataKey(context.Background(), keyARN)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plaintext, bytes.Repeat([]byte{7}, 32)) {
		t.Fatal("returned key must keep its value")
	}
	if !bytes.Equal(source, make([]byte, 32)) {
		t.Fatal("the client's plaintext buffer must be zeroed")
	}
	wrapped[0] ^= 0xff
	if out.CiphertextBlob[0] == wrapped[0] {
		t.Fatal("wrapped key must be a copy")
	}
}

func TestNoEncryptionContextSendsNone(t *testing.T) {
	client := &scriptedClient{genOut: goodGen(keyARN)}
	if _, _, err := New(client).GenerateDataKey(context.Background(), keyARN); err != nil {
		t.Fatal(err)
	}
	if client.genIn[0].EncryptionContext != nil {
		t.Fatalf("expected no context, got %v", client.genIn[0].EncryptionContext)
	}
}

func TestKeyReferenceValidation(t *testing.T) {
	valid := []string{
		keyARN,
		aliasARN,
		aliasRef,
		"alias/team/records_1-a",
		"arn:aws-us-gov:kms:us-gov-west-1:123456789012:key/mrk-0123456789abcdef0123456789abcdef",
		"arn:aws-cn:kms:cn-north-1:123456789012:alias/records",
	}
	for _, ref := range valid {
		client := &scriptedClient{genOut: goodGen(ref)}
		if _, _, err := New(client).GenerateDataKey(context.Background(), ref); err != nil {
			t.Fatalf("%q should be accepted: %v", ref, err)
		}
	}
	invalid := []string{
		"",
		"1234abcd-12ab-34cd-56ef-1234567890ab",
		"alias/",
		"alias/bad name",
		"alias/records\n",
		"alias/" + strings.Repeat("a", 300),
		"arn:aws:kms:eu-west-1:12345678901:key/abc",
		"arn:aws:kms:eu-west-1:123456789012:key/",
		"arn:aws:kms:eu-west-1:123456789012:key/abc/def",
		"arn:aws:s3:::bucket",
		"arn:azure:kms:eu-west-1:123456789012:key/abc",
		"arn:aws:kms:EU:123456789012:key/abc",
		keyARN + " ",
		" " + keyARN,
		"arn:aws:kms:eu-west-1:123456789012:key/abc\nalias/x",
	}
	for _, ref := range invalid {
		client := &scriptedClient{genOut: goodGen(keyARN), decOut: goodDec(keyARN)}
		backend := New(client)
		_, _, err := backend.GenerateDataKey(context.Background(), ref)
		if !errors.Is(err, vault.ErrInvalidInput) {
			t.Fatalf("GenerateDataKey(%q) must be ErrInvalidInput, got %v", ref, err)
		}
		if _, err := backend.Decrypt(context.Background(), ref, []byte("blob")); !errors.Is(err, vault.ErrInvalidInput) {
			t.Fatalf("Decrypt(%q) must be ErrInvalidInput, got %v", ref, err)
		}
		if len(client.genIn)+len(client.decIn) != 0 {
			t.Fatalf("%q must be refused before any request", ref)
		}
		if ref != "" && strings.Contains(err.Error(), strings.TrimSpace(ref)) {
			t.Fatalf("the error must not echo the key reference: %v", err)
		}
	}
}

func TestGenerateDataKeyRefusesUnusableResponses(t *testing.T) {
	cases := map[string]*kms.GenerateDataKeyOutput{
		"nil output":      nil,
		"short plaintext": {Plaintext: make([]byte, 31), CiphertextBlob: []byte("x"), KeyId: aws.String(keyARN)},
		"long plaintext":  {Plaintext: make([]byte, 33), CiphertextBlob: []byte("x"), KeyId: aws.String(keyARN)},
		"no plaintext":    {CiphertextBlob: []byte("x"), KeyId: aws.String(keyARN)},
		"empty blob":      {Plaintext: make([]byte, 32), KeyId: aws.String(keyARN)},
		"oversized blob":  {Plaintext: make([]byte, 32), CiphertextBlob: make([]byte, 4097), KeyId: aws.String(keyARN)},
		"other key":       {Plaintext: make([]byte, 32), CiphertextBlob: []byte("x"), KeyId: aws.String(otherARN)},
		"missing key id":  {Plaintext: make([]byte, 32), CiphertextBlob: []byte("x")},
	}
	for name, out := range cases {
		plaintext, wrapped, err := New(&scriptedClient{genOut: out}).GenerateDataKey(context.Background(), keyARN)
		if err == nil || plaintext != nil || wrapped != nil {
			t.Fatalf("%s: expected a refusal, got %v", name, err)
		}
	}
	// The largest accepted blob is 4096 bytes.
	out := &kms.GenerateDataKeyOutput{Plaintext: make([]byte, 32), CiphertextBlob: make([]byte, 4096), KeyId: aws.String(keyARN)}
	if _, _, err := New(&scriptedClient{genOut: out}).GenerateDataKey(context.Background(), keyARN); err != nil {
		t.Fatalf("a 4096-byte blob is acceptable: %v", err)
	}
}

func TestGenerateDataKeyZeroesRefusedPlaintext(t *testing.T) {
	out := &kms.GenerateDataKeyOutput{Plaintext: bytes.Repeat([]byte{9}, 32), KeyId: aws.String(keyARN)}
	source := out.Plaintext
	if _, _, err := New(&scriptedClient{genOut: out}).GenerateDataKey(context.Background(), keyARN); err == nil {
		t.Fatal("expected a refusal")
	}
	if !bytes.Equal(source, make([]byte, 32)) {
		t.Fatal("a refused plaintext key must be zeroed")
	}
}

func TestAliasResponsesAcceptTheKeyARNBehindTheAlias(t *testing.T) {
	for _, ref := range []string{aliasRef, aliasARN} {
		client := &scriptedClient{genOut: goodGen(keyARN), decOut: goodDec(keyARN)}
		backend := New(client)
		if _, _, err := backend.GenerateDataKey(context.Background(), ref); err != nil {
			t.Fatalf("%q: %v", ref, err)
		}
		if _, err := backend.Decrypt(context.Background(), ref, []byte("blob")); err != nil {
			t.Fatalf("%q: %v", ref, err)
		}
		if aws.ToString(client.decIn[0].KeyId) != ref {
			t.Fatalf("Decrypt must name the alias in its request, got %q", aws.ToString(client.decIn[0].KeyId))
		}
	}
}

func TestDecryptRequestAndResult(t *testing.T) {
	out := goodDec(keyARN)
	source := out.Plaintext
	client := &scriptedClient{decOut: out}
	plaintext, err := New(client).Decrypt(ctxWith("org_1", "op-1"), keyARN, []byte("opaque-wrapped-blob"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plaintext, bytes.Repeat([]byte{7}, 32)) {
		t.Fatal("unexpected plaintext")
	}
	if !bytes.Equal(source, make([]byte, 32)) {
		t.Fatal("the client's plaintext buffer must be zeroed")
	}
	in := client.decIn[0]
	if aws.ToString(in.KeyId) != keyARN || string(in.CiphertextBlob) != "opaque-wrapped-blob" ||
		in.EncryptionContext["organization_id"] != "org_1" || in.EncryptionContext["operation_id"] != "op-1" {
		t.Fatalf("unexpected request: %+v", in)
	}
}

func TestEncryptionContextIsEqualForGenerateAndDecrypt(t *testing.T) {
	client := &scriptedClient{genOut: goodGen(keyARN), decOut: goodDec(keyARN)}
	backend := New(client)
	ctx := ctxWith("org_9", "op-9")
	_, wrapped, err := backend.GenerateDataKey(ctx, keyARN)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := backend.Decrypt(ctx, keyARN, wrapped); err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(client.genIn[0].EncryptionContext)
	b, _ := json.Marshal(client.decIn[0].EncryptionContext)
	if string(a) != string(b) || len(a) < 3 {
		t.Fatalf("contexts differ: %s vs %s", a, b)
	}
}

func TestDecryptRefusesUnusableInputAndResponses(t *testing.T) {
	backend := New(&scriptedClient{decOut: goodDec(keyARN)})
	for name, blob := range map[string][]byte{"nil": nil, "empty": {}, "oversized": make([]byte, 4097)} {
		if _, err := backend.Decrypt(context.Background(), keyARN, blob); !errors.Is(err, vault.ErrInvalidWrappedKey) {
			t.Fatalf("%s blob: expected ErrInvalidWrappedKey, got %v", name, err)
		}
	}
	cases := map[string]*kms.DecryptOutput{
		"nil output":      nil,
		"short plaintext": {Plaintext: make([]byte, 16), KeyId: aws.String(keyARN)},
		"long plaintext":  {Plaintext: make([]byte, 64), KeyId: aws.String(keyARN)},
		"no plaintext":    {KeyId: aws.String(keyARN)},
	}
	for name, out := range cases {
		plaintext, err := New(&scriptedClient{decOut: out}).Decrypt(context.Background(), keyARN, []byte("blob"))
		if err == nil || plaintext != nil {
			t.Fatalf("%s: expected a refusal, got %v", name, err)
		}
	}
}

func TestDecryptRefusesAResponseFromAnotherKey(t *testing.T) {
	out := goodDec(otherARN)
	source := out.Plaintext
	plaintext, err := New(&scriptedClient{decOut: out}).Decrypt(context.Background(), keyARN, []byte("blob"))
	if !errors.Is(err, vault.ErrInvalidWrappedKey) || plaintext != nil {
		t.Fatalf("expected ErrInvalidWrappedKey and no plaintext, got %q %v", plaintext, err)
	}
	if !bytes.Equal(source, make([]byte, 32)) {
		t.Fatal("a refused plaintext key must be zeroed")
	}
	missing := &kms.DecryptOutput{Plaintext: make([]byte, 32)}
	if _, err := New(&scriptedClient{decOut: missing}).Decrypt(context.Background(), keyARN, []byte("blob")); !errors.Is(err, vault.ErrInvalidWrappedKey) {
		t.Fatalf("a response without a key id must be refused for an ARN reference, got %v", err)
	}
}

func TestKMSErrorMapping(t *testing.T) {
	secret := "CANARY-secret-message"
	cases := []struct {
		name      string
		err       error
		destroyed bool
		notFound  bool
		invalid   bool
	}{
		{"disabled", &types.DisabledException{Message: aws.String(secret)}, true, false, false},
		{"unavailable", &types.KeyUnavailableException{Message: aws.String(secret)}, true, false, false},
		{"pending deletion", &types.KMSInvalidStateException{Message: aws.String(secret)}, true, false, false},
		{"not found", &types.NotFoundException{Message: aws.String(secret)}, true, true, false},
		{"invalid ciphertext", &types.InvalidCiphertextException{Message: aws.String(secret)}, false, false, true},
		{"incorrect key", &types.IncorrectKeyException{Message: aws.String(secret)}, false, false, true},
		{"wrapped in another error", errors.Join(errors.New("operation error"), &types.DisabledException{Message: aws.String(secret)}), true, false, false},
		{"other service error", &types.InvalidKeyUsageException{Message: aws.String(secret)}, false, false, false},
		{"plain error", errors.New(secret), false, false, false},
	}
	for _, c := range cases {
		client := &scriptedClient{genErr: c.err, decErr: c.err}
		backend := New(client)
		_, _, genErr := backend.GenerateDataKey(context.Background(), keyARN)
		_, decErr := backend.Decrypt(context.Background(), keyARN, []byte("blob"))
		for op, err := range map[string]error{"GenerateDataKey": genErr, "Decrypt": decErr} {
			if err == nil {
				t.Fatalf("%s/%s: expected an error", c.name, op)
			}
			if errors.Is(err, vault.ErrKeyDestroyed) != c.destroyed ||
				errors.Is(err, vault.ErrKeyNotFound) != c.notFound ||
				errors.Is(err, vault.ErrInvalidWrappedKey) != c.invalid {
				t.Fatalf("%s/%s: wrong classification: %v", c.name, op, err)
			}
			if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), keyARN) {
				t.Fatalf("%s/%s: the error leaks service text or the key reference: %v", c.name, op, err)
			}
			if c.name == "plain error" && (errors.Is(err, vault.ErrInvalidInput) || errors.Is(err, vault.ErrKeyDestroyed)) {
				t.Fatalf("a plain error must stay plain: %v", err)
			}
		}
	}
}

func TestContextCancellation(t *testing.T) {
	client := &scriptedClient{genOut: goodGen(keyARN), decOut: goodDec(keyARN)}
	backend := New(client)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := backend.GenerateDataKey(ctx, keyARN); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if _, err := backend.Decrypt(ctx, keyARN, []byte("blob")); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if len(client.genIn)+len(client.decIn) != 0 {
		t.Fatal("no request may be sent on a cancelled context")
	}

	// Cancelled while the request is in flight: the failure keeps the context error.
	inflight, cancelInflight := context.WithCancel(context.Background())
	failing := &cancellingClient{cancel: cancelInflight}
	if _, _, err := New(failing).GenerateDataKey(inflight, keyARN); !errors.Is(err, context.Canceled) || errors.Is(err, vault.ErrKeyDestroyed) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

type cancellingClient struct{ cancel context.CancelFunc }

func (c *cancellingClient) GenerateDataKey(context.Context, *kms.GenerateDataKeyInput, ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error) {
	c.cancel()
	return nil, errors.New("request aborted")
}

func (c *cancellingClient) Decrypt(context.Context, *kms.DecryptInput, ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	c.cancel()
	return nil, errors.New("request aborted")
}

func TestEncryptionContextIsValidated(t *testing.T) {
	big := map[string]string{}
	for i := 0; i < 17; i++ {
		big[strings.Repeat("k", i+1)] = "v"
	}
	bad := []map[string]string{
		big,
		{"organization_id": ""},
		{"": "value"},
		{"organization_id": strings.Repeat("a", 257)},
	}
	for _, values := range bad {
		client := &scriptedClient{genOut: goodGen(keyARN), decOut: goodDec(keyARN)}
		ctx := vault.WithEncryptionContext(context.Background(), values)
		if _, _, err := New(client).GenerateDataKey(ctx, keyARN); !errors.Is(err, vault.ErrInvalidInput) {
			t.Fatalf("expected ErrInvalidInput for %v, got %v", values, err)
		}
		if _, err := New(client).Decrypt(ctx, keyARN, []byte("blob")); !errors.Is(err, vault.ErrInvalidInput) {
			t.Fatalf("expected ErrInvalidInput for %v, got %v", values, err)
		}
		if len(client.genIn)+len(client.decIn) != 0 {
			t.Fatal("no request may be sent")
		}
	}
}

func TestNilClientFailsClosed(t *testing.T) {
	if _, _, err := New(nil).GenerateDataKey(context.Background(), keyARN); err == nil {
		t.Fatal("expected an error")
	}
	if _, err := New(nil).Decrypt(context.Background(), keyARN, []byte("blob")); err == nil {
		t.Fatal("expected an error")
	}
	var none *Backend
	if _, _, err := none.GenerateDataKey(context.Background(), keyARN); err == nil {
		t.Fatal("expected an error")
	}
}

// fakeKMS wraps data keys for real with AES-256-GCM, binds the encryption context and the
// key to the wrapped blob, and refuses anything else the way KMS does.
type fakeKMS struct {
	keys     map[string][]byte // key ARN -> key-encryption key
	aliases  map[string]string // alias -> key ARN
	disabled map[string]bool
	seen     []map[string]string
}

func newFakeKMS() *fakeKMS {
	f := &fakeKMS{keys: map[string][]byte{}, aliases: map[string]string{aliasRef: keyARN}, disabled: map[string]bool{}}
	for _, arn := range []string{keyARN, otherARN} {
		kek := make([]byte, 32)
		_, _ = rand.Read(kek)
		f.keys[arn] = kek
	}
	return f
}

func (f *fakeKMS) resolve(id string) (string, error) {
	if arn, ok := f.aliases[id]; ok {
		id = arn
	}
	if _, ok := f.keys[id]; !ok {
		return "", &types.NotFoundException{}
	}
	if f.disabled[id] {
		return "", &types.DisabledException{}
	}
	return id, nil
}

func contextAAD(values map[string]string) []byte {
	raw, _ := json.Marshal(values) // map keys are sorted by encoding/json
	return raw
}

func (f *fakeKMS) gcm(arn string) cipher.AEAD {
	block, _ := aes.NewCipher(f.keys[arn])
	g, _ := cipher.NewGCM(block)
	return g
}

func (f *fakeKMS) GenerateDataKey(_ context.Context, in *kms.GenerateDataKeyInput, _ ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error) {
	arn, err := f.resolve(aws.ToString(in.KeyId))
	if err != nil {
		return nil, err
	}
	if in.KeySpec != types.DataKeySpecAes256 {
		return nil, errors.New("unexpected key spec")
	}
	f.seen = append(f.seen, in.EncryptionContext)
	dataKey := make([]byte, 32)
	nonce := make([]byte, 12)
	_, _ = rand.Read(dataKey)
	_, _ = rand.Read(nonce)
	blob := append(nonce, f.gcm(arn).Seal(nil, nonce, dataKey, contextAAD(in.EncryptionContext))...)
	return &kms.GenerateDataKeyOutput{Plaintext: dataKey, CiphertextBlob: blob, KeyId: aws.String(arn)}, nil
}

func (f *fakeKMS) Decrypt(_ context.Context, in *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	arn, err := f.resolve(aws.ToString(in.KeyId))
	if err != nil {
		return nil, err
	}
	f.seen = append(f.seen, in.EncryptionContext)
	if len(in.CiphertextBlob) < 12 {
		return nil, &types.InvalidCiphertextException{}
	}
	nonce, body := in.CiphertextBlob[:12], in.CiphertextBlob[12:]
	plaintext, err := f.gcm(arn).Open(nil, nonce, body, contextAAD(in.EncryptionContext))
	if err != nil {
		// A different context or a blob wrapped under another key fails the same way.
		return nil, &types.InvalidCiphertextException{}
	}
	return &kms.DecryptOutput{Plaintext: plaintext, KeyId: aws.String(arn)}, nil
}

func TestSealAndOpenEndToEndThroughTheBackend(t *testing.T) {
	fake := newFakeKMS()
	backend := New(fake)
	ctx := context.Background()
	canary := "CANARY-record-4c1d"
	record := map[string]any{"note": canary, "n": 3}

	for _, ref := range []string{keyARN, aliasRef} {
		envelope, err := vault.Seal(ctx, backend, ref, vault.KindInput, "org_1", "op-1", record)
		if err != nil {
			t.Fatalf("%s: %v", ref, err)
		}
		if bytes.Contains(envelope, []byte(canary)) {
			t.Fatal("the envelope must not hold the plaintext")
		}
		header, plaintext, err := vault.Open(ctx, backend, envelope)
		if err != nil {
			t.Fatalf("%s: %v", ref, err)
		}
		if header.KeyRef != ref || !bytes.Contains(plaintext, []byte(canary)) {
			t.Fatalf("%s: unexpected result %+v %s", ref, header, plaintext)
		}
	}
	for i, values := range fake.seen {
		if values["organization_id"] != "org_1" || values["operation_id"] != "op-1" || len(values) != 2 {
			t.Fatalf("call %d carried an unexpected encryption context: %v", i, values)
		}
	}
	if len(fake.seen) != 4 {
		t.Fatalf("expected 4 KMS calls, got %d", len(fake.seen))
	}
}

func TestOpenFailsWithADifferentEncryptionContext(t *testing.T) {
	fake := newFakeKMS()
	backend := New(fake)
	// Wrap under one context, then ask KMS to unwrap under another.
	plaintext, wrapped, err := backend.GenerateDataKey(ctxWith("org_1", "op-1"), keyARN)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := backend.Decrypt(ctxWith("org_1", "op-2"), keyARN, wrapped); !errors.Is(err, vault.ErrInvalidWrappedKey) {
		t.Fatalf("a different context must fail, got %v", err)
	}
	if _, err := backend.Decrypt(context.Background(), keyARN, wrapped); !errors.Is(err, vault.ErrInvalidWrappedKey) {
		t.Fatalf("no context must fail, got %v", err)
	}
	again, err := backend.Decrypt(ctxWith("org_1", "op-1"), keyARN, wrapped)
	if err != nil || !bytes.Equal(again, plaintext) {
		t.Fatalf("the matching context must unwrap the same key: %v", err)
	}
}

func TestOpenFailsForAWrappedKeyFromAnotherKey(t *testing.T) {
	fake := newFakeKMS()
	backend := New(fake)
	envelope, err := vault.Seal(context.Background(), backend, otherARN, vault.KindOutput, "org_1", "op-1", map[string]any{"a": 1})
	if err != nil {
		t.Fatal(err)
	}
	// An envelope whose header is rewritten to name another key must not open.
	rewritten := bytes.Replace(envelope, []byte(otherARN), []byte(keyARN), 1)
	if _, _, err := vault.Open(context.Background(), backend, rewritten); !errors.Is(err, vault.ErrInvalidWrappedKey) {
		t.Fatalf("expected ErrInvalidWrappedKey, got %v", err)
	}
}

func TestDisabledKeyMakesTheEnvelopeUnreadable(t *testing.T) {
	fake := newFakeKMS()
	backend := New(fake)
	ctx := context.Background()
	envelope, err := vault.Seal(ctx, backend, keyARN, vault.KindInput, "org_1", "op-1", map[string]any{"a": 1})
	if err != nil {
		t.Fatal(err)
	}
	fake.disabled[keyARN] = true
	_, plaintext, err := vault.Open(ctx, backend, envelope)
	if !errors.Is(err, vault.ErrKeyDestroyed) || !errors.Is(err, vault.ErrKeyBackend) || plaintext != nil {
		t.Fatalf("expected a destroyed-key error and no plaintext, got %q %v", plaintext, err)
	}
	if _, err := vault.Seal(ctx, backend, keyARN, vault.KindInput, "org_1", "op-2", map[string]any{"a": 1}); !errors.Is(err, vault.ErrKeyDestroyed) {
		t.Fatalf("a disabled key must not wrap new data keys: %v", err)
	}
	// Another key keeps working.
	if _, err := vault.Seal(ctx, backend, otherARN, vault.KindInput, "org_1", "op-3", map[string]any{"a": 1}); err != nil {
		t.Fatalf("other keys keep working: %v", err)
	}
	delete(fake.keys, keyARN)
	if _, _, err := vault.Open(ctx, backend, envelope); !errors.Is(err, vault.ErrKeyDestroyed) {
		t.Fatalf("a deleted key must report destroyed: %v", err)
	}
}
