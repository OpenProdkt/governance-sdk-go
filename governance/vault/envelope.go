package vault

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"unicode/utf8"
)

const (
	// Version is the envelope format identifier carried in every header.
	Version = "opk-vault.v1"
	// Algorithm is the only supported content cipher.
	Algorithm = "AES-256-GCM"
	// MaxRecordSize is the largest canonical record, in bytes, that Seal accepts.
	MaxRecordSize = 8 << 20

	magic          = "OPKV1\n"
	nonceSize      = 12
	tagSize        = 16
	maxIDLength    = 128
	maxKeyRefChars = 256
	maxWrappedKey  = 4096
	maxHeaderBytes = 16 << 10
)

// Kind says which side of a call a record belongs to.
type Kind string

const (
	KindInput  Kind = "input"
	KindOutput Kind = "output"
)

var (
	// ErrInvalidInput means an argument or the record was refused before anything was
	// encrypted. The message never contains the offending value.
	ErrInvalidInput = errors.New("vault: invalid input")
	// ErrEnvelope is the single failure class for an envelope that cannot be opened: bad
	// magic, malformed or altered header, wrong authenticated data, wrong key, or a failed
	// authentication tag. It deliberately says nothing more.
	ErrEnvelope = errors.New("vault: envelope rejected")

	idPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]+$`)
)

// Header is the authenticated metadata at the start of an envelope.
type Header struct {
	Version        string
	Kind           Kind
	OrganizationID string
	OperationID    string
	KeyRef         string
	WrappedKey     []byte
	Nonce          []byte
	Algorithm      string
}

func validID(s string) bool {
	return len(s) > 0 && len(s) <= maxIDLength && idPattern.MatchString(s)
}

func validKeyRef(s string) bool {
	return s != "" && utf8.ValidString(s) && utf8.RuneCountInString(s) <= maxKeyRefChars
}

func validKind(k Kind) bool { return k == KindInput || k == KindOutput }

// aad returns the authenticated data: the canonical JSON of the header members that
// bind a record to one organization, operation, kind and key.
func aad(kind Kind, organizationID, operationID, keyRef string) []byte {
	return canonicalStrings(map[string]string{
		"v":               Version,
		"kind":            string(kind),
		"organization_id": organizationID,
		"operation_id":    operationID,
		"key_ref":         keyRef,
	})
}

func encryptionContext(organizationID, operationID string) map[string]string {
	return map[string]string{"organization_id": organizationID, "operation_id": operationID}
}

// Seal encrypts record for one organization and operation with a fresh data key and a
// fresh random nonce, and returns the envelope bytes. The record must be a JSON object:
// a map or struct, or JSON text as []byte or json.RawMessage. Numbers must be integers
// within +/-(2^53-1). Every failure before the key backend is called is ErrInvalidInput.
func Seal(ctx context.Context, backend KeyBackend, keyRef string, kind Kind, organizationID, operationID string, record any) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if backend == nil || !validKind(kind) || !validID(organizationID) || !validID(operationID) || !validKeyRef(keyRef) {
		return nil, ErrInvalidInput
	}
	plaintext, err := canonicalRecord(record)
	if err != nil || len(plaintext) > MaxRecordSize {
		return nil, ErrInvalidInput
	}
	keyCtx := WithEncryptionContext(ctx, encryptionContext(organizationID, operationID))
	dataKey, wrapped, err := backend.GenerateDataKey(keyCtx, keyRef)
	defer zero(dataKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrKeyBackend, err)
	}
	if len(dataKey) != DataKeySize || len(wrapped) == 0 || len(wrapped) > maxWrappedKey {
		return nil, fmt.Errorf("%w: unusable data key", ErrKeyBackend)
	}
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, errors.New("vault: random source failed")
	}
	return seal(kind, organizationID, operationID, keyRef, dataKey, wrapped, nonce, plaintext)
}

// seal builds an envelope from explicit key material. Seal always passes fresh random
// values; in-package tests pass fixed ones to reproduce the shared vectors.
func seal(kind Kind, organizationID, operationID, keyRef string, dataKey, wrapped, nonce, plaintext []byte) ([]byte, error) {
	gcm, err := newGCM(dataKey)
	if err != nil || len(nonce) != nonceSize {
		return nil, ErrInvalidInput
	}
	header := canonicalStrings(map[string]string{
		"v":               Version,
		"kind":            string(kind),
		"organization_id": organizationID,
		"operation_id":    operationID,
		"key_ref":         keyRef,
		"wrapped_key":     base64.StdEncoding.EncodeToString(wrapped),
		"nonce":           base64.StdEncoding.EncodeToString(nonce),
		"alg":             Algorithm,
	})
	ciphertext := gcm.Seal(nil, nonce, plaintext, aad(kind, organizationID, operationID, keyRef))
	out := make([]byte, 0, len(magic)+len(header)+1+len(ciphertext))
	out = append(out, magic...)
	out = append(out, header...)
	out = append(out, '\n')
	return append(out, ciphertext...), nil
}

// Open verifies and decrypts an envelope. It returns the header and the canonical JSON
// bytes of the record. Every structural, authenticity or key failure is ErrEnvelope,
// except failures reported by the key backend, which wrap ErrKeyBackend (for a
// destroyed key the error also matches ErrKeyDestroyed). No error contains key or
// plaintext material.
func Open(ctx context.Context, backend KeyBackend, envelope []byte) (Header, []byte, error) {
	if err := ctx.Err(); err != nil {
		return Header{}, nil, err
	}
	if backend == nil {
		return Header{}, nil, ErrInvalidInput
	}
	header, ciphertext, err := parseEnvelope(envelope)
	if err != nil {
		return Header{}, nil, ErrEnvelope
	}
	keyCtx := WithEncryptionContext(ctx, encryptionContext(header.OrganizationID, header.OperationID))
	dataKey, err := backend.Decrypt(keyCtx, header.KeyRef, header.WrappedKey)
	defer zero(dataKey)
	if err != nil {
		return Header{}, nil, fmt.Errorf("%w: %w", ErrKeyBackend, err)
	}
	gcm, err := newGCM(dataKey)
	if err != nil {
		return Header{}, nil, ErrEnvelope
	}
	plaintext, err := gcm.Open(nil, header.Nonce, ciphertext, aad(header.Kind, header.OrganizationID, header.OperationID, header.KeyRef))
	if err != nil {
		return Header{}, nil, ErrEnvelope
	}
	return header, plaintext, nil
}

var headerMembers = []string{"v", "kind", "organization_id", "operation_id", "key_ref", "wrapped_key", "nonce", "alg"}

// parseEnvelope checks everything that does not need the key.
func parseEnvelope(envelope []byte) (Header, []byte, error) {
	bad := errors.New("malformed")
	if len(envelope) > MaxRecordSize+tagSize+maxHeaderBytes+len(magic)+1 || !bytes.HasPrefix(envelope, []byte(magic)) {
		return Header{}, nil, bad
	}
	rest := envelope[len(magic):]
	end := bytes.IndexByte(rest, '\n')
	if end < 0 || end > maxHeaderBytes {
		return Header{}, nil, bad
	}
	headerBytes, ciphertext := rest[:end], rest[end+1:]
	if len(ciphertext) < tagSize {
		return Header{}, nil, bad
	}
	parsed, err := parseJSON(headerBytes)
	if err != nil {
		return Header{}, nil, bad
	}
	object, ok := parsed.(map[string]any)
	if !ok || len(object) != len(headerMembers) {
		return Header{}, nil, bad
	}
	members := make(map[string]string, len(object))
	for _, name := range headerMembers {
		text, ok := object[name].(string)
		if !ok {
			return Header{}, nil, bad
		}
		members[name] = text
	}
	// The header must already be canonical: no reordering, whitespace or alternate escapes.
	canonical := canonicalStrings(members)
	if canonical == nil || !bytes.Equal(canonical, headerBytes) {
		return Header{}, nil, bad
	}
	header := Header{
		Version:        members["v"],
		Kind:           Kind(members["kind"]),
		OrganizationID: members["organization_id"],
		OperationID:    members["operation_id"],
		KeyRef:         members["key_ref"],
		Algorithm:      members["alg"],
	}
	if header.Version != Version || header.Algorithm != Algorithm || !validKind(header.Kind) ||
		!validID(header.OrganizationID) || !validID(header.OperationID) || !validKeyRef(header.KeyRef) {
		return Header{}, nil, bad
	}
	if header.WrappedKey, err = decodeBase64(members["wrapped_key"]); err != nil || len(header.WrappedKey) == 0 || len(header.WrappedKey) > maxWrappedKey {
		return Header{}, nil, bad
	}
	if header.Nonce, err = decodeBase64(members["nonce"]); err != nil || len(header.Nonce) != nonceSize {
		return Header{}, nil, bad
	}
	return header, ciphertext, nil
}

// decodeBase64 accepts only the canonical standard alphabet with padding.
func decodeBase64(text string) ([]byte, error) {
	decoded, err := base64.StdEncoding.Strict().DecodeString(text)
	if err != nil || base64.StdEncoding.EncodeToString(decoded) != text {
		return nil, errors.New("invalid base64")
	}
	return decoded, nil
}
