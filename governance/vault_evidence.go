package governance

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"sync/atomic"
	"time"

	"github.com/OpenProdkt/governance-sdk-go/governance/vault"
)

// Reasons a vault record could not be stored. The set is closed: a gap carries one of
// these classes and nothing else, never an error text.
const (
	VaultGapKeyServiceUnavailable = "key_service_unavailable"
	VaultGapStorageUnavailable    = "storage_unavailable"
	VaultGapRecordTooLarge        = "record_too_large"
	VaultGapWriteFailed           = "write_failed"
)

// Kinds of a VaultRef. An evaluate request carries an input reference and an outcome
// report carries an output reference.
const (
	VaultKindInput  = string(vault.KindInput)
	VaultKindOutput = string(vault.KindOutput)
)

// VaultRef points at one sealed record in storage the caller owns. It holds no record
// content and no key material. Build it from the writer's pointer with NewVaultRef.
//
// CiphertextDigest is "sha256:" plus 64 lowercase hex characters. The pointer is
// untrusted caller evidence.
type VaultRef struct {
	Kind             string `json:"kind"`
	ObjectKey        string `json:"object_key"`
	VersionID        string `json:"version_id"`
	KeyRef           string `json:"key_ref"`
	CiphertextDigest string `json:"ciphertext_digest"`
}

// VaultGap states that a record could not be stored. Reason is one of the VaultGap*
// constants.
type VaultGap struct {
	Reason string `json:"reason"`
}

// NewVaultRef converts a vault writer pointer into its wire form.
func NewVaultRef(p vault.Pointer) VaultRef {
	return VaultRef{
		Kind:             string(p.Kind),
		ObjectKey:        p.ObjectKey,
		VersionID:        p.VersionID,
		KeyRef:           p.KeyRef,
		CiphertextDigest: p.CiphertextDigest,
	}
}

var vaultDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func validVaultGapReason(reason string) bool {
	switch reason {
	case VaultGapKeyServiceUnavailable, VaultGapStorageUnavailable, VaultGapRecordTooLarge, VaultGapWriteFailed:
		return true
	}
	return false
}

func validateVaultRef(ref *VaultRef, kind string) error {
	if ref == nil {
		return nil
	}
	if ref.Kind != kind {
		return &InvalidAuthorizationInputError{Message: "vault_ref kind must be " + kind + " for this request"}
	}
	if ref.ObjectKey == "" || ref.VersionID == "" || ref.KeyRef == "" {
		return &InvalidAuthorizationInputError{Message: "vault_ref object_key, version_id and key_ref are required"}
	}
	if !vaultDigestPattern.MatchString(ref.CiphertextDigest) {
		return &InvalidAuthorizationInputError{Message: "vault_ref ciphertext_digest must be sha256: followed by 64 lowercase hex characters"}
	}
	return nil
}

func validateVaultGap(gap *VaultGap) error {
	if gap != nil && !validVaultGapReason(gap.Reason) {
		return &InvalidAuthorizationInputError{Message: "vault_gap reason is not recognized"}
	}
	return nil
}

// validateVaultEvidence checks the vault members of one request before any network call.
func validateVaultEvidence(ref *VaultRef, gap *VaultGap, kind string) error {
	if ref != nil && gap != nil {
		return &InvalidAuthorizationInputError{Message: "vault_ref and vault_gap must not both be set"}
	}
	if err := validateVaultRef(ref, kind); err != nil {
		return err
	}
	return validateVaultGap(gap)
}

// VaultWriter stores one record. *vault.Writer satisfies it.
type VaultWriter interface {
	Write(ctx context.Context, kind vault.Kind, organizationID, operationID string, n int, record any) (vault.Pointer, error)
}

// VaultWriteError reports that a record was not stored. It carries the gap reason only;
// its text never includes a record, a key, a storage address or the underlying error.
type VaultWriteError struct {
	Reason string
}

func (e *VaultWriteError) Error() string {
	return "evidence vault write failed: " + e.Reason
}

// VaultGapReason classifies an error from a vault write into a gap reason. record is
// the record that was written; it is only measured, never read into the result.
func VaultGapReason(err error, record any) string {
	switch {
	case errors.Is(err, vault.ErrKeyBackend), errors.Is(err, vault.ErrKeyDestroyed),
		errors.Is(err, vault.ErrKeyNotFound), errors.Is(err, vault.ErrInvalidWrappedKey):
		return VaultGapKeyServiceUnavailable
	case errors.Is(err, vault.ErrObjectWrite):
		return VaultGapStorageUnavailable
	case errors.Is(err, vault.ErrInvalidInput) && recordExceedsLimit(record):
		return VaultGapRecordTooLarge
	}
	return VaultGapWriteFailed
}

// recordExceedsLimit measures a record the way the vault reads it: JSON text as given,
// anything else as its JSON encoding.
func recordExceedsLimit(record any) bool {
	switch v := record.(type) {
	case nil:
		return false
	case []byte:
		return len(v) > vault.MaxRecordSize
	case json.RawMessage:
		return len(v) > vault.MaxRecordSize
	}
	encoded, err := json.Marshal(record)
	return err == nil && len(encoded) > vault.MaxRecordSize
}

var lastRecordNumber atomic.Int64

// nextRecordNumber returns the current Unix time in milliseconds, raised when needed so
// that no two calls in this process return the same number.
func nextRecordNumber() int {
	now := time.Now().UnixMilli()
	for {
		last := lastRecordNumber.Load()
		next := now
		if next <= last {
			next = last + 1
		}
		if lastRecordNumber.CompareAndSwap(last, next) {
			return int(next)
		}
	}
}

// WriteVaultRecord seals and stores one record and returns its reference. A write is
// not started when ctx is already done; that returns the context error. Every other
// failure, including a panic in the writer and a pointer that does not match the
// request, returns a *VaultWriteError.
func WriteVaultRecord(ctx context.Context, writer VaultWriter, kind vault.Kind, organizationID, operationID string, record any) (ref *VaultRef, err error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	fail := func(cause error) (*VaultRef, error) {
		return nil, &VaultWriteError{Reason: VaultGapReason(cause, record)}
	}
	if writer == nil {
		return fail(vault.ErrInvalidInput)
	}
	defer func() {
		if recover() != nil {
			ref, err = nil, &VaultWriteError{Reason: VaultGapWriteFailed}
		}
	}()
	pointer, werr := writer.Write(ctx, kind, organizationID, operationID, nextRecordNumber(), record)
	if werr != nil {
		return fail(werr)
	}
	wire := NewVaultRef(pointer)
	if validateVaultRef(&wire, string(kind)) != nil {
		return nil, &VaultWriteError{Reason: VaultGapWriteFailed}
	}
	return &wire, nil
}
