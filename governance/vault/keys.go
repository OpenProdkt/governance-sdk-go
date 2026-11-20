// Package vault seals records into an authenticated, encrypted envelope
// ("opk-vault.v1") and writes them to object storage that the caller owns.
//
// Everything in this package runs in the caller's environment. The caller holds the
// key service and the storage credentials; nothing here talks to the OpenProdkt control
// plane, and the control plane never sees a record, a data key or key material.
//
// A key backend generates one fresh 32-byte data key per record and wraps it with a
// key held by the caller's key service. Erasing a record means the caller destroys that
// key in the key service; the stored ciphertext is then unreadable.
package vault

import (
	"context"
	"errors"
)

// DataKeySize is the size in bytes of every data key and of every plaintext key a
// KeyBackend returns.
const DataKeySize = 32

var (
	// ErrKeyDestroyed means the key service reports that the key was destroyed, or can
	// no longer be used, so the wrapped data key (and the record) cannot be recovered.
	ErrKeyDestroyed = errors.New("vault: key destroyed")
	// ErrKeyNotFound means the key service does not know the key reference.
	ErrKeyNotFound = errors.New("vault: key not found")
	// ErrInvalidWrappedKey means the wrapped data key was not produced by the key or was
	// altered.
	ErrInvalidWrappedKey = errors.New("vault: wrapped key rejected")
	// ErrKeyBackend wraps every failure that comes from a key backend.
	ErrKeyBackend = errors.New("vault: key backend failed")
)

// KeyBackend is the customer's key service. Implementations use the ambient
// credentials of the running environment; the interface carries no credentials.
//
// Implementations must return a plaintext key of exactly DataKeySize bytes, must not
// retain it, and may read an optional encryption context from EncryptionContext(ctx)
// so the key service can bind it to the wrapped key.
type KeyBackend interface {
	// GenerateDataKey returns a new random data key in plaintext and wrapped under keyRef.
	GenerateDataKey(ctx context.Context, keyRef string) (plaintextKey, wrappedKey []byte, err error)
	// Decrypt unwraps a data key that GenerateDataKey returned for the same keyRef.
	Decrypt(ctx context.Context, keyRef string, wrappedKey []byte) (plaintextKey []byte, err error)
}

type encryptionContextKey struct{}

// WithEncryptionContext returns a context that carries a non-secret encryption context
// (for example organization and operation identifiers). Seal and Open attach it before
// they call the key backend. Backends that support it (such as AWS KMS) bind it to the
// wrapped key.
func WithEncryptionContext(ctx context.Context, values map[string]string) context.Context {
	return context.WithValue(ctx, encryptionContextKey{}, copyStrings(values))
}

// EncryptionContext returns a copy of the encryption context attached to ctx, or nil.
func EncryptionContext(ctx context.Context) map[string]string {
	values, _ := ctx.Value(encryptionContextKey{}).(map[string]string)
	if values == nil {
		return nil
	}
	return copyStrings(values)
}

func copyStrings(values map[string]string) map[string]string {
	copied := make(map[string]string, len(values))
	for k, v := range values {
		copied[k] = v
	}
	return copied
}

// zero overwrites a key buffer.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
