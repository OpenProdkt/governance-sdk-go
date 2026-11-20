package vault

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"sync"
)

const wrapNonceSize = 12

// Call records one request to a MemoryBackend. It never holds key material.
type Call struct {
	Op      string // "GenerateDataKey" or "Decrypt"
	KeyRef  string
	Context map[string]string
}

// MemoryBackend is an in-memory KeyBackend for tests and local development. Every
// key reference gets its own random 32-byte key-encryption key on first use. Data keys
// are wrapped with AES-256-GCM, bound to the key reference. It is not a key service:
// keys live in process memory only.
type MemoryBackend struct {
	mu        sync.Mutex
	keys      map[string][]byte
	destroyed map[string]bool
	calls     []Call
}

// NewMemoryBackend returns an empty backend.
func NewMemoryBackend() *MemoryBackend {
	return &MemoryBackend{keys: map[string][]byte{}, destroyed: map[string]bool{}}
}

var _ KeyBackend = (*MemoryBackend)(nil)

// GenerateDataKey creates the key for keyRef when it does not exist yet.
func (b *MemoryBackend) GenerateDataKey(ctx context.Context, keyRef string) ([]byte, []byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.log("GenerateDataKey", keyRef, ctx)
	if keyRef == "" {
		return nil, nil, ErrKeyNotFound
	}
	if b.destroyed[keyRef] {
		return nil, nil, ErrKeyDestroyed
	}
	kek, ok := b.keys[keyRef]
	if !ok {
		kek = make([]byte, DataKeySize)
		if _, err := rand.Read(kek); err != nil {
			return nil, nil, fmt.Errorf("vault: random source failed")
		}
		b.keys[keyRef] = kek
	}
	dataKey := make([]byte, DataKeySize)
	nonce := make([]byte, wrapNonceSize)
	if _, err := rand.Read(dataKey); err != nil {
		return nil, nil, fmt.Errorf("vault: random source failed")
	}
	if _, err := rand.Read(nonce); err != nil {
		zero(dataKey)
		return nil, nil, fmt.Errorf("vault: random source failed")
	}
	wrapped, err := wrapDataKey(kek, nonce, dataKey, keyRef)
	if err != nil {
		zero(dataKey)
		return nil, nil, err
	}
	return dataKey, wrapped, nil
}

// Decrypt returns ErrKeyDestroyed after DestroyKey, ErrKeyNotFound for a key reference
// that was never used, and ErrInvalidWrappedKey for a wrapped key it did not produce.
func (b *MemoryBackend) Decrypt(ctx context.Context, keyRef string, wrappedKey []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.log("Decrypt", keyRef, ctx)
	if b.destroyed[keyRef] {
		return nil, ErrKeyDestroyed
	}
	kek, ok := b.keys[keyRef]
	if !ok {
		return nil, ErrKeyNotFound
	}
	if len(wrappedKey) < wrapNonceSize {
		return nil, ErrInvalidWrappedKey
	}
	gcm, err := newGCM(kek)
	if err != nil {
		return nil, err
	}
	dataKey, err := gcm.Open(nil, wrappedKey[:wrapNonceSize], wrappedKey[wrapNonceSize:], []byte(keyRef))
	if err != nil || len(dataKey) != DataKeySize {
		zero(dataKey)
		return nil, ErrInvalidWrappedKey
	}
	return dataKey, nil
}

// DestroyKey zeroes and forgets the key for keyRef. Afterwards Decrypt fails with
// ErrKeyDestroyed and GenerateDataKey refuses to create the key again. It models the
// customer destroying a key in their own key service.
func (b *MemoryBackend) DestroyKey(keyRef string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	zero(b.keys[keyRef])
	delete(b.keys, keyRef)
	b.destroyed[keyRef] = true
}

// Calls returns a copy of the call log, oldest first.
func (b *MemoryBackend) Calls() []Call {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]Call, len(b.calls))
	for i, c := range b.calls {
		out[i] = Call{Op: c.Op, KeyRef: c.KeyRef, Context: copyStrings(c.Context)}
	}
	return out
}

func (b *MemoryBackend) log(op, keyRef string, ctx context.Context) {
	b.calls = append(b.calls, Call{Op: op, KeyRef: keyRef, Context: EncryptionContext(ctx)})
}

// setKey installs a fixed key-encryption key. Test-only: the shared vectors need a known key.
func (b *MemoryBackend) setKey(keyRef string, kek []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.keys[keyRef] = append([]byte(nil), kek...)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("vault: invalid key size")
	}
	return cipher.NewGCM(block)
}

// wrapDataKey returns nonce || AES-256-GCM(kek, nonce, dataKey, aad=keyRef).
func wrapDataKey(kek, nonce, dataKey []byte, keyRef string) ([]byte, error) {
	gcm, err := newGCM(kek)
	if err != nil {
		return nil, err
	}
	return append(append([]byte(nil), nonce...), gcm.Seal(nil, nonce, dataKey, []byte(keyRef))...), nil
}
