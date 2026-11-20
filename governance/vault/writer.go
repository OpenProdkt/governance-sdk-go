package vault

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// RetentionMode is the object-lock mode of a written object.
type RetentionMode string

const (
	RetentionCompliance RetentionMode = "COMPLIANCE"
	RetentionGovernance RetentionMode = "GOVERNANCE"
)

// Retention is the lock an ObjectWriter applies to one object.
type Retention struct {
	Until time.Time
	Mode  RetentionMode
}

// ObjectWriter stores one object under a retention lock in storage the caller owns, with
// the caller's credentials, and returns the version id of the stored object. A
// production implementation (S3 Object Lock, Azure immutable blob, GCS retention) is
// supplied by the caller. It must return an error, never an empty version id, when the
// object is not durably stored with the lock.
type ObjectWriter interface {
	PutLocked(ctx context.Context, key string, body []byte, retention Retention) (versionID string, err error)
}

// ErrObjectWrite wraps every failure to store an envelope.
var ErrObjectWrite = errors.New("vault: object write failed")

// Pointer identifies a stored envelope. It holds no record content and no key material.
type Pointer struct {
	ObjectKey        string
	VersionID        string
	KeyRef           string
	CiphertextDigest string // "sha256:" plus the lowercase hex SHA-256 of the envelope bytes
	Kind             Kind
}

// WriterConfig configures a Writer.
type WriterConfig struct {
	Backend KeyBackend
	Objects ObjectWriter
	// KeyRef names the customer key that wraps every data key this writer creates.
	KeyRef string
	// RetentionMode and RetentionPeriod are the customer's lock settings. Each object is
	// locked until the time of the write plus RetentionPeriod.
	RetentionMode   RetentionMode
	RetentionPeriod time.Duration
	// Now is the clock; nil means time.Now.
	Now func() time.Time
}

// Writer seals records and writes them through an ObjectWriter.
type Writer struct {
	cfg WriterConfig
}

// NewWriter validates the configuration.
func NewWriter(cfg WriterConfig) (*Writer, error) {
	if cfg.Backend == nil || cfg.Objects == nil || !validKeyRef(cfg.KeyRef) ||
		(cfg.RetentionMode != RetentionCompliance && cfg.RetentionMode != RetentionGovernance) ||
		cfg.RetentionPeriod <= 0 {
		return nil, ErrInvalidInput
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Writer{cfg: cfg}, nil
}

// Write seals record and stores it as record number n (starting at 1) of the
// operation. It fails, and returns no pointer, when sealing fails, when the
// ObjectWriter fails, or when it returns an empty version id. It never skips a write.
func (w *Writer) Write(ctx context.Context, kind Kind, organizationID, operationID string, n int, record any) (Pointer, error) {
	now := w.cfg.Now()
	key, err := ObjectKey(organizationID, now, operationID, kind, n)
	if err != nil {
		return Pointer{}, err
	}
	envelope, err := Seal(ctx, w.cfg.Backend, w.cfg.KeyRef, kind, organizationID, operationID, record)
	if err != nil {
		return Pointer{}, err
	}
	versionID, err := w.cfg.Objects.PutLocked(ctx, key, envelope, Retention{Until: now.UTC().Add(w.cfg.RetentionPeriod), Mode: w.cfg.RetentionMode})
	if err != nil {
		return Pointer{}, fmt.Errorf("%w: %w", ErrObjectWrite, err)
	}
	if versionID == "" {
		return Pointer{}, fmt.Errorf("%w: no version id returned", ErrObjectWrite)
	}
	sum := sha256.Sum256(envelope)
	return Pointer{
		ObjectKey:        key,
		VersionID:        versionID,
		KeyRef:           w.cfg.KeyRef,
		CiphertextDigest: "sha256:" + hex.EncodeToString(sum[:]),
		Kind:             kind,
	}, nil
}

// StoredObject is one object held by a MemoryObjectWriter.
type StoredObject struct {
	Body      []byte
	VersionID string
	Retention Retention
}

// MemoryObjectWriter is an in-memory ObjectWriter for tests. Like a locked bucket
// used with unique keys, it refuses to write the same key twice.
type MemoryObjectWriter struct {
	mu      sync.Mutex
	objects map[string]StoredObject
	next    int
}

// NewMemoryObjectWriter returns an empty writer.
func NewMemoryObjectWriter() *MemoryObjectWriter {
	return &MemoryObjectWriter{objects: map[string]StoredObject{}}
}

var _ ObjectWriter = (*MemoryObjectWriter)(nil)

// PutLocked stores a copy of body and returns a new version id.
func (m *MemoryObjectWriter) PutLocked(ctx context.Context, key string, body []byte, retention Retention) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if key == "" || retention.Until.IsZero() || (retention.Mode != RetentionCompliance && retention.Mode != RetentionGovernance) {
		return "", errors.New("memory object writer: invalid object or retention")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.objects[key]; exists {
		return "", errors.New("memory object writer: key already written")
	}
	m.next++
	version := fmt.Sprintf("mem-%d", m.next)
	m.objects[key] = StoredObject{Body: append([]byte(nil), body...), VersionID: version, Retention: retention}
	return version, nil
}

// Get returns a copy of a stored object.
func (m *MemoryObjectWriter) Get(key string) (StoredObject, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	o, ok := m.objects[key]
	o.Body = append([]byte(nil), o.Body...)
	return o, ok
}

// Keys returns the stored object keys in sorted order.
func (m *MemoryObjectWriter) Keys() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	keys := make([]string, 0, len(m.objects))
	for k := range m.objects {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
