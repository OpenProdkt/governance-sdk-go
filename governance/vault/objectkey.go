package vault

import (
	"fmt"
	"time"
)

// ObjectKey returns the storage key of one record:
//
//	vault/<organization>/<yyyy>/<mm>/<operation id>/<kind>-<n>.opkv
//
// The year and month are the UTC month of when. n is the record's position within the
// operation and starts at 1. Identifiers are validated as for Seal; "." and ".." are
// refused as well so a key can never be read as a relative path.
func ObjectKey(organizationID string, when time.Time, operationID string, kind Kind, n int) (string, error) {
	if !validID(organizationID) || !validID(operationID) || !validKind(kind) || n < 1 ||
		organizationID == "." || organizationID == ".." || operationID == "." || operationID == ".." {
		return "", ErrInvalidInput
	}
	utc := when.UTC()
	if utc.Year() < 1 || utc.Year() > 9999 {
		return "", ErrInvalidInput
	}
	return fmt.Sprintf("vault/%s/%04d/%02d/%s/%s-%d.opkv", organizationID, utc.Year(), int(utc.Month()), operationID, kind, n), nil
}
