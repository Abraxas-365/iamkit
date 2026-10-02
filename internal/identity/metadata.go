package identity

import (
	"bytes"
	"encoding/json"
	"regexp"

	"github.com/Abraxas-365/iamkit/internal/errx"
)

// Metadata limits of users and organizations: at most MetadataMaxKeys
// keys matching MetadataKey, each value at most MetadataMaxValue bytes of
// JSON, the whole object at most MetadataMaxSize bytes.
const (
	MetadataMaxKeys  = 64
	MetadataMaxValue = 4 << 10
	MetadataMaxSize  = 32 << 10
)

var metadataKey = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,64}$`)

// MetadataKey checks one metadata key.
func MetadataKey(key string) error {
	if !metadataKey.MatchString(key) {
		return errx.Validation("metadata key must be 1-64 letters, digits, '_', '.' or '-'")
	}
	return nil
}

// ValidateMetadata checks a whole metadata object against the limits.
func ValidateMetadata(raw json.RawMessage) error {
	object, err := metadataObject(raw)
	if err != nil {
		return err
	}
	for key, value := range object {
		if err = MetadataKey(key); err != nil {
			return err
		}
		if len(value) > MetadataMaxValue {
			return errx.Validation("metadata value of " + key + " must be at most 4 KiB")
		}
	}
	return metadataSize(object, len(raw))
}

// SetMetadata returns raw with key set to value. Only the new key and the
// totals are checked, so older data outside the limits stays readable.
func SetMetadata(raw json.RawMessage, key string, value json.RawMessage) (json.RawMessage, error) {
	if err := MetadataKey(key); err != nil {
		return nil, err
	}
	value = bytes.TrimSpace(value)
	if len(value) == 0 || !json.Valid(value) {
		return nil, errx.Validation("metadata value must be JSON")
	}
	if len(value) > MetadataMaxValue {
		return nil, errx.Validation("metadata value must be at most 4 KiB")
	}
	object, err := metadataObject(raw)
	if err != nil {
		return nil, err
	}
	object[key] = value
	out, err := json.Marshal(object)
	if err != nil {
		return nil, errx.Validation("metadata value must be JSON")
	}
	return out, metadataSize(object, len(out))
}

// DeleteMetadata returns raw without key; found reports whether it was set.
func DeleteMetadata(raw json.RawMessage, key string) (out json.RawMessage, found bool, err error) {
	object, err := metadataObject(raw)
	if err != nil {
		return nil, false, err
	}
	if _, found = object[key]; !found {
		return raw, false, nil
	}
	delete(object, key)
	out, err = json.Marshal(object)
	return out, true, err
}

// MetadataValue returns the value of key, if set.
func MetadataValue(raw json.RawMessage, key string) (json.RawMessage, bool) {
	object, err := metadataObject(raw)
	if err != nil {
		return nil, false
	}
	value, ok := object[key]
	return value, ok
}

func metadataObject(raw json.RawMessage) (map[string]json.RawMessage, error) {
	object := map[string]json.RawMessage{}
	if len(bytes.TrimSpace(raw)) == 0 {
		return object, nil
	}
	if err := json.Unmarshal(raw, &object); err != nil || object == nil {
		return nil, errx.Validation("metadata must be a JSON object")
	}
	return object, nil
}

func metadataSize(object map[string]json.RawMessage, size int) error {
	if len(object) > MetadataMaxKeys {
		return errx.Validation("metadata can have at most 64 keys")
	}
	if size > MetadataMaxSize {
		return errx.Validation("metadata must be at most 32 KiB")
	}
	return nil
}
