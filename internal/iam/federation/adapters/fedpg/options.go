package fedpg

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"

	"github.com/Abraxas-365/iamkit/internal/iam/federation"
)

// options stores federation.Options as jsonb.
type options federation.Options

func (o options) Value() (driver.Value, error) { return json.Marshal(federation.Options(o)) }

func (o *options) Scan(src any) error {
	var raw []byte
	switch v := src.(type) {
	case nil:
		*o = options{}
		return nil
	case []byte:
		raw = v
	case string:
		raw = []byte(v)
	default:
		return fmt.Errorf("federation options: unsupported type %T", src)
	}
	return json.Unmarshal(raw, (*federation.Options)(o))
}
