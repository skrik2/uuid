package uuid

import (
	"database/sql"
	"database/sql/driver"
	"fmt"
)

var _ driver.Valuer = UUID{}
var _ sql.Scanner = (*UUID)(nil)

// Value implements the driver.Valuer interface.
func (u UUID) Value() (driver.Value, error) {
	return u.String(), nil
}

// Scan implements the sql.Scanner interface.
// A 16-byte slice will be handled by UnmarshalBinary,
// while a longer byte slice or a string will be handled by UnmarshalText.
func (u *UUID) Scan(src any) error {
	switch src := src.(type) {
	case UUID: // support gorm convert from UUID to NullUUID
		*u = src
		return nil

	case []byte:
		if len(src) == 16 {
			return u.UnmarshalBinary(src)
		}
		return u.UnmarshalText(src)

	case string:
		uu, err := Parse(src)
		*u = uu
		return err
	}

	return fmt.Errorf("%s %T to UUID", "uuid: cannot convert", src)
}

// NullUUID can be used with the standard sql package to represent a
// UUID value that can be NULL in the database.
type NullUUID struct {
	UUID  UUID
	Valid bool
}

// Value implements the driver.Valuer interface.
func (u NullUUID) Value() (driver.Value, error) {
	if !u.Valid {
		return nil, nil
	}
	// Delegate to UUID Value function
	return u.UUID.Value()
}

// Scan implements the sql.Scanner interface.
func (u *NullUUID) Scan(src interface{}) error {
	if src == nil {
		u.UUID, u.Valid = NilUUID, false
		return nil
	}

	// Delegate to UUID Scan function
	u.Valid = true
	return u.UUID.Scan(src)
}

var nullJSON = []byte("null")

// MarshalJSON marshals the NullUUID as null or the nested UUID
func (u NullUUID) MarshalJSON() ([]byte, error) {
	if !u.Valid {
		return nullJSON, nil
	}
	var buf [38]byte
	buf[0] = '"'
	encodeCanonical(buf[1:37], u.UUID)
	buf[37] = '"'
	return buf[:], nil
}

// UnmarshalJSON unmarshals a NullUUID
func (u *NullUUID) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		u.UUID, u.Valid = NilUUID, false
		return nil
	}
	if n := len(b); n >= 2 && b[0] == '"' {
		b = b[1 : n-1]
	}
	err := u.UUID.UnmarshalText(b)
	u.Valid = (err == nil)
	return err
}

// encodeCanonical encodes the canonical RFC-9562 form of UUID u into the
// first 36 bytes dst.
func encodeCanonical(dst []byte, u UUID) {
	const hextable = "0123456789abcdef"
	dst[8] = '-'
	dst[13] = '-'
	dst[18] = '-'
	dst[23] = '-'
	for i, x := range [16]byte{
		0, 2, 4, 6,
		9, 11,
		14, 16,
		19, 21,
		24, 26, 28, 30, 32, 34,
	} {
		c := u[i]
		dst[x] = hextable[c>>4]
		dst[x+1] = hextable[c&0x0f]
	}
}
