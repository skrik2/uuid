// https://datatracker.ietf.org/doc/html/rfc9562

package uuid

import (
	"database/sql/driver"
	"fmt"
	"time"
	"unsafe"
)

type UUID [16]byte

// UUID versions.
const (
	_  byte = iota
	V1      // Version 1 (date-time and MAC address) [no implement]
	_       // Version 2 (date-time and MAC address, DCE security version) [removed]
	V3      // Version 3 (namespace name-based) [no implement]
	V4      // Version 4 (random)
	V5      // Version 5 (namespace name-based) [no implement]
	V6      // Version 6 (k-sortable timestamp and random data, field-compatible with v1) [no implement]
	V7      // Version 7 (k-sortable timestamp and random data)
	_       // Version 8 (k-sortable timestamp, meant for custom implementations) [not implemented]
)

// NilUUID is the nil UUID, as specified in RFC-9562, that has all 128 bits set to zero.
var NilUUID = UUID{}

// Max is the maximum UUID, as specified in RFC-9562, that has all 128 bits
// set to one.
var Max = UUID{
	0xFF,
	0xFF,
	0xFF,
	0xFF,
	0xFF,
	0xFF,
	0xFF,
	0xFF,
	0xFF,
	0xFF,
	0xFF,
	0xFF,
	0xFF,
	0xFF,
	0xFF,
	0xFF,
}

// UUID layout variants.
const (
	VariantNCS byte = iota
	VariantRFC9562
	VariantMicrosoft
	VariantFuture
)

func NewV4() (UUID, error) {
	return defaultGen.NewV4()
}

func NewV7() (UUID, error)

// NewV7Lazy generates a V7 UUID with a 48-bit Unix millisecond timestamp
// and a fully random tail. This version does not guarantee monotonicity
// within the same millisecond.
//
// UUIDv7 layout (bit positions):
//
//	0..47   unix_ts_ms
//	48..51  version
//	52..63  rand_a
//	64..65  variant
//	66..127 rand_b
func NewV7Lazy() (UUID, error) {
	return defaultGen.NewV7Lazy()
}

// func NewV4Rand(rand io.Reader) UUID
// func NewV7AtTime(t time.Time) UUID
// func NewV7AtTimeRand(t time.Time, rand io.Reader) UUID

// Version returns the algorithm version used to generate the UUID.
func (u UUID) Version() byte {
	return u[6] >> 4
}

// Must is a helper that wraps a call to a function returning (UUID, error) and panics
// if the error is non-nil. It is intended for use in variable initializations such as
//
//	var packageUUID = uuid.MustUUID(uuid.FromString("123e4567-e89b-12d3-a456-426655440000"))
func MustUUID(u UUID, err error) UUID {
	if err != nil {
		panic(err)
	}
	return u
}
func FromBytes(input []byte) (UUID, error)
func FromBytesOrNil(input []byte) UUID

func FromString(input string) (UUID, error)

// Parse parses the UUID stored in the string text. Parsing
// and supported formats are the same as UnmarshalText.
func (u *UUID) Parse(s string) error

func FromStringOrNil(input string) UUID

var hexTable = func() [256][2]byte {
	var t [256][2]byte
	const digits = "0123456789abcdef"
	for i := range 256 {
		t[i][0] = digits[i>>4]
		t[i][1] = digits[i&0x0f]
	}
	return t
}()

func (u UUID) String() string {
	buf := make([]byte, 36)
	buf[8], buf[13], buf[18], buf[23] = '-', '-', '-', '-'

	t := hexTable[u[0]]
	buf[0], buf[1] = t[0], t[1]
	t = hexTable[u[1]]
	buf[2], buf[3] = t[0], t[1]
	t = hexTable[u[2]]
	buf[4], buf[5] = t[0], t[1]
	t = hexTable[u[3]]
	buf[6], buf[7] = t[0], t[1]
	t = hexTable[u[4]]
	buf[9], buf[10] = t[0], t[1]
	t = hexTable[u[5]]
	buf[11], buf[12] = t[0], t[1]
	t = hexTable[u[6]]
	buf[14], buf[15] = t[0], t[1]
	t = hexTable[u[7]]
	buf[16], buf[17] = t[0], t[1]
	t = hexTable[u[8]]
	buf[19], buf[20] = t[0], t[1]
	t = hexTable[u[9]]
	buf[21], buf[22] = t[0], t[1]
	t = hexTable[u[10]]
	buf[24], buf[25] = t[0], t[1]
	t = hexTable[u[11]]
	buf[26], buf[27] = t[0], t[1]
	t = hexTable[u[12]]
	buf[28], buf[29] = t[0], t[1]
	t = hexTable[u[13]]
	buf[30], buf[31] = t[0], t[1]
	t = hexTable[u[14]]
	buf[32], buf[33] = t[0], t[1]
	t = hexTable[u[15]]
	buf[34], buf[35] = t[0], t[1]

	return unsafe.String(&buf[0], 36)
}

// Bytes returns a newly allocated byte slice containing the UUID.
// Modifying the returned slice will NOT affect the original UUID.
func (u UUID) Bytes() []byte {
	b := make([]byte, 16)
	copy(b, u[:])
	return b
}

// AsSlice returns a byte slice referencing the underlying UUID array.
// Modifying the returned slice WILL modify the UUID itself.
func (u *UUID) AsSlice() []byte {
	return u[:]
}

// Format implements fmt.Formatter for UUID values.
// The behavior is as follows: The 'x' and 'X' verbs output only the hex digits of the UUID,
// using a-f for 'x' and A-F for 'X'. The 'v', '+v', 's' and 'q' verbs return the canonical RFC-9562 string
// representation. The 'S' verb returns the RFC-9562 format, but with capital hex digits. The '#v' verb returns
// the "Go syntax" representation, which is a 16 byte array initializer. All other verbs not handled directly by the
// fmt package (like '%p') are unsupported and will return "%!verb(uuid.UUID=value)" as recommended by the fmt package.
func (u UUID) Format(f fmt.State, c rune)

// IsNilUUID returns if the UUID is equal to the nil UUID
func (u UUID) IsNilUUID() bool {
	return u == NilUUID
}

func (u UUID) Equal(another UUID) bool

func (u UUID) Compare(v UUID) int

func (u UUID) Time() time.Time // only V7

// MarshalBinary implements the encoding.BinaryMarshaler interface.
func (u UUID) MarshalBinary() ([]byte, error)

// UnmarshalBinary implements the encoding.BinaryUnmarshaler interface.
// It will return an error if the slice isn't 16 bytes long.
func (u *UUID) UnmarshalBinary(data []byte) error

// MarshalText implements the encoding.TextMarshaler interface.
// The encoding is the same as returned by the String() method.
func (u UUID) MarshalText() ([]byte, error)

func (u *UUID) UnmarshalText(b []byte) error

// Value implements the driver.Valuer interface.
func (u UUID) Value() (driver.Value, error)

// Scan implements the sql.Scanner interface. A 16-byte slice will be handled by UnmarshalBinary,
// while a longer byte slice or a string will be handled by UnmarshalText.
func (u *UUID) Scan(src interface{}) error

// Variant returns the UUID layout variant.
func (u UUID) Variant() byte {
	switch {
	case (u[8] >> 7) == 0x00:
		return VariantNCS
	case (u[8] >> 6) == 0x02:
		return VariantRFC9562
	case (u[8] >> 5) == 0x06:
		return VariantMicrosoft
	case (u[8] >> 5) == 0x07:
		fallthrough
	default:
		return VariantFuture
	}
}
