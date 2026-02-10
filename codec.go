package uuid

import (
	"errors"
	"fmt"
)

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

// MarshalBinary implements the encoding.BinaryMarshaler interface.
func (u UUID) MarshalBinary() ([]byte, error) {
	return u.Bytes(), nil
}

// UnmarshalBinary implements the encoding.BinaryUnmarshaler interface.
// It will return an error if the slice isn't 16 bytes long.
func (u *UUID) UnmarshalBinary(data []byte) error {
	if len(data) != 16 {
		return fmt.Errorf("%s, got %d bytes", "uuid: UUID must be exactly 16 bytes long", len(data))
	}
	copy(u[:], data)

	return nil
}

// FromBytes returns a UUID generated from the raw byte slice input.
// It will return an error if the slice isn't 16 bytes long.
func FromBytes(input []byte) (UUID, error) {
	u := UUID{}
	err := u.UnmarshalBinary(input)
	return u, err
}

func fromHexChar(c byte) byte {
	switch {
	case '0' <= c && c <= '9':
		return c - '0'
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10
	}
	return 255
}

// Parse parses UUID text representation from a byte slice and populates
// the provided UUID reference. It centralizes the parsing logic so that both
// Parse (string input) and UnmarshalText ([]byte input) can delegate to this
// single implementation, eliminating code duplication.
//
// Supported formats and ABNF grammar are documented on UnmarshalText; refer
// there for full details. This helper simply enforces those rules.
func parse(b []byte, u *UUID) error {
	// Fast-path: ensure we don't accidentally mutate the caller's slice.
	// We will only reslice, never modify the underlying bytes.
	switch len(b) {
	case 32: // hash
	case 36: // canonical
	case 34, 38:
		if b[0] != '{' || b[len(b)-1] != '}' {
			return fmt.Errorf("%s %q", "uuid: incorrect UUID format in string", b)
		}
		b = b[1 : len(b)-1]
	case 41, 45:
		if string(b[:9]) != "urn:uuid:" {
			return fmt.Errorf("%s %q", "uuid: incorrect UUID format in string", b[:9])
		}
		b = b[9:]
	default:
		return fmt.Errorf("%s %d in string %q", "uuid: UUID must be exactly 16 bytes long", len(b), b)
	}

	// canonical (36 chars with dashes at fixed positions)
	if len(b) == 36 {
		if b[8] != '-' || b[13] != '-' || b[18] != '-' || b[23] != '-' {
			return fmt.Errorf("%s %q", "uuid: incorrect UUID format in string", b)
		}
		for i, x := range [16]byte{
			0, 2, 4, 6,
			9, 11,
			14, 16,
			19, 21,
			24, 26, 28, 30, 32, 34,
		} {
			v1 := fromHexChar(b[x])
			v2 := fromHexChar(b[x+1])
			if v1|v2 == 255 {
				return errors.New("uuid: invalid UUID format")
			}
			u[i] = (v1 << 4) | v2
		}
		return nil
	}

	// hash-like (32 hex chars, no dashes)
	for i := 0; i < 32; i += 2 {
		v1 := fromHexChar(b[i])
		v2 := fromHexChar(b[i+1])
		if v1|v2 == 255 {
			return errors.New("uuid: invalid UUID format")
		}
		u[i/2] = (v1 << 4) | v2
	}
	return nil
}

// Parse parses the UUID stored in the string text. Parsing and supported
// formats are the same as UnmarshalText.
func Parse(s string) (UUID, error) {
	u := UUID{}
	err := parse([]byte(s), &u)
	return u, err
}

// MarshalText implements the encoding.TextMarshaler interface.
// The encoding is the same as returned by the String() method.
func (u UUID) MarshalText() ([]byte, error) {
	return []byte(u.String()), nil
}

// Following formats are supported:
//
//	"6ba7b810-9dad-11d1-80b4-00c04fd430c8",
//	"{6ba7b810-9dad-11d1-80b4-00c04fd430c8}",
//	"urn:uuid:6ba7b810-9dad-11d1-80b4-00c04fd430c8"
//	"6ba7b8109dad11d180b400c04fd430c8",
//	"{6ba7b8109dad11d180b400c04fd430c8}",
//	"urn:uuid:6ba7b8109dad11d180b400c04fd430c8"
//
// ABNF for supported UUID text representation follows:
//
//	URN       := "urn"
//	UUID-NID  := "uuid"
//
//	hexdig    := "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" |
//	             "a" | "b" | "c" | "d" | "e" | "f" |
//	             "A" | "B" | "C" | "D" | "E" | "F"
//
//	hexoct    := hexdig hexdig
//	2hexoct   := hexoct hexoct
//	4hexoct   := 2hexoct 2hexoct
//	6hexoct   := 4hexoct 2hexoct
//	12hexoct  := 6hexoct 6hexoct
//
//	hashlike  := 12hexoct
//	canonical := 4hexoct "-" 2hexoct "-" 2hexoct "-" 2hexoct "-" 6hexoct
//
//	plain     := canonical | hashlike
//	braced    := "{" plain "}"
//	urn       := URN ":" UUID-NID ":" plain
//
//	uuid      := canonical | hashlike | braced | urn
//
// The function delegates validation to internal parseBytes().
func (u *UUID) UnmarshalText(b []byte) error {
	return parse(b, u)
}
