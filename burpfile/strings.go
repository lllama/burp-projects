package burpfile

import (
	"encoding/binary"
	"fmt"
)

// ImmutableString reads a Zv1/Zmju immutable string object. The second
// result is false when the object or its character array is absent
// (prub.parser.read_immutable_string).
func (p *Project) ImmutableString(stringAddress int64) (string, bool, error) {
	if stringAddress == 0 {
		return "", false, nil
	}
	stringObject, err := p.ResolveObject(stringAddress)
	if err != nil {
		return "", false, err
	}
	charsAddress, ok, err := p.ObjectAddress(stringObject, 0)
	if err != nil || !ok {
		return "", false, err
	}
	value, err := p.ReadUTF16Array(charsAddress)
	if err != nil {
		return "", false, err
	}
	return value, true, nil
}

// MutableString reads a Zvp/Zmjj chunked mutable string object
// (prub.parser.read_mutable_string): field 0 logical length, field 2 chunk
// width, field 3 chunk collection of UTF-16BE arrays.
func (p *Project) MutableString(stringAddress int64) (string, error) {
	stringObject, err := p.ResolveObject(stringAddress)
	if err != nil {
		return "", err
	}
	length, okLength, err := p.Int32Field(stringObject, 0)
	if err != nil {
		return "", err
	}
	chunkWidth, okWidth, err := p.Int32Field(stringObject, 2)
	if err != nil {
		return "", err
	}
	chunksAddress, okChunks, err := p.ObjectAddress(stringObject, 3)
	if err != nil {
		return "", err
	}
	if !okLength || !okWidth || !okChunks {
		return "", formatError("mutable string is missing a required field")
	}
	if length < 0 || chunkWidth <= 0 {
		return "", formatError("mutable string has invalid dimensions")
	}
	chunkAddresses, err := p.DirectCollectionAddresses(chunksAddress)
	if err != nil {
		return "", err
	}
	var text []rune
	for _, chunkAddress := range chunkAddresses {
		chunk, err := p.ReadUTF16Array(chunkAddress)
		if err != nil {
			return "", err
		}
		text = append(text, []rune(chunk)...)
	}
	if len(text) < int(length) {
		return "", formatError(
			"mutable string contains %d characters; expected %d", len(text), length)
	}
	return string(text[:length]), nil
}

// UUIDString reads the two-long UUID object used by Repeater tabs and groups
// (prub.parser.read_uuid_object): unsigned 64-bit fields 0 (high) and 1 (low).
func (p *Project) UUIDString(uuidAddress int64) (string, error) {
	uuidObject, err := p.ResolveObject(uuidAddress)
	if err != nil {
		return "", err
	}
	var raw [16]byte
	high, okHigh, err := p.Uint64Field(uuidObject, 0)
	if err != nil {
		return "", err
	}
	low, okLow, err := p.Uint64Field(uuidObject, 1)
	if err != nil {
		return "", err
	}
	if !okHigh || !okLow {
		return "", formatError("UUID object is missing a required field")
	}
	binary.BigEndian.PutUint64(raw[0:], high)
	binary.BigEndian.PutUint64(raw[8:], low)
	return formatUUID(raw), nil
}

func formatUUID(raw [16]byte) string {
	return fmt.Sprintf("%x-%x-%x-%x-%x", raw[0:4], raw[4:6], raw[6:8], raw[8:10], raw[10:16])
}
