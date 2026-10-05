package burpfile

import "unicode/utf16"

// Record is one independently addressed variable byte record:
//
//	int32 total_size, int32 logical_length, payload[logical_length]
//
// Zero-length records reserve one padding byte (total_size = 9). Payload is
// a subslice of the project data, valid for as long as the Project is.
type Record struct {
	Offset        int64
	TotalSize     int32
	LogicalLength int32
	Payload       []byte
}

// ReadRecord parses the variable byte record at addr, mirroring
// prub.parser.parse_variable_record including its framing validation.
func (p *Project) ReadRecord(addr int64) (Record, error) {
	if addr < 0 {
		return Record{}, formatError("record offset must not be negative: %d", addr)
	}
	head, err := p.slice(addr, 8)
	if err != nil {
		return Record{}, formatError("record header at %d exceeds available data", addr)
	}
	totalSize := be32(head[0:4])
	logicalLength := be32(head[4:8])
	if logicalLength < 0 {
		return Record{}, formatError("negative logical length: %d", logicalLength)
	}
	storedPayloadSize := max64(int64(logicalLength), 1)
	if int64(totalSize) != 8+storedPayloadSize {
		return Record{}, formatError(
			"record total size %d does not match expected %d",
			totalSize, 8+storedPayloadSize)
	}
	if _, err := p.slice(addr, int64(totalSize)); err != nil {
		return Record{}, formatError(
			"record ending at %d exceeds available data", addr+int64(totalSize))
	}
	payload, err := p.slice(addr+8, int64(logicalLength))
	if err != nil {
		return Record{}, err
	}
	return Record{
		Offset:        addr,
		TotalSize:     totalSize,
		LogicalLength: logicalLength,
		Payload:       payload,
	}, nil
}

// readArrayRecord parses variable framing whose logical length counts
// fixed-size elements (prub.parser.parse_variable_array_record).
func (p *Project) readArrayRecord(addr int64, elemSize int64) ([]byte, error) {
	if elemSize <= 0 {
		return nil, formatError("element size must be positive: %d", elemSize)
	}
	if addr < 0 {
		return nil, formatError("array offset must not be negative: %d", addr)
	}
	head, err := p.slice(addr, 8)
	if err != nil {
		return nil, formatError("array header at %d exceeds available data", addr)
	}
	totalSize := be32(head[0:4])
	elementCount := be32(head[4:8])
	if elementCount < 0 {
		return nil, formatError("negative element count: %d", elementCount)
	}
	payloadSize := int64(elementCount) * elemSize
	storedPayloadSize := max64(payloadSize, 1)
	if int64(totalSize) != 8+storedPayloadSize {
		return nil, formatError(
			"array total size %d does not match expected %d",
			totalSize, 8+storedPayloadSize)
	}
	if _, err := p.slice(addr, int64(totalSize)); err != nil {
		return nil, formatError(
			"array ending at %d exceeds available data", addr+int64(totalSize))
	}
	payload, err := p.slice(addr+8, payloadSize)
	if err != nil {
		return nil, err
	}
	return payload, nil
}

// AddressArray is a decoded 8-byte-element address array record. Slot value
// 0 represents an absent reference; negative values are rejected.
type AddressArray []int64

// ReadAddressArray parses an array record of signed 64-bit object addresses.
func (p *Project) ReadAddressArray(addr int64) (AddressArray, error) {
	payload, err := p.readArrayRecord(addr, 8)
	if err != nil {
		return nil, err
	}
	addresses := make(AddressArray, len(payload)/8)
	for i := range addresses {
		address := int64(be64(payload[i*8 : i*8+8]))
		if address < 0 {
			return nil, formatError("address array contains a negative address")
		}
		addresses[i] = address
	}
	return addresses, nil
}

// IdentityTuple is one 24-byte hash/key/value entry of an identity-index
// bucket.
type IdentityTuple struct {
	Hash       int64
	KeyAddress int64
	Value      int64
}

// ReadIdentityTuples parses the 24-byte tuple array record at addr.
func (p *Project) ReadIdentityTuples(addr int64) ([]IdentityTuple, error) {
	payload, err := p.readArrayRecord(addr, 24)
	if err != nil {
		return nil, err
	}
	tuples := make([]IdentityTuple, len(payload)/24)
	for i := range tuples {
		chunk := payload[i*24 : (i+1)*24]
		tuples[i] = IdentityTuple{
			Hash:       int64(be64(chunk[0:8])),
			KeyAddress: int64(be64(chunk[8:16])),
			Value:      int64(be64(chunk[16:24])),
		}
		if tuples[i].KeyAddress < 0 {
			return nil, formatError("identity index contains a negative key")
		}
	}
	return tuples, nil
}

// ReadUTF16Array decodes the UTF-16BE character-array record at addr.
func (p *Project) ReadUTF16Array(addr int64) (string, error) {
	payload, err := p.readArrayRecord(addr, 2)
	if err != nil {
		return "", err
	}
	return decodeUTF16BE(payload), nil
}

func decodeUTF16BE(b []byte) string {
	units := make([]uint16, len(b)/2)
	for i := range units {
		units[i] = uint16(b[i*2])<<8 | uint16(b[i*2+1])
	}
	return string(utf16.Decode(units))
}

func be32(b []byte) int32 {
	return int32(uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3]))
}

func be64(b []byte) uint64 {
	return uint64(b[0])<<56 | uint64(b[1])<<48 | uint64(b[2])<<40 | uint64(b[3])<<32 |
		uint64(b[4])<<24 | uint64(b[5])<<16 | uint64(b[6])<<8 | uint64(b[7])
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
