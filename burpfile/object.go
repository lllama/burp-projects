package burpfile

// ObjectField is one descriptor entry: a field id and its offset relative to
// the object start.
type ObjectField struct {
	FieldID        uint8
	RelativeOffset int16
}

// CompactObject is the parsed header of one persistent object:
//
//	uint8 flags, uint8 type, uint8 subtype, uint8 descriptor_count,
//	descriptor[descriptor_count]
//
// Each descriptor is three bytes (field_id, int16 relative offset). Field
// ids are searched in the descriptor table, so byte positions are not fixed.
// If flags bit 0 is set the record is a forwarding record; its replacement
// address is the signed 64-bit value at offset +1 and no descriptors follow.
type CompactObject struct {
	Offset            int64
	Flags             uint8
	TypeID            uint8
	Subtype           uint8
	Fields            []ObjectField
	ForwardingAddress int64 // valid only when IsForwarding
}

// IsForwarding reports whether this record forwards to another address.
func (o *CompactObject) IsForwarding() bool { return o.Flags&1 != 0 }

// Field returns the descriptor for the given field id.
func (o *CompactObject) Field(fieldID uint8) (ObjectField, bool) {
	for _, field := range o.Fields {
		if field.FieldID == fieldID {
			return field, true
		}
	}
	return ObjectField{}, false
}

// CompactObject parses the object header at addr, mirroring
// prub.parser.parse_compact_object including all its descriptor validations.
func (p *Project) CompactObject(addr int64) (*CompactObject, error) {
	if addr < 0 {
		return nil, formatError("object offset must not be negative: %d", addr)
	}
	flags, err := p.u8at(addr)
	if err != nil {
		return nil, formatError("object header at %d exceeds available data", addr)
	}
	object := &CompactObject{Offset: addr, Flags: flags}
	if flags&1 != 0 {
		forwardingAddress, err := p.i64at(addr + 1)
		if err != nil {
			return nil, formatError("forwarding record at %d exceeds available data", addr)
		}
		if forwardingAddress <= 0 {
			return nil, formatError("invalid forwarding address: %d", forwardingAddress)
		}
		object.ForwardingAddress = forwardingAddress
		return object, nil
	}

	typeID, err := p.u8at(addr + 1)
	if err != nil {
		return nil, err
	}
	subtype, err := p.u8at(addr + 2)
	if err != nil {
		return nil, err
	}
	descriptorCount, err := p.u8at(addr + 3)
	if err != nil {
		return nil, err
	}
	object.TypeID = typeID
	object.Subtype = subtype

	descriptorTableSize := int64(4 + 3*int(descriptorCount))
	if _, err := p.slice(addr, descriptorTableSize); err != nil {
		return nil, formatError(
			"descriptor table ending at %d exceeds available data", addr+descriptorTableSize)
	}

	fields := make([]ObjectField, 0, descriptorCount)
	seenFieldIDs := make(map[uint8]bool)
	previousOffset := descriptorTableSize - 1
	for index := uint8(0); index < descriptorCount; index++ {
		entryOffset := addr + 4 + 3*int64(index)
		fieldID, err := p.u8at(entryOffset)
		if err != nil {
			return nil, err
		}
		relativeOffset, err := p.i16at(entryOffset + 1)
		if err != nil {
			return nil, err
		}
		if fieldID >= 128 {
			return nil, formatError("invalid field ID: %d", fieldID)
		}
		if seenFieldIDs[fieldID] {
			return nil, formatError("duplicate field ID: %d", fieldID)
		}
		if int64(relativeOffset) < descriptorTableSize {
			return nil, formatError(
				"field %d offset %d overlaps descriptor table", fieldID, relativeOffset)
		}
		if int64(relativeOffset) <= previousOffset {
			return nil, formatError(
				"field %d offset %d is not increasing", fieldID, relativeOffset)
		}
		if addr+int64(relativeOffset) >= int64(len(p.data)) {
			return nil, formatError(
				"field %d address %d exceeds available data %d",
				fieldID, addr+int64(relativeOffset), len(p.data))
		}
		fields = append(fields, ObjectField{FieldID: fieldID, RelativeOffset: relativeOffset})
		seenFieldIDs[fieldID] = true
		previousOffset = int64(relativeOffset)
	}
	object.Fields = fields
	return object, nil
}

// Resolve follows bounded forwarding records and returns the address of the
// current object (prub.parser.resolve_compact_object).
func (p *Project) Resolve(addr int64) (int64, error) {
	if addr < 0 {
		return 0, formatError("object offset must not be negative: %d", addr)
	}
	visited := make(map[int64]bool)
	current := addr
	for depth := 0; depth <= MaxForwardDepth; depth++ {
		if visited[current] {
			return 0, formatError("forwarding cycle at address %d", current)
		}
		visited[current] = true
		object, err := p.CompactObject(current)
		if err != nil {
			return 0, err
		}
		if !object.IsForwarding() {
			return current, nil
		}
		current = object.ForwardingAddress
	}
	return 0, formatError("forwarding depth exceeds limit %d", MaxForwardDepth)
}

// ResolveObject follows forwarding records and parses the current object.
func (p *Project) ResolveObject(addr int64) (*CompactObject, error) {
	resolved, err := p.Resolve(addr)
	if err != nil {
		return nil, err
	}
	return p.CompactObject(resolved)
}

// ---------------------------------------------------------- field readers --

func (p *Project) requireNormal(o *CompactObject) error {
	if o.IsForwarding() {
		return formatError("cannot read fields from a forwarding record")
	}
	return nil
}

// ObjectAddress reads a descriptor-backed 64-bit object address. The second
// result is false when the field is absent or holds the 0 (null) sentinel;
// negative addresses are errors (prub.parser.read_object_address).
func (p *Project) ObjectAddress(o *CompactObject, fieldID uint8) (int64, bool, error) {
	if err := p.requireNormal(o); err != nil {
		return 0, false, err
	}
	field, ok := o.Field(fieldID)
	if !ok {
		return 0, false, nil
	}
	address, err := p.i64at(o.Offset + int64(field.RelativeOffset))
	if err != nil {
		return 0, false, formatError(
			"address field %d at %d exceeds available data",
			fieldID, o.Offset+int64(field.RelativeOffset))
	}
	if address < 0 {
		return 0, false, formatError("negative object address in field %d: %d", fieldID, address)
	}
	if address == 0 {
		return 0, false, nil
	}
	return address, true, nil
}

// Int32Field reads a descriptor-backed signed 32-bit field; absent when the
// field id is not in the descriptor table.
func (p *Project) Int32Field(o *CompactObject, fieldID uint8) (int32, bool, error) {
	if err := p.requireNormal(o); err != nil {
		return 0, false, err
	}
	field, ok := o.Field(fieldID)
	if !ok {
		return 0, false, nil
	}
	value, err := p.i32at(o.Offset + int64(field.RelativeOffset))
	if err != nil {
		return 0, false, formatError(
			"int32 field %d at %d exceeds available data",
			fieldID, o.Offset+int64(field.RelativeOffset))
	}
	return value, true, nil
}

// Uint8Field reads a descriptor-backed unsigned byte field.
func (p *Project) Uint8Field(o *CompactObject, fieldID uint8) (uint8, bool, error) {
	if err := p.requireNormal(o); err != nil {
		return 0, false, err
	}
	field, ok := o.Field(fieldID)
	if !ok {
		return 0, false, nil
	}
	value, err := p.u8at(o.Offset + int64(field.RelativeOffset))
	if err != nil {
		return 0, false, err
	}
	return value, true, nil
}

// Uint64Field reads a descriptor-backed unsigned 64-bit field.
func (p *Project) Uint64Field(o *CompactObject, fieldID uint8) (uint64, bool, error) {
	if err := p.requireNormal(o); err != nil {
		return 0, false, err
	}
	field, ok := o.Field(fieldID)
	if !ok {
		return 0, false, nil
	}
	value, err := p.u64at(o.Offset + int64(field.RelativeOffset))
	if err != nil {
		return 0, false, err
	}
	return value, true, nil
}
