package burpfile

// ChunkedCollection is the verified Zwtw/Zmea layout: field 0 logical size,
// field 1 chunk size, field 2 chunk-list address, field 3 leading offset.
type ChunkedCollection struct {
	Address       int64
	Size          int32
	ChunkSize     int32
	ChunkListAddr int64
	LeadingOffset int32
}

// ChunkedCollection parses the collection header at addr
// (prub.parser.read_chunked_collection_slots field validation).
func (p *Project) ChunkedCollection(addr int64) (*ChunkedCollection, error) {
	resolved, err := p.ResolveObject(addr)
	if err != nil {
		return nil, err
	}
	size, okSize, err := p.Int32Field(resolved, 0)
	if err != nil {
		return nil, err
	}
	chunkSize, okChunkSize, err := p.Int32Field(resolved, 1)
	if err != nil {
		return nil, err
	}
	chunkListAddr, okList, err := p.ObjectAddress(resolved, 2)
	if err != nil {
		return nil, err
	}
	leadingOffset, okLeading, err := p.Int32Field(resolved, 3)
	if err != nil {
		return nil, err
	}
	if !okSize || !okChunkSize || !okList || !okLeading {
		return nil, formatError("chunked collection is missing a required field")
	}
	if size < 0 {
		return nil, formatError("negative collection size: %d", size)
	}
	if chunkSize <= 0 {
		return nil, formatError("invalid collection chunk size: %d", chunkSize)
	}
	if leadingOffset < 0 {
		return nil, formatError("negative collection leading offset: %d", leadingOffset)
	}
	return &ChunkedCollection{
		Address:       resolved.Offset,
		Size:          size,
		ChunkSize:     chunkSize,
		ChunkListAddr: chunkListAddr,
		LeadingOffset: leadingOffset,
	}, nil
}

// ChunkedCollectionSlots returns the logical slot addresses (0 = null slot)
// of a chunked collection, mirroring prub's lookup: the collection's leading
// offset is added before selecting a chunk and slot.
func (p *Project) ChunkedCollectionSlots(addr int64) ([]int64, error) {
	collection, err := p.ChunkedCollection(addr)
	if err != nil {
		return nil, err
	}

	chunkList, err := p.ResolveObject(collection.ChunkListAddr)
	if err != nil {
		return nil, err
	}
	chunkCount, okCount, err := p.Int32Field(chunkList, 0)
	if err != nil {
		return nil, err
	}
	chunkArrayAddr, okArray, err := p.ObjectAddress(chunkList, 1)
	if err != nil {
		return nil, err
	}
	if !okCount || !okArray {
		return nil, formatError("chunk list is missing a required field")
	}
	if chunkCount < 0 {
		return nil, formatError("negative chunk count: %d", chunkCount)
	}

	chunkAddresses, err := p.ReadAddressArray(chunkArrayAddr)
	if err != nil {
		return nil, err
	}
	if chunkCount > int32(len(chunkAddresses)) {
		return nil, formatError(
			"chunk count %d exceeds address capacity %d", chunkCount, len(chunkAddresses))
	}

	slots := make([]int64, 0, collection.Size)
	chunkCache := make(map[int64]AddressArray)
	for logicalIndex := int32(0); logicalIndex < collection.Size; logicalIndex++ {
		physicalIndex := int64(collection.LeadingOffset) + int64(logicalIndex)
		chunkIndex := physicalIndex / int64(collection.ChunkSize)
		slotIndex := physicalIndex % int64(collection.ChunkSize)
		if chunkIndex >= int64(chunkCount) {
			return nil, formatError(
				"logical item %d requires missing chunk %d", logicalIndex, chunkIndex)
		}
		chunkAddress := chunkAddresses[chunkIndex]
		if chunkAddress == 0 {
			return nil, formatError("chunk %d has a null address", chunkIndex)
		}
		chunk, cached := chunkCache[chunkAddress]
		if !cached {
			chunk, err = p.ReadAddressArray(chunkAddress)
			if err != nil {
				return nil, err
			}
			chunkCache[chunkAddress] = chunk
		}
		if int64(len(chunk)) != int64(collection.ChunkSize) {
			return nil, formatError(
				"chunk %d has %d slots; expected %d", chunkIndex, len(chunk), collection.ChunkSize)
		}
		slots = append(slots, chunk[slotIndex])
	}
	return slots, nil
}

// ChunkedCollectionAddresses returns only the nonnull logical addresses.
func (p *Project) ChunkedCollectionAddresses(addr int64) ([]int64, error) {
	slots, err := p.ChunkedCollectionSlots(addr)
	if err != nil {
		return nil, err
	}
	addresses := make([]int64, 0, len(slots))
	for logicalIndex, address := range slots {
		if address == 0 {
			return nil, formatError(
				"logical item %d resolves to a null address", logicalIndex)
		}
		addresses = append(addresses, address)
	}
	return addresses, nil
}

// DirectCollectionAddresses reads the verified Zg_i/Zmex layout: field 0
// logical size plus one backing address array
// (prub.parser.read_direct_collection_addresses).
func (p *Project) DirectCollectionAddresses(addr int64) ([]int64, error) {
	resolved, err := p.ResolveObject(addr)
	if err != nil {
		return nil, err
	}
	size, okSize, err := p.Int32Field(resolved, 0)
	if err != nil {
		return nil, err
	}
	backingAddress, okBacking, err := p.ObjectAddress(resolved, 1)
	if err != nil {
		return nil, err
	}
	if !okSize || !okBacking {
		return nil, formatError("direct collection is missing a required field")
	}
	if size < 0 {
		return nil, formatError("negative direct collection size: %d", size)
	}
	addresses, err := p.ReadAddressArray(backingAddress)
	if err != nil {
		return nil, err
	}
	if size > int32(len(addresses)) {
		return nil, formatError(
			"direct collection size %d exceeds address capacity %d", size, len(addresses))
	}
	logical := addresses[:size]
	for _, address := range logical {
		if address == 0 {
			return nil, formatError("direct collection contains a null logical address")
		}
	}
	return logical, nil
}
