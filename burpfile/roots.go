package burpfile

import "fmt"

// ProjectRoot resolves and parses the compact object at the header project
// root (prub field semantics: 0 installation id, 1 proxy root, 2 repeater
// root, 3 target root, 6 project name, 15 project identifier).
func (p *Project) ProjectRoot() (*CompactObject, error) {
	return p.ResolveObject(p.header.ProjectRoot)
}

// Metadata mirrors prub's inspect_project_metadata.
func (p *Project) Metadata() (*Metadata, error) {
	root, err := p.ProjectRoot()
	if err != nil {
		return nil, err
	}
	out := &Metadata{
		HeaderRandomIdentifier: p.header.RandomIdentifier,
		SchemaCurrent:          p.header.SchemaCurrent,
		SchemaFloor:            p.header.SchemaFloor,
	}
	if installID, ok, err := p.rootString(root, 0); err != nil {
		return nil, err
	} else if ok {
		out.InstallationID = &installID
	}
	if projectName, ok, err := p.rootString(root, 6); err != nil {
		return nil, err
	} else if ok {
		out.ProjectName = &projectName
	}
	if projectID, ok, err := p.rootString(root, 15); err != nil {
		return nil, err
	} else if ok {
		out.ProjectIdentifier = &projectID
	}
	return out, nil
}

func (p *Project) rootString(root *CompactObject, fieldID uint8) (string, bool, error) {
	address, ok, err := p.ObjectAddress(root, fieldID)
	if err != nil || !ok {
		return "", false, err
	}
	return p.ImmutableString(address)
}

// Proxy mirrors prub's inspect_proxy_items.
func (p *Project) Proxy() (*ProxyInfo, error) {
	root, err := p.ProjectRoot()
	if err != nil {
		return nil, err
	}
	proxyAddress, ok, err := p.ObjectAddress(root, 1)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, formatError("project root has no Proxy root address")
	}
	proxyRoot, err := p.ResolveObject(proxyAddress)
	if err != nil {
		return nil, err
	}

	out := &ProxyInfo{
		RootAddress: proxyRoot.Offset,
		Collections: []ProxyCollection{},
	}
	for _, fieldID := range []uint8{0, 1} {
		collectionAddress, ok, err := p.ObjectAddress(proxyRoot, fieldID)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, formatError(
				"Proxy root has no HTTP collection in field %d", fieldID)
		}
		collection := ProxyCollection{
			FieldID: int(fieldID),
			Address: collectionAddress,
			Items:   []ProxyItem{},
		}
		itemAddresses, err := p.ChunkedCollectionAddresses(collectionAddress)
		if err != nil {
			return nil, err
		}
		for _, itemAddress := range itemAddresses {
			item, err := p.ResolveObject(itemAddress)
			if err != nil {
				return nil, err
			}
			variants := make(map[string]*ByteVariant)
			for _, variantFieldID := range []uint8{15, 16, 17, 18, 19, 20} {
				variant, err := p.byteVariant(item, variantFieldID)
				if err != nil {
					return nil, err
				}
				variants[fmt.Sprintf("%d", variantFieldID)] = variant
			}
			collection.Items = append(collection.Items, ProxyItem{
				Address:      item.Offset,
				ByteVariants: variants,
				Subtype:      item.Subtype,
				TypeID:       item.TypeID,
			})
		}
		out.Collections = append(out.Collections, collection)
	}
	return out, nil
}

func (p *Project) byteVariant(item *CompactObject, fieldID uint8) (*ByteVariant, error) {
	address, ok, err := p.ObjectAddress(item, fieldID)
	if err != nil {
		return nil, err
	}
	if !ok {
		return &ByteVariant{}, nil
	}
	record, err := p.ReadRecord(address)
	if err != nil {
		return nil, err
	}
	logical := record.LogicalLength
	return &ByteVariant{Address: &address, Length: &logical}, nil
}

// Repeater mirrors prub's inspect_repeater_items.
func (p *Project) Repeater() (*RepeaterInfo, error) {
	root, err := p.ProjectRoot()
	if err != nil {
		return nil, err
	}
	repeaterAddress, ok, err := p.ObjectAddress(root, 2)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, formatError("project root has no Repeater root address")
	}
	repeaterRoot, err := p.ResolveObject(repeaterAddress)
	if err != nil {
		return nil, err
	}

	tabCollectionAddress, okTabs, err := p.ObjectAddress(repeaterRoot, 1)
	if err != nil {
		return nil, err
	}
	groupCollectionAddress, okGroups, err := p.ObjectAddress(repeaterRoot, 4)
	if err != nil {
		return nil, err
	}
	if !okTabs || !okGroups {
		return nil, formatError("Repeater root is missing a required collection")
	}

	out := &RepeaterInfo{
		RootAddress:            repeaterRoot.Offset,
		TabCollectionAddress:   &tabCollectionAddress,
		GroupCollectionAddress: &groupCollectionAddress,
		Groups:                 []RepeaterGroup{},
		Tabs:                   []RepeaterTab{},
	}

	groupAddresses, err := p.DirectCollectionAddresses(groupCollectionAddress)
	if err != nil {
		return nil, err
	}
	for _, groupAddress := range groupAddresses {
		group, err := p.ResolveObject(groupAddress)
		if err != nil {
			return nil, err
		}
		entry := RepeaterGroup{Address: group.Offset}
		if nameAddress, ok, err := p.ObjectAddress(group, 0); err != nil {
			return nil, err
		} else if ok {
			if name, present, err := p.ImmutableString(nameAddress); err != nil {
				return nil, err
			} else if present {
				entry.Name = &name
			}
		}
		if colorID, ok, err := p.Uint8Field(group, 1); err != nil {
			return nil, err
		} else if ok {
			entry.ColorID = &colorID
			if colorID == 7 {
				colorEnum := "GROUP_0"
				entry.ColorEnum = &colorEnum
			}
		}
		if expanded, ok, err := p.Uint8Field(group, 2); err != nil {
			return nil, err
		} else if ok {
			value := expanded != 0
			entry.Expanded = &value
		}
		if index, ok, err := p.Int32Field(group, 3); err != nil {
			return nil, err
		} else if ok {
			entry.Index = &index
		}
		if uuidAddress, ok, err := p.ObjectAddress(group, 4); err != nil {
			return nil, err
		} else if ok {
			if uuid, err := p.UUIDString(uuidAddress); err != nil {
				return nil, err
			} else {
				entry.UUID = &uuid
			}
		}
		out.Groups = append(out.Groups, entry)
	}

	tabAddresses, err := p.DirectCollectionAddresses(tabCollectionAddress)
	if err != nil {
		return nil, err
	}
	for _, tabAddress := range tabAddresses {
		tab, err := p.ResolveObject(tabAddress)
		if err != nil {
			return nil, err
		}
		entry := RepeaterTab{
			Address: tab.Offset,
			TypeID:  tab.TypeID,
			Pairs:   []RepeaterPair{},
		}
		if captionAddress, ok, err := p.ObjectAddress(tab, 0); err != nil {
			return nil, err
		} else if ok {
			if caption, err := p.MutableString(captionAddress); err != nil {
				return nil, err
			} else {
				entry.Caption = &caption
			}
		}
		if groupAddress, ok, err := p.ObjectAddress(tab, 32); err != nil {
			return nil, err
		} else if ok {
			entry.GroupAddress = &groupAddress
		}
		if uuidAddress, ok, err := p.ObjectAddress(tab, 33); err != nil {
			return nil, err
		} else if ok {
			if uuid, err := p.UUIDString(uuidAddress); err != nil {
				return nil, err
			} else {
				entry.UUID = &uuid
			}
		}
		if currentRequestAddress, ok, err := p.ObjectAddress(tab, 4); err != nil {
			return nil, err
		} else if ok {
			entry.CurrentRequestAddress = &currentRequestAddress
		}
		if pairCollectionAddress, ok, err := p.ObjectAddress(tab, 2); err != nil {
			return nil, err
		} else if ok {
			pairAddresses, err := p.DirectCollectionAddresses(pairCollectionAddress)
			if err != nil {
				return nil, err
			}
			for _, pairAddress := range pairAddresses {
				pair, err := p.ResolveObject(pairAddress)
				if err != nil {
					return nil, err
				}
				pairEntry := RepeaterPair{Address: pair.Offset}
				if pairEntry.Request, err = p.recordRef(pair, 2); err != nil {
					return nil, err
				}
				if pairEntry.Response, err = p.recordRef(pair, 3); err != nil {
					return nil, err
				}
				entry.Pairs = append(entry.Pairs, pairEntry)
			}
		}
		out.Tabs = append(out.Tabs, entry)
	}
	return out, nil
}

func (p *Project) recordRef(o *CompactObject, fieldID uint8) (RecordRef, error) {
	address, ok, err := p.ObjectAddress(o, fieldID)
	if err != nil {
		return RecordRef{}, err
	}
	if !ok {
		return RecordRef{}, nil
	}
	record, err := p.ReadRecord(address)
	if err != nil {
		return RecordRef{}, err
	}
	logical := record.LogicalLength
	return RecordRef{Address: &address, Length: &logical}, nil
}

// Target mirrors prub's inspect_target_items.
func (p *Project) Target() (*TargetInfo, error) {
	root, err := p.ProjectRoot()
	if err != nil {
		return nil, err
	}
	targetAddress, ok, err := p.ObjectAddress(root, 3)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, formatError("project root has no Target root address")
	}
	targetRoot, err := p.ResolveObject(targetAddress)
	if err != nil {
		return nil, err
	}
	identityIndexAddress, ok, err := p.ObjectAddress(targetRoot, 3)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, formatError("Target root has no identity index address")
	}

	out := &TargetInfo{
		RootAddress:          targetRoot.Offset,
		IdentityIndexAddress: &identityIndexAddress,
		Nodes:                []TargetNode{},
	}

	entries, err := p.IdentityIndexEntries(identityIndexAddress)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if entry.KeyAddress == 0 {
			continue
		}
		node, err := p.ResolveObject(entry.KeyAddress)
		if err != nil {
			return nil, err
		}
		nodeData := TargetNode{
			Bucket:     entry.Bucket,
			Hash:       entry.Hash,
			KeyAddress: entry.KeyAddress,
			Subtype:    node.Subtype,
			TypeID:     node.TypeID,
			Value:      entry.Value,
		}
		if messageAddress, ok, err := p.ObjectAddress(node, 33); err != nil {
			return nil, err
		} else if ok {
			nodeData.MessageAddress = &messageAddress
			message, err := p.ResolveObject(messageAddress)
			if err != nil {
				return nil, err
			}
			if nodeData.Request, err = p.recordRef(message, 0); err != nil {
				return nil, err
			}
			if nodeData.Response, err = p.recordRef(message, 1); err != nil {
				return nil, err
			}
		}
		out.Nodes = append(out.Nodes, nodeData)
	}
	return out, nil
}

// identityEntry is one decoded identity-index entry: the hash/key/value
// tuple plus the bucket it was found in.
type identityEntry struct {
	Bucket     int
	Hash       int64
	KeyAddress int64
	Value      int64
}

// IdentityIndexEntries reads the Zpt2 identity index (field 2 expected size,
// field 3 chunked bucket collection), mirroring
// prub.parser.read_identity_index_entries.
func (p *Project) IdentityIndexEntries(indexAddress int64) ([]identityEntry, error) {
	index, err := p.ResolveObject(indexAddress)
	if err != nil {
		return nil, err
	}
	expectedSize, okSize, err := p.Int32Field(index, 2)
	if err != nil {
		return nil, err
	}
	bucketCollectionAddress, okBuckets, err := p.ObjectAddress(index, 3)
	if err != nil {
		return nil, err
	}
	if !okSize || !okBuckets {
		return nil, formatError("identity index is missing a required field")
	}
	if expectedSize < 0 {
		return nil, formatError("negative identity index size: %d", expectedSize)
	}

	bucketAddresses, err := p.ChunkedCollectionSlots(bucketCollectionAddress)
	if err != nil {
		return nil, err
	}
	var entries []identityEntry
	for bucketIndex, bucketAddress := range bucketAddresses {
		if bucketAddress == 0 {
			continue
		}
		bucket, err := p.ResolveObject(bucketAddress)
		if err != nil {
			return nil, err
		}
		bucketSize, okSize, err := p.Int32Field(bucket, 0)
		if err != nil {
			return nil, err
		}
		tupleArrayAddress, okTuples, err := p.ObjectAddress(bucket, 1)
		if err != nil {
			return nil, err
		}
		if !okSize || !okTuples {
			return nil, formatError("bucket %d is missing a field", bucketIndex)
		}
		if bucketSize < 0 {
			return nil, formatError("negative bucket size: %d", bucketSize)
		}
		tuples, err := p.ReadIdentityTuples(tupleArrayAddress)
		if err != nil {
			return nil, err
		}
		if bucketSize > int32(len(tuples)) {
			return nil, formatError(
				"bucket size %d exceeds tuple capacity %d", bucketSize, len(tuples))
		}
		for _, tuple := range tuples[:bucketSize] {
			entries = append(entries, identityEntry{
				Bucket:     bucketIndex,
				Hash:       tuple.Hash,
				KeyAddress: tuple.KeyAddress,
				Value:      tuple.Value,
			})
		}
	}
	if len(entries) != int(expectedSize) {
		return nil, formatError(
			"identity index reports %d entries; decoded %d", expectedSize, len(entries))
	}
	return entries, nil
}
