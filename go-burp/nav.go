// Package burpfmt provides navigation over Burp Suite project (.burp) save
// files on top of the Kaitai-generated structural layer (burp_project.go).
//
// The generated types expose raw structure: variable records, address arrays,
// compact objects with descriptor tables, and find_* descriptor lookups.
// This file adds the graph semantics verified for schema 226/227:
// forwarding resolution, chunked/direct collection walking, string decoding,
// and typed accessors for the Proxy / Repeater / Target roots.
package burpfmt

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"unicode/utf16"

	"github.com/kaitai-io/kaitai_struct_go_runtime/kaitai"
)

const (
	// HeaderSize is the size of the 72-byte outer header.
	HeaderSize = 72
	// Magic is the outer storage magic value.
	Magic = 0x66858280
	// MaxOuterVersion is the highest supported outer storage version.
	MaxOuterVersion = 1
	// MaxCompatibility is the highest supported compatibility value.
	MaxCompatibility = -2142078604
	// MaxForwardDepth bounds forwarding-record chasing.
	MaxForwardDepth = 16
)

// ProjectFormatError marks bytes that violate verified format invariants.
type ProjectFormatError struct{ msg string }

func (e *ProjectFormatError) Error() string { return e.msg }

func formatError(format string, args ...interface{}) error {
	return &ProjectFormatError{msg: fmt.Sprintf(format, args...)}
}

// UnsupportedProjectVersionError marks projects requiring a newer reader.
type UnsupportedProjectVersionError struct{ msg string }

func (e *UnsupportedProjectVersionError) Error() string { return e.msg }

// Project is a parsed, read-only view of one .burp project file.
type Project struct {
	Path string
	Root *BurpProject

	io   *kaitai.Stream
	data []byte
	size int64
}

// Open reads the file into memory and parses the outer header.
func Open(path string) (*Project, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	stream := kaitai.NewStream(bytes.NewReader(data))
	root := NewBurpProject()
	if err := root.Read(stream, nil, root); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	p := &Project{
		Path: path,
		Root: root,
		io:   stream,
		data: data,
		size: int64(len(data)),
	}
	if err := p.validate(); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *Project) validate() error {
	h := p.Root.Header
	if h.OuterVersion < 0 || h.OuterVersion > MaxOuterVersion {
		return &UnsupportedProjectVersionError{
			msg: fmt.Sprintf("unsupported outer version: %d", h.OuterVersion),
		}
	}
	if h.Compatibility > MaxCompatibility {
		return &UnsupportedProjectVersionError{
			msg: fmt.Sprintf("unsupported compatibility value: %d", h.Compatibility),
		}
	}
	if h.SegmentSpan <= 0 {
		return formatError("invalid segment span: %d", h.SegmentSpan)
	}
	if h.AllocationCursor < HeaderSize {
		return formatError("allocation cursor %d precedes object data", h.AllocationCursor)
	}
	if h.MetadataRoot < 0 || h.ProjectRoot < 0 {
		return formatError("root addresses must not be negative")
	}
	if h.AllocationCursor > p.size {
		return formatError("allocation cursor %d exceeds available data %d", h.AllocationCursor, p.size)
	}
	return nil
}

// Header returns the parsed outer header.
func (p *Project) Header() *BurpProject_Header { return p.Root.Header }

// ----------------------------------------------------------------- graph --

// resolve follows forwarding records (flags bit 0) with cycle detection and
// returns the address of the current object.
func (p *Project) resolve(addr int64) (int64, error) {
	if addr < 0 {
		return 0, formatError("object address must not be negative: %d", addr)
	}
	visited := make(map[int64]bool)
	current := addr
	for depth := 0; depth <= MaxForwardDepth; depth++ {
		if visited[current] {
			return 0, formatError("forwarding cycle at address %d", current)
		}
		visited[current] = true
		obj, err := p.newCompactObject(current)
		if err != nil {
			return 0, err
		}
		forwarding, err := obj.IsForwarding()
		if err != nil {
			return 0, err
		}
		if !forwarding {
			return current, nil
		}
		fwd, err := obj.FwdAddr()
		if err != nil {
			return 0, err
		}
		if fwd <= 0 {
			return 0, formatError("invalid forwarding address: %d", fwd)
		}
		current = fwd
	}
	return 0, formatError("forwarding depth exceeds limit %d", MaxForwardDepth)
}

type resolvedCompact struct {
	addr    int64
	typeID  uint8
	subtype uint8
}

func (p *Project) resolveCompact(addr int64) (*resolvedCompact, error) {
	resolved, err := p.resolve(addr)
	if err != nil {
		return nil, err
	}
	obj, err := p.newCompactObject(resolved)
	if err != nil {
		return nil, err
	}
	return &resolvedCompact{
		addr:    resolved,
		typeID:  obj.TypeId,
		subtype: obj.Subtype,
	}, nil
}

func (p *Project) newCompactObject(addr int64) (*BurpProject_CompactObject, error) {
	obj := NewBurpProject_CompactObject(addr)
	err := p.readAt(addr, func() error { return obj.Read(p.io, nil, p.Root) })
	if err != nil {
		return nil, err
	}
	return obj, nil
}

// readAt seeks to addr and runs read, restoring the stream position after.
func (p *Project) readAt(addr int64, read func() error) error {
	if addr < 0 {
		return formatError("address must not be negative: %d", addr)
	}
	prev, err := p.io.Pos()
	if err != nil {
		return err
	}
	if _, err := p.io.Seek(addr, io.SeekStart); err != nil {
		return err
	}
	if err := read(); err != nil {
		return err
	}
	_, err = p.io.Seek(prev, io.SeekStart)
	return err
}

// ---------------------------------------------------------------- fields --

// i32Of reads a find_i32 field; ok is false when the field is absent.
func (p *Project) i32OfE(f *BurpProject_FindI32, ferr error) (int32, bool, error) {
	if ferr != nil {
		return 0, false, ferr
	}
	found, err := f.Found()
	if err != nil || !found {
		return 0, false, err
	}
	v, err := f.Value()
	return v, true, err
}

// addrOf reads a find_addr field; ok is false when the field is absent or
// the stored address is the 0 sentinel.
func (p *Project) addrOfE(f *BurpProject_FindAddr, ferr error) (int64, bool, error) {
	if ferr != nil {
		return 0, false, ferr
	}
	found, err := f.Found()
	if err != nil || !found {
		return 0, false, err
	}
	v, err := f.Value()
	if err != nil {
		return 0, false, err
	}
	if v == 0 {
		return 0, false, nil
	}
	if v < 0 {
		return 0, false, formatError("negative object address: %d", v)
	}
	return v, true, nil
}

func (p *Project) u8OfE(f *BurpProject_FindU8, ferr error) (uint8, bool, error) {
	if ferr != nil {
		return 0, false, ferr
	}
	found, err := f.Found()
	if err != nil || !found {
		return 0, false, err
	}
	v, err := f.Value()
	return v, true, err
}

func (p *Project) u64OfE(f *BurpProject_FindU64, ferr error) (uint64, bool, error) {
	if ferr != nil {
		return 0, false, ferr
	}
	found, err := f.Found()
	if err != nil || !found {
		return 0, false, err
	}
	v, err := f.Value()
	return v, true, err
}

// --------------------------------------------------------------- records --

// ReadRecord parses the variable record at addr, validating its framing.
func (p *Project) ReadRecord(addr int64) (*BurpProject_VarRecord, error) {
	if addr < 0 {
		return nil, formatError("record offset must not be negative: %d", addr)
	}
	rec := NewBurpProject_VarRecord()
	err := p.readAt(addr, func() error { return rec.Read(p.io, nil, p.Root) })
	if err != nil {
		return nil, err
	}
	logical := rec.LogicalLength
	stored := logical
	if stored == 0 {
		stored = 1
	}
	if rec.TotalSize != 8+stored {
		return nil, formatError(
			"record total size %d does not match expected %d", rec.TotalSize, 8+stored)
	}
	if logical < 0 {
		return nil, formatError("negative logical length: %d", logical)
	}
	return rec, nil
}

// RecordPayload returns the logical payload bytes of the record at addr.
func (p *Project) RecordPayload(addr int64) ([]byte, error) {
	rec, err := p.ReadRecord(addr)
	if err != nil {
		return nil, err
	}
	return rec.Data, nil
}

// readAddressArray parses an 8-byte-element array record at addr.
func (p *Project) readAddressArray(addr int64) ([]int64, error) {
	if addr < 0 {
		return nil, formatError("array offset must not be negative: %d", addr)
	}
	arr := NewBurpProject_AddressArray()
	err := p.readAt(addr, func() error { return arr.Read(p.io, nil, p.Root) })
	if err != nil {
		return nil, err
	}
	count := arr.ElementCount
	if count < 0 {
		return nil, formatError("negative element count: %d", count)
	}
	payload := count * 8
	stored := payload
	if stored == 0 {
		stored = 1
	}
	if arr.TotalSize != 8+stored {
		return nil, formatError(
			"array total size %d does not match expected %d", arr.TotalSize, 8+stored)
	}
	for _, a := range arr.Addresses {
		if a < 0 {
			return nil, formatError("address array contains a negative address")
		}
	}
	return arr.Addresses, nil
}

// ReadBucketTuples parses a 24-byte tuple array record at addr.
func (p *Project) ReadBucketTuples(addr int64) ([]*BurpProject_BucketTuple, error) {
	if addr < 0 {
		return nil, formatError("array offset must not be negative: %d", addr)
	}
	arr := NewBurpProject_BucketTuples()
	err := p.readAt(addr, func() error { return arr.Read(p.io, nil, p.Root) })
	if err != nil {
		return nil, err
	}
	count := arr.ElementCount
	if count < 0 {
		return nil, formatError("negative element count: %d", count)
	}
	stored := count * 24
	if stored == 0 {
		stored = 1
	}
	if arr.TotalSize != 8+stored {
		return nil, formatError(
			"array total size %d does not match expected %d", arr.TotalSize, 8+stored)
	}
	for _, t := range arr.Tuples {
		if t.KeyAddress < 0 {
			return nil, formatError("identity index contains a negative key")
		}
	}
	return arr.Tuples, nil
}

// --------------------------------------------------------------- strings --

// readUTF16Array parses a UTF-16BE character-array record at addr.
func (p *Project) readUTF16Array(addr int64) (string, error) {
	if addr < 0 {
		return "", formatError("array offset must not be negative: %d", addr)
	}
	arr := NewBurpProject_Utf16Array()
	err := p.readAt(addr, func() error { return arr.Read(p.io, nil, p.Root) })
	if err != nil {
		return "", err
	}
	count := arr.CharCount
	if count < 0 {
		return "", formatError("negative character count: %d", count)
	}
	payload := count * 2
	stored := payload
	if stored == 0 {
		stored = 1
	}
	if arr.TotalSize != 8+stored {
		return "", formatError(
			"array total size %d does not match expected %d", arr.TotalSize, 8+stored)
	}
	return decodeUTF16BE(arr.Data)
}

func decodeUTF16BE(b []byte) (string, error) {
	if len(b)%2 != 0 {
		return "", formatError("UTF-16BE array has odd byte length %d", len(b))
	}
	units := make([]uint16, len(b)/2)
	for i := range units {
		units[i] = binary.BigEndian.Uint16(b[i*2:])
	}
	return string(utf16.Decode(units)), nil
}

// immutableString reads a Zv1/Zmju string object.
func (p *Project) immutableString(addr int64) (string, error) {
	resolved, err := p.resolve(addr)
	if err != nil {
		return "", err
	}
	obj := NewBurpProject_ImmutableString(resolved)
	err = p.readAt(resolved, func() error { return obj.Read(p.io, nil, p.Root) })
	if err != nil {
		return "", err
	}
	chars, ok, err := p.addrOfE(obj.CharsAddr())
	if err != nil || !ok {
		return "", err
	}
	return p.readUTF16Array(chars)
}

// mutableString reads a Zvp/Zmjj chunked mutable string object.
func (p *Project) mutableString(addr int64) (string, error) {
	resolved, err := p.resolve(addr)
	if err != nil {
		return "", err
	}
	obj := NewBurpProject_MutableString(resolved)
	err = p.readAt(resolved, func() error { return obj.Read(p.io, nil, p.Root) })
	if err != nil {
		return "", err
	}
	length, okLength, err := p.i32OfE(obj.Length())
	if err != nil {
		return "", err
	}
	width, okWidth, err := p.i32OfE(obj.ChunkWidth())
	if err != nil {
		return "", err
	}
	chunksAddr, okChunks, err := p.addrOfE(obj.ChunksAddr())
	if err != nil {
		return "", err
	}
	if !okLength || !okWidth || !okChunks {
		return "", formatError("mutable string is missing a required field")
	}
	if length < 0 || width <= 0 {
		return "", formatError("mutable string has invalid dimensions")
	}
	chunkAddrs, err := p.directAddrs(chunksAddr)
	if err != nil {
		return "", err
	}
	var text []rune
	for _, chunkAddr := range chunkAddrs {
		chunk, err := p.readUTF16Array(chunkAddr)
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

// uuidString reads the two-long UUID object at addr.
func (p *Project) uuidString(addr int64) (string, error) {
	resolved, err := p.resolve(addr)
	if err != nil {
		return "", err
	}
	obj := NewBurpProject_UuidObj(resolved)
	err = p.readAt(resolved, func() error { return obj.Read(p.io, nil, p.Root) })
	if err != nil {
		return "", err
	}
	high, okHigh, err := p.u64OfE(obj.High())
	if err != nil {
		return "", err
	}
	low, okLow, err := p.u64OfE(obj.Low())
	if err != nil {
		return "", err
	}
	if !okHigh || !okLow {
		return "", formatError("UUID object is missing a required field")
	}
	var b [16]byte
	binary.BigEndian.PutUint64(b[0:], high)
	binary.BigEndian.PutUint64(b[8:], low)
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// ----------------------------------------------------------- collections --

// chunkedSlots walks a Zwtw chunked collection and returns the logical slot
// addresses (0 = null slot).
func (p *Project) chunkedSlots(addr int64) ([]int64, error) {
	resolved, err := p.resolve(addr)
	if err != nil {
		return nil, err
	}
	obj := NewBurpProject_ChunkedCollection(resolved)
	err = p.readAt(resolved, func() error { return obj.Read(p.io, nil, p.Root) })
	if err != nil {
		return nil, err
	}
	size, okSize, err := p.i32OfE(obj.Size())
	if err != nil {
		return nil, err
	}
	chunkSize, okChunkSize, err := p.i32OfE(obj.ChunkSize())
	if err != nil {
		return nil, err
	}
	listAddr, okList, err := p.addrOfE(obj.ChunkListAddr())
	if err != nil {
		return nil, err
	}
	leading, okLeading, err := p.i32OfE(obj.LeadingOffset())
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
	if leading < 0 {
		return nil, formatError("negative collection leading offset: %d", leading)
	}

	listResolved, err := p.resolve(listAddr)
	if err != nil {
		return nil, err
	}
	list := NewBurpProject_ChunkList(listResolved)
	err = p.readAt(listResolved, func() error { return list.Read(p.io, nil, p.Root) })
	if err != nil {
		return nil, err
	}
	chunkCount, okCount, err := p.i32OfE(list.ChunkCount())
	if err != nil {
		return nil, err
	}
	chunkArray, okArray, err := p.addrOfE(list.ChunkArrayAddr())
	if err != nil {
		return nil, err
	}
	if !okCount || !okArray {
		return nil, formatError("chunk list is missing a required field")
	}
	if chunkCount < 0 {
		return nil, formatError("negative chunk count: %d", chunkCount)
	}

	chunkAddrs, err := p.readAddressArray(chunkArray)
	if err != nil {
		return nil, err
	}
	if chunkCount > int32(len(chunkAddrs)) {
		return nil, formatError(
			"chunk count %d exceeds address capacity %d", chunkCount, len(chunkAddrs))
	}

	slots := make([]int64, 0, size)
	chunkCache := make(map[int64][]int64)
	for logical := int32(0); logical < size; logical++ {
		physical := int64(leading) + int64(logical)
		chunkIndex := physical / int64(chunkSize)
		slotIndex := physical % int64(chunkSize)
		if chunkIndex >= int64(chunkCount) {
			return nil, formatError(
				"logical item %d requires missing chunk %d", logical, chunkIndex)
		}
		chunkAddr := chunkAddrs[chunkIndex]
		if chunkAddr == 0 {
			return nil, formatError("chunk %d has a null address", chunkIndex)
		}
		chunk, cached := chunkCache[chunkAddr]
		if !cached {
			chunk, err = p.readAddressArray(chunkAddr)
			if err != nil {
				return nil, err
			}
			chunkCache[chunkAddr] = chunk
		}
		if int64(len(chunk)) != int64(chunkSize) {
			return nil, formatError(
				"chunk %d has %d slots; expected %d", chunkIndex, len(chunk), chunkSize)
		}
		slots = append(slots, chunk[slotIndex])
	}
	return slots, nil
}

// directAddrs walks a Zg_i direct collection and returns its logical
// addresses (all verified nonnull).
func (p *Project) directAddrs(addr int64) ([]int64, error) {
	resolved, err := p.resolve(addr)
	if err != nil {
		return nil, err
	}
	obj := NewBurpProject_DirectCollection(resolved)
	err = p.readAt(resolved, func() error { return obj.Read(p.io, nil, p.Root) })
	if err != nil {
		return nil, err
	}
	size, okSize, err := p.i32OfE(obj.Size())
	if err != nil {
		return nil, err
	}
	backing, okBacking, err := p.addrOfE(obj.BackingAddr())
	if err != nil {
		return nil, err
	}
	if !okSize || !okBacking {
		return nil, formatError("direct collection is missing a required field")
	}
	if size < 0 {
		return nil, formatError("negative direct collection size: %d", size)
	}
	addresses, err := p.readAddressArray(backing)
	if err != nil {
		return nil, err
	}
	if size > int32(len(addresses)) {
		return nil, formatError(
			"direct collection size %d exceeds address capacity %d", size, len(addresses))
	}
	logical := addresses[:size]
	for _, a := range logical {
		if a == 0 {
			return nil, formatError("direct collection contains a null logical address")
		}
	}
	return logical, nil
}

// ----------------------------------------------------------------- roots --

// ProjectRoot resolves and returns the typed project root.
func (p *Project) ProjectRoot() (*BurpProject_ProjectRoot, error) {
	addr, err := p.resolve(p.Root.Header.ProjectRoot)
	if err != nil {
		return nil, err
	}
	obj := NewBurpProject_ProjectRoot(addr)
	err = p.readAt(addr, func() error { return obj.Read(p.io, nil, p.Root) })
	return obj, err
}

// Metadata mirrors prub's inspect_project_metadata.
func (p *Project) Metadata() (*Metadata, error) {
	h := p.Root.Header
	root, err := p.ProjectRoot()
	if err != nil {
		return nil, err
	}
	out := &Metadata{
		SchemaFloor:            h.SchemaFloor,
		SchemaCurrent:          h.SchemaCurrent,
		HeaderRandomIdentifier: h.RandomIdentifier,
	}
	if installID, ok, err := p.addrOfE(root.InstallId()); err != nil {
		return nil, err
	} else if ok {
		v, err := p.immutableString(installID)
		if err != nil {
			return nil, err
		}
		out.InstallationID = &v
	}
	if nameAddr, ok, err := p.addrOfE(root.ProjectName()); err != nil {
		return nil, err
	} else if ok {
		v, err := p.immutableString(nameAddr)
		if err != nil {
			return nil, err
		}
		out.ProjectName = &v
	}
	if identAddr, ok, err := p.addrOfE(root.ProjectIdentifier()); err != nil {
		return nil, err
	} else if ok {
		v, err := p.immutableString(identAddr)
		if err != nil {
			return nil, err
		}
		out.ProjectIdentifier = &v
	}
	return out, nil
}

// ------------------------------------------------------------ JSON types --

// Metadata mirrors prub's metadata JSON shape.
type Metadata struct {
	SchemaFloor            uint16  `json:"schema_floor"`
	SchemaCurrent          uint16  `json:"schema_current"`
	HeaderRandomIdentifier uint32  `json:"header_random_identifier"`
	InstallationID         *string `json:"installation_id"`
	ProjectName            *string `json:"project_name"`
	ProjectIdentifier      *string `json:"project_identifier"`
}

// ByteVariant reports one raw byte variant of a Proxy history item.
type ByteVariant struct {
	Address *int64 `json:"address"`
	Length  *int32 `json:"length,omitempty"`
}

// RecordRef reports one raw request/response byte record.
type RecordRef struct {
	Address *int64 `json:"address"`
	Length  *int32 `json:"length,omitempty"`
}

func (p *Project) byteVariant(addr int64, ok bool) (*ByteVariant, error) {
	if !ok {
		return &ByteVariant{}, nil
	}
	rec, err := p.ReadRecord(addr)
	if err != nil {
		return nil, err
	}
	a := addr
	l := rec.LogicalLength
	return &ByteVariant{Address: &a, Length: &l}, nil
}

func (p *Project) recordRef(addr int64, ok bool) (RecordRef, error) {
	if !ok {
		return RecordRef{}, nil
	}
	rec, err := p.ReadRecord(addr)
	if err != nil {
		return RecordRef{}, err
	}
	a := addr
	l := rec.LogicalLength
	return RecordRef{Address: &a, Length: &l}, nil
}

// ProxyItem is one Proxy history entry view.
type ProxyItem struct {
	Address      int64                   `json:"address"`
	TypeID       uint8                   `json:"type_id"`
	Subtype      uint8                   `json:"subtype"`
	ByteVariants map[string]*ByteVariant `json:"byte_variants"`
}

// ProxyCollection is one chunked Proxy history view.
type ProxyCollection struct {
	FieldID int         `json:"field_id"`
	Address int64       `json:"address"`
	Items   []ProxyItem `json:"items"`
}

// ProxyInfo mirrors prub's inspect_proxy_items JSON shape.
type ProxyInfo struct {
	RootAddress int64             `json:"root_address"`
	Collections []ProxyCollection `json:"collections"`
}

// Proxy mirrors prub's inspect_proxy_items.
func (p *Project) Proxy() (*ProxyInfo, error) {
	root, err := p.ProjectRoot()
	if err != nil {
		return nil, err
	}
	proxyAddr, ok, err := p.addrOfE(root.ProxyRootAddr())
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, formatError("project root has no Proxy root address")
	}
	proxyResolved, err := p.resolve(proxyAddr)
	if err != nil {
		return nil, err
	}
	proxy := NewBurpProject_ProxyRoot(proxyResolved)
	err = p.readAt(proxyResolved, func() error { return proxy.Read(p.io, nil, p.Root) })
	if err != nil {
		return nil, err
	}

	out := &ProxyInfo{RootAddress: proxyResolved, Collections: []ProxyCollection{}}
	historyFinders := []func() (*BurpProject_FindAddr, error){proxy.HistoryAllAddr, proxy.HistoryUniqueAddr}
	for fieldID, getFinder := range historyFinders {
		finder, err := getFinder()
		if err != nil {
			return nil, err
		}
		collAddr, ok, err := p.addrOfE(finder, nil)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, formatError("Proxy root has no HTTP collection in field %d", fieldID)
		}
		collection := ProxyCollection{FieldID: fieldID, Address: collAddr, Items: []ProxyItem{}}
		slots, err := p.chunkedSlots(collAddr)
		if err != nil {
			return nil, err
		}
		for _, slot := range slots {
			if slot == 0 {
				return nil, formatError("proxy history item address is null")
			}
			resolved, err := p.resolveCompact(slot)
			if err != nil {
				return nil, err
			}
			item := NewBurpProject_ProxyItem(resolved.addr)
			err = p.readAt(resolved.addr, func() error { return item.Read(p.io, nil, p.Root) })
			if err != nil {
				return nil, err
			}
			variants := make(map[string]*ByteVariant)
			for _, id := range []int{15, 16, 17, 18, 19, 20} {
				finder, ferr := proxyItemVariant(item, id)
				addr, ok, err := p.addrOfE(finder, ferr)
				if err != nil {
					return nil, err
				}
				variant, err := p.byteVariant(addr, ok)
				if err != nil {
					return nil, err
				}
				variants[fmt.Sprintf("%d", id)] = variant
			}
			collection.Items = append(collection.Items, ProxyItem{
				Address:      resolved.addr,
				TypeID:       resolved.typeID,
				Subtype:      resolved.subtype,
				ByteVariants: variants,
			})
		}
		out.Collections = append(out.Collections, collection)
	}
	return out, nil
}

// proxyItemVariant returns the finder for one Proxy item byte-variant field.
func proxyItemVariant(item *BurpProject_ProxyItem, id int) (*BurpProject_FindAddr, error) {
	switch id {
	case 15:
		return item.RequestAddr()
	case 16:
		return item.RequestAlt1Addr()
	case 17:
		return item.RequestAlt2Addr()
	case 18:
		return item.ResponseAddr()
	case 19:
		return item.ResponseAlt1Addr()
	case 20:
		return item.ResponseAlt2Addr()
	}
	return nil, nil
}

// RepeaterPair is one Repeater request/response exchange.
type RepeaterPair struct {
	Address  int64     `json:"address"`
	Request  RecordRef `json:"request"`
	Response RecordRef `json:"response"`
}

// RepeaterTab is one Repeater tab.
type RepeaterTab struct {
	Address               int64          `json:"address"`
	TypeID                uint8          `json:"type_id"`
	Caption               *string        `json:"caption"`
	GroupAddress          *int64         `json:"group_address"`
	UUID                  *string        `json:"uuid"`
	CurrentRequestAddress *int64         `json:"current_request_address"`
	Pairs                 []RepeaterPair `json:"pairs"`
}

// RepeaterGroup is one Repeater tab group.
type RepeaterGroup struct {
	Address   int64   `json:"address"`
	Name      *string `json:"name"`
	ColorID   *uint8  `json:"color_id"`
	ColorEnum *string `json:"color_enum"`
	Expanded  *bool   `json:"expanded"`
	Index     *int32  `json:"index"`
	UUID      *string `json:"uuid"`
}

// RepeaterInfo mirrors prub's inspect_repeater_items JSON shape.
type RepeaterInfo struct {
	RootAddress            int64           `json:"root_address"`
	TabCollectionAddress   *int64          `json:"tab_collection_address"`
	GroupCollectionAddress *int64          `json:"group_collection_address"`
	Tabs                   []RepeaterTab   `json:"tabs"`
	Groups                 []RepeaterGroup `json:"groups"`
}

// Repeater mirrors prub's inspect_repeater_items.
func (p *Project) Repeater() (*RepeaterInfo, error) {
	root, err := p.ProjectRoot()
	if err != nil {
		return nil, err
	}
	repeaterAddr, ok, err := p.addrOfE(root.RepeaterRootAddr())
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, formatError("project root has no Repeater root address")
	}
	repeaterResolved, err := p.resolve(repeaterAddr)
	if err != nil {
		return nil, err
	}
	repeater := NewBurpProject_RepeaterRoot(repeaterResolved)
	err = p.readAt(repeaterResolved, func() error { return repeater.Read(p.io, nil, p.Root) })
	if err != nil {
		return nil, err
	}

	out := &RepeaterInfo{RootAddress: repeaterResolved, Tabs: []RepeaterTab{}, Groups: []RepeaterGroup{}}

	tabsAddr, okTabs, err := p.addrOfE(repeater.TabsAddr())
	if err != nil {
		return nil, err
	}
	groupsAddr, okGroups, err := p.addrOfE(repeater.GroupsAddr())
	if err != nil {
		return nil, err
	}
	if !okTabs || !okGroups {
		return nil, formatError("Repeater root is missing a required collection")
	}
	out.TabCollectionAddress = &tabsAddr
	out.GroupCollectionAddress = &groupsAddr

	groupAddrs, err := p.directAddrs(groupsAddr)
	if err != nil {
		return nil, err
	}
	for _, groupAddr := range groupAddrs {
		resolved, err := p.resolveCompact(groupAddr)
		if err != nil {
			return nil, err
		}
		group := NewBurpProject_RepeaterGroup(resolved.addr)
		err = p.readAt(resolved.addr, func() error { return group.Read(p.io, nil, p.Root) })
		if err != nil {
			return nil, err
		}
		entry := RepeaterGroup{Address: resolved.addr}
		if nameAddr, ok, err := p.addrOfE(group.NameAddr()); err != nil {
			return nil, err
		} else if ok {
			name, err := p.immutableString(nameAddr)
			if err != nil {
				return nil, err
			}
			entry.Name = &name
		}
		if color, ok, err := p.u8OfE(group.ColorId()); err != nil {
			return nil, err
		} else if ok {
			entry.ColorID = &color
			if color == 7 {
				enum := "GROUP_0"
				entry.ColorEnum = &enum
			}
		}
		if expanded, ok, err := p.u8OfE(group.Expanded()); err != nil {
			return nil, err
		} else if ok {
			v := expanded != 0
			entry.Expanded = &v
		}
		if index, ok, err := p.i32OfE(group.Index()); err != nil {
			return nil, err
		} else if ok {
			entry.Index = &index
		}
		if uuidAddr, ok, err := p.addrOfE(group.UuidAddr()); err != nil {
			return nil, err
		} else if ok {
			u, err := p.uuidString(uuidAddr)
			if err != nil {
				return nil, err
			}
			entry.UUID = &u
		}
		out.Groups = append(out.Groups, entry)
	}

	tabAddrs, err := p.directAddrs(tabsAddr)
	if err != nil {
		return nil, err
	}
	for _, tabAddr := range tabAddrs {
		resolved, err := p.resolveCompact(tabAddr)
		if err != nil {
			return nil, err
		}
		tab := NewBurpProject_RepeaterTab(resolved.addr)
		err = p.readAt(resolved.addr, func() error { return tab.Read(p.io, nil, p.Root) })
		if err != nil {
			return nil, err
		}
		entry := RepeaterTab{Address: resolved.addr, TypeID: resolved.typeID, Pairs: []RepeaterPair{}}
		if captionAddr, ok, err := p.addrOfE(tab.CaptionAddr()); err != nil {
			return nil, err
		} else if ok {
			caption, err := p.mutableString(captionAddr)
			if err != nil {
				return nil, err
			}
			entry.Caption = &caption
		}
		if groupAddr, ok, err := p.addrOfE(tab.GroupAddr()); err != nil {
			return nil, err
		} else if ok {
			entry.GroupAddress = &groupAddr
		}
		if uuidAddr, ok, err := p.addrOfE(tab.UuidAddr()); err != nil {
			return nil, err
		} else if ok {
			u, err := p.uuidString(uuidAddr)
			if err != nil {
				return nil, err
			}
			entry.UUID = &u
		}
		if curAddr, ok, err := p.addrOfE(tab.CurrentRequestAddr()); err != nil {
			return nil, err
		} else if ok {
			entry.CurrentRequestAddress = &curAddr
		}
		if pairsAddr, ok, err := p.addrOfE(tab.PairsAddr()); err != nil {
			return nil, err
		} else if ok {
			pairAddrs, err := p.directAddrs(pairsAddr)
			if err != nil {
				return nil, err
			}
			for _, pairAddr := range pairAddrs {
				resolved, err := p.resolveCompact(pairAddr)
				if err != nil {
					return nil, err
				}
				pair := NewBurpProject_RepeaterPair(resolved.addr)
				err = p.readAt(resolved.addr, func() error { return pair.Read(p.io, nil, p.Root) })
				if err != nil {
					return nil, err
				}
				pairEntry := RepeaterPair{Address: resolved.addr}
				if reqAddr, ok, err := p.addrOfE(pair.RequestAddr()); err != nil {
					return nil, err
				} else if pairEntry.Request, err = p.recordRef(reqAddr, ok); err != nil {
					return nil, err
				}
				if respAddr, ok, err := p.addrOfE(pair.ResponseAddr()); err != nil {
					return nil, err
				} else if pairEntry.Response, err = p.recordRef(respAddr, ok); err != nil {
					return nil, err
				}
				entry.Pairs = append(entry.Pairs, pairEntry)
			}
		}
		out.Tabs = append(out.Tabs, entry)
	}
	return out, nil
}

// TargetNode is one Site Map identity-index entry with its hierarchy node.
type TargetNode struct {
	Bucket         int       `json:"bucket"`
	Hash           int64     `json:"hash"`
	KeyAddress     int64     `json:"key_address"`
	Value          int64     `json:"value"`
	TypeID         uint8     `json:"type_id"`
	Subtype        uint8     `json:"subtype"`
	MessageAddress *int64    `json:"message_address"`
	Request        RecordRef `json:"request"`
	Response       RecordRef `json:"response"`
}

// TargetInfo mirrors prub's inspect_target_items JSON shape.
type TargetInfo struct {
	RootAddress          int64        `json:"root_address"`
	IdentityIndexAddress *int64       `json:"identity_index_address"`
	Nodes                []TargetNode `json:"nodes"`
}

// Target mirrors prub's inspect_target_items.
func (p *Project) Target() (*TargetInfo, error) {
	root, err := p.ProjectRoot()
	if err != nil {
		return nil, err
	}
	targetAddr, ok, err := p.addrOfE(root.TargetRootAddr())
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, formatError("project root has no Target root address")
	}
	targetResolved, err := p.resolve(targetAddr)
	if err != nil {
		return nil, err
	}
	target := NewBurpProject_TargetRoot(targetResolved)
	err = p.readAt(targetResolved, func() error { return target.Read(p.io, nil, p.Root) })
	if err != nil {
		return nil, err
	}

	out := &TargetInfo{RootAddress: targetResolved, Nodes: []TargetNode{}}
	idxAddr, okIdx, err := p.addrOfE(target.IdentityIndexAddr())
	if err != nil {
		return nil, err
	}
	if !okIdx {
		return nil, formatError("Target root has no identity index address")
	}
	out.IdentityIndexAddress = &idxAddr

	idxResolved, err := p.resolve(idxAddr)
	if err != nil {
		return nil, err
	}
	idx := NewBurpProject_IdentityIndex(idxResolved)
	err = p.readAt(idxResolved, func() error { return idx.Read(p.io, nil, p.Root) })
	if err != nil {
		return nil, err
	}
	expected, okExpected, err := p.i32OfE(idx.ExpectedSize())
	if err != nil {
		return nil, err
	}
	bucketsAddr, okBuckets, err := p.addrOfE(idx.BucketsAddr())
	if err != nil {
		return nil, err
	}
	if !okExpected || !okBuckets {
		return nil, formatError("identity index is missing a required field")
	}
	if expected < 0 {
		return nil, formatError("negative identity index size: %d", expected)
	}

	bucketSlots, err := p.chunkedSlots(bucketsAddr)
	if err != nil {
		return nil, err
	}
	count := 0
	for bucketIndex, bucketAddr := range bucketSlots {
		if bucketAddr == 0 {
			continue
		}
		resolved, err := p.resolveCompact(bucketAddr)
		if err != nil {
			return nil, err
		}
		bucket := NewBurpProject_Bucket(resolved.addr)
		err = p.readAt(resolved.addr, func() error { return bucket.Read(p.io, nil, p.Root) })
		if err != nil {
			return nil, err
		}
		bucketSize, okSize, err := p.i32OfE(bucket.Size())
		if err != nil {
			return nil, err
		}
		tuplesAddr, okTuples, err := p.addrOfE(bucket.TuplesAddr())
		if err != nil {
			return nil, err
		}
		if !okSize || !okTuples {
			return nil, formatError("bucket %d is missing a field", bucketIndex)
		}
		if bucketSize < 0 {
			return nil, formatError("negative bucket size: %d", bucketSize)
		}
		tuples, err := p.ReadBucketTuples(tuplesAddr)
		if err != nil {
			return nil, err
		}
		if bucketSize > int32(len(tuples)) {
			return nil, formatError(
				"bucket size %d exceeds tuple capacity %d", bucketSize, len(tuples))
		}
		for _, tuple := range tuples[:bucketSize] {
			if tuple.KeyAddress == 0 {
				continue
			}
			nodeResolved, err := p.resolveCompact(tuple.KeyAddress)
			if err != nil {
				return nil, err
			}
			node := NewBurpProject_TargetNode(nodeResolved.addr)
			err = p.readAt(nodeResolved.addr, func() error { return node.Read(p.io, nil, p.Root) })
			if err != nil {
				return nil, err
			}
			entry := TargetNode{
				Bucket:     bucketIndex,
				Hash:       tuple.Hash,
				KeyAddress: tuple.KeyAddress,
				Value:      tuple.Value,
				TypeID:     nodeResolved.typeID,
				Subtype:    nodeResolved.subtype,
			}
			if msgAddr, ok, err := p.addrOfE(node.MessageAddr()); err != nil {
				return nil, err
			} else if ok {
				entry.MessageAddress = &msgAddr
				msgResolved, err := p.resolve(msgAddr)
				if err != nil {
					return nil, err
				}
				msg := NewBurpProject_SiteMessage(msgResolved)
				err = p.readAt(msgResolved, func() error { return msg.Read(p.io, nil, p.Root) })
				if err != nil {
					return nil, err
				}
				if reqAddr, ok, err := p.addrOfE(msg.RequestAddr()); err != nil {
					return nil, err
				} else if entry.Request, err = p.recordRef(reqAddr, ok); err != nil {
					return nil, err
				}
				if respAddr, ok, err := p.addrOfE(msg.ResponseAddr()); err != nil {
					return nil, err
				} else if entry.Response, err = p.recordRef(respAddr, ok); err != nil {
					return nil, err
				}
			}
			out.Nodes = append(out.Nodes, entry)
			count++
		}
	}
	if count != int(expected) {
		return nil, formatError(
			"identity index reports %d entries; decoded %d", expected, count)
	}
	return out, nil
}
