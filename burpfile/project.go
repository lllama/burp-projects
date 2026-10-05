// Package burpfile implements a read-only parser for Burp Suite project
// (.burp) save files. It is a direct port of the semantics verified in the
// prub Python reference (see ../prub/ai-docs/format-specification.md), valid
// for outer storage version 1 with schema 226/227.
//
// The file is an object heap: persisted references are signed 64-bit byte
// offsets into the file (0 = absent), and objects are located by chasing
// addresses rather than by sequential layout. The package is organised for
// reuse by higher-level applications (TUI, FUSE, web):
//
//   - project.go: outer header, validation, bounds-checked raw readers
//   - record.go:  variable byte records and fixed-width element arrays
//   - object.go:  compact objects, descriptor tables, forwarding resolution
//   - strings.go: UTF-16BE, immutable/mutable strings, UUIDs
//   - collections.go: chunked and direct address collections
//   - roots.go:   Metadata / Proxy / Repeater / Target walks
//   - json.go:    JSON view types (mirroring prub's output shapes)
//   - export.go:  unified HTTP message export
package burpfile

import (
	"encoding/binary"
	"fmt"
	"os"
)

// Outer header layout constants.
const (
	HeaderSize       = 72
	Magic            = 0x66858280
	MaxOuterVersion  = 1
	MaxCompatibility = -2142078604
	// MaxForwardDepth bounds forwarding-record chasing, matching prub.
	MaxForwardDepth = 16
)

// ProjectFormatError marks bytes that violate a verified format invariant.
type ProjectFormatError struct{ msg string }

func (e *ProjectFormatError) Error() string { return e.msg }

func formatError(format string, args ...any) error {
	return &ProjectFormatError{msg: fmt.Sprintf(format, args...)}
}

// UnsupportedProjectVersionError marks projects that require a newer reader.
type UnsupportedProjectVersionError struct{ msg string }

func (e *UnsupportedProjectVersionError) Error() string { return e.msg }

// Header is the decoded 72-byte outer header.
type Header struct {
	Magic            uint32
	OuterVersion     int32
	Compatibility    int32
	SchemaFloor      uint16
	SchemaCurrent    uint16
	RandomIdentifier uint32
	MetadataRoot     int64
	SegmentSpan      int64
	AllocationCursor int64
	ProjectRoot      int64
}

// Project is a parsed, read-only view of one .burp project file.
type Project struct {
	data   []byte
	header Header
}

// Open reads the project file into memory and validates the outer header.
// The whole file is held in memory; swap in an mmap-backed implementation of
// the same shape if very large projects become a concern.
func Open(path string) (*Project, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	p := &Project{data: data}
	if err := p.parseHeader(); err != nil {
		return nil, err
	}
	return p, nil
}

// Header returns the decoded outer header.
func (p *Project) Header() Header { return p.header }

// Size returns the total file size in bytes.
func (p *Project) Size() int64 { return int64(len(p.data)) }

// parseHeader mirrors prub.parser.parse_header, including its validations.
func (p *Project) parseHeader() error {
	raw, err := p.slice(0, HeaderSize)
	if err != nil {
		return formatError("project header requires %d bytes; got %d", HeaderSize, len(p.data))
	}
	h := Header{
		Magic:         binary.BigEndian.Uint32(raw[0:4]),
		OuterVersion:  int32(binary.BigEndian.Uint32(raw[4:8])),
		Compatibility: int32(binary.BigEndian.Uint32(raw[8:12])),
		SchemaFloor:   binary.BigEndian.Uint16(raw[12:14]),
		SchemaCurrent: binary.BigEndian.Uint16(raw[14:16]),
	}
	h.RandomIdentifier = binary.BigEndian.Uint32(raw[16:20])
	h.MetadataRoot = int64(binary.BigEndian.Uint64(raw[40:48]))
	h.SegmentSpan = int64(binary.BigEndian.Uint64(raw[48:56]))
	h.AllocationCursor = int64(binary.BigEndian.Uint64(raw[56:64]))
	h.ProjectRoot = int64(binary.BigEndian.Uint64(raw[64:72]))

	if h.Magic != Magic {
		return formatError("invalid project magic: %#08x", h.Magic)
	}
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
	if h.AllocationCursor > int64(len(p.data)) {
		return formatError(
			"allocation cursor %d exceeds available data %d", h.AllocationCursor, len(p.data))
	}
	p.header = h
	return nil
}

// ------------------------------------------------------- raw byte access --

// slice returns n bytes starting at off, bounds-checked against the file.
func (p *Project) slice(off int64, n int64) ([]byte, error) {
	if off < 0 || n < 0 || off > int64(len(p.data)) || n > int64(len(p.data))-off {
		return nil, formatError(
			"read of %d bytes at %d exceeds available data %d", n, off, len(p.data))
	}
	return p.data[off : off+n], nil
}

func (p *Project) u8at(off int64) (uint8, error) {
	b, err := p.slice(off, 1)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

func (p *Project) i16at(off int64) (int16, error) {
	b, err := p.slice(off, 2)
	if err != nil {
		return 0, err
	}
	return int16(binary.BigEndian.Uint16(b)), nil
}

func (p *Project) i32at(off int64) (int32, error) {
	b, err := p.slice(off, 4)
	if err != nil {
		return 0, err
	}
	return int32(binary.BigEndian.Uint32(b)), nil
}

func (p *Project) i64at(off int64) (int64, error) {
	b, err := p.slice(off, 8)
	if err != nil {
		return 0, err
	}
	return int64(binary.BigEndian.Uint64(b)), nil
}

func (p *Project) u64at(off int64) (uint64, error) {
	b, err := p.slice(off, 8)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(b), nil
}
