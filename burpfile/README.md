# burpfile — custom Go parser for Burp project files

Read-only Go implementation of the Burp Suite `.burp` project format,
replacing the Kaitai-generated layer (`../go-burp`) with hand-written code
over a byte slice. Semantics are a direct port of the verified Python
reference (`../prub`).

Validation: the CLI is **byte-identical** to the prub Python CLI on both
controlled samples for every command — `metadata`, `inspect proxy|repeater|target`,
`record` (including a zero-length padding record and hex offsets), and
`export`.

## Layout

| File             | Purpose                                                              |
| ---------------- | -------------------------------------------------------------------- |
| `project.go`     | Outer header, validation, bounds-checked raw readers, error types    |
| `record.go`      | Variable byte records, address/tuple/UTF-16 element arrays           |
| `object.go`      | Compact objects, descriptor tables, forwarding resolution, field readers |
| `strings.go`     | Immutable (Zv1) / mutable chunked (Zvp) strings, two-long UUIDs      |
| `collections.go` | Chunked (Zwtw) and direct (Zg_i) address collections                 |
| `roots.go`       | Metadata / Proxy / Repeater / Target walks, identity index           |
| `json.go`        | JSON view types (fields alphabetically ordered to match `sort_keys`) |
| `export.go`      | Unified base64 HTTP message export (prub exporter port)              |
| `cmd/prub`       | urfave/cli command replicating the prub Python CLI                   |
| `cmd/prub-tui`   | Bubbletea v2 viewer: tool menu, content lists, metadata, raw detail  |

## Usage

```sh
go build -o prub ./cmd/prub
./prub metadata ../2026-09-23.burp
./prub inspect target ../2026-09-23.burp
./prub record ../2026-09-23.burp 0x6a07e     # decimal, 0x…, 0b…, 0o…
./prub export ../2026-09-23.burp out.json

# interactive viewer (Bubbletea v2)
CGO_ENABLED=0 go build -o prub-tui ./cmd/prub-tui
./prub-tui ../2026-09-23.burp
```

TUI key map: `↑/↓` or `j/k` move · `enter` open · `esc` back ·
`pgup/pgdn` page · `g/G` top/bottom (detail) · `q` quit.
Tools whose structures are not mapped yet (Intruder, Scope) appear in the
menu with an explanation instead of a list.

Library entry points for future TUI/FUSE/web consumers:

```go
project, err := burpfile.Open(path)
project.Header()                 // outer header values
project.ReadRecord(addr)         // raw byte record at an address
project.ResolveObject(addr)      // forwarding-resolved compact object
project.Metadata() / Proxy() / Repeater() / Target() / Export()
```

## Notes

- The whole file is read into memory (`os.ReadFile`); the API takes byte
  offsets, so swapping in an mmap-backed `Project` later is mechanical.
- Read-only by design: addresses, records, and objects are exposed for
  browsing; a future writer will need its own allocation/relocation layer.
- `go test ./...` runs sample-based smoke tests when the `.burp` fixtures are
  present (skipped-safe on absent files is not implemented — tests fail fast
  instead, which is what we want in this repo).
- `../go-burp` (Kaitai-based) is kept as an independent cross-check; both
  implementations agree on the full prub output surface.
