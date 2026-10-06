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
| `cmd/prub-tui`   | Bubbletea v2 + Lipgloss v2 viewer: tool menu, lists, metadata, detail |
| `cmd/prub-fuse`  | read-only FUSE mount of the project (hanwen/go-fuse v2, pure Go)     |
| `fusefs/`        | FUSE tree model (headless-testable) + mount adapter                  |

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

# read-only FUSE mount (requires /dev/fuse and fusermount3)
CGO_ENABLED=0 go build -o prub-fuse ./cmd/prub-fuse
./prub-fuse ../2026-09-23.burp /mnt/burp
fusermount -u /mnt/burp
```

TUI key map: `↑/↓` or `j/k` move · `enter` open · `esc` back ·
`pgup/pgdn` page · `g/G` top/bottom (detail) · `q` quit.
Tools whose structures are not mapped yet (Intruder, Scope) appear in the
menu with an explanation instead of a list.

## FUSE layout

`prub-fuse` exposes the object tree as a read-only filesystem
(`fusefs.BuildTree` builds a plain `Node` model that is unit-tested
headlessly; `fusefs.Mount` adapts it to go-fuse):

    /mnt/burp
    ├── header.json                  storage header facts
    ├── metadata.json                project metadata (prub metadata shape)
    ├── proxy/0001/                  one directory per unique history item
    │   ├── info.json                addresses, type ids, all byte variants
    │   ├── request                  raw request bytes (Zp1u field 15)
    │   ├── response                 raw response bytes (field 18)
    │   ├── request.alt1/.alt2       alternate request slots (16/17, if stored)
    │   └── response.alt1/.alt2      alternate response slots (19/20, if stored)
    ├── repeater/tabs/001-<caption>/
    │   ├── info.json                caption, uuid, group, pair count
    │   └── pair-0001/{request,response,info.json}
    ├── repeater/groups/001-<name>/info.json
    └── target/sitemap/0001/{info.json,request,response}

Modified requests: Burp stores up to three request and three response byte
variants per Proxy item. The primary slot is exposed as `request`/`response`;
the two alternate slots appear as `.alt1`/`.alt2` only when populated. A
sample containing an actually modified request has not been analysed yet, so
the slots are named neutrally; once one is captured, the mapping (original vs
modified) can be verified and the names adjusted — `info.json` already
exposes every variant's address and length for cross-checking.

File timestamps come from the project format and are provisional (verified
empirically on the controlled samples, not yet confirmed against decompiled
writer code):

| File                       | Source field                  |
| -------------------------- | ----------------------------- |
| `proxy/*/request` + dir    | Zp1u field 11, epoch-ms       |
| `proxy/*/response`         | Zp1u field 30, epoch-ms       |
| `repeater/*/pair-*` + dir  | Zx4g field 4, epoch-ms        |
| `target/sitemap/*` + dir   | Zfkk field 3, epoch-ms        |
| everything else            | mount time (`Options.DefaultTime`) |

Across all 28 sample items the field-11/30 values are epoch milliseconds on
the project's date, monotonic through history order with response ≥ request,
which is what a request/response completion time pair should look like.

## macOS (macFUSE)

The mount code is cross-platform and the binary cross-compiles for darwin
arm64 and amd64 (`GOOS=darwin CGO_ENABLED=0 go build -o prub-fuse
./cmd/prub-fuse`). macFUSE specifics that were verified against the
go-fuse v2.11 mount path (`fuse/mount_darwin.go`):

- macFUSE 4.x is looked up at
  `/Library/Filesystems/macfuse.fs/Contents/Resources/mount_macfuse`
  (older osxfuse.fs path also supported). Install macFUSE first and approve
  its system extension; that is a macFUSE prerequisite, unrelated to the
  binary's linking (CGO stays off).
- Mount options (including our `ro`) are forwarded as `-o ro` to the
  mount helper, so the kernel enforces read-only on macOS too.
- macFUSE's mount helper does not exit until the filesystem answers INIT
  *and* STATFS; go-fuse answers a zeroed STATFS by default. `fusefs` roots
  implement `Statfs` reporting real block/inode counts, which also gives
  Finder sane "free space" values.
- File times include the macOS birth time (`st_birthtime`, shown as
  "Created" in Finder): `fusefs/birthtime_darwin.go` fills `Attr.Crtime_`
  with the same timestamp as mtime (request/response time where known).
  Linux keeps a no-op shim.

What could not be verified here: an actual mount (this container has no
macOS). On a Mac:

    ./prub-fuse project.burp /mnt/burp     # mountpoint must exist, not be under /System
    umount /mnt/burp                       # or `diskutil unmount /mnt/burp`, or Ctrl-C

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
