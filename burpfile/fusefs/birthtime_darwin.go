//go:build darwin

package fusefs

import (
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
)

// setBirthTime fills the macOS birth time (st_birthtime) of a getattr
// reply. The macFUSE wire layout of fuse.Attr carries the creation time in
// the Crtime_ fields; Finder and `stat -f %B` report them as "created".
func setBirthTime(out *fuse.AttrOut, t time.Time) {
	out.Crtime_ = uint64(t.Unix())
	out.Crtimensec_ = uint32(t.Nanosecond())
}
