//go:build !darwin

package fusefs

import (
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
)

// setBirthTime is a no-op outside macOS: the Linux/FreeBSD FUSE attribute
// wire layouts carry no birth time (Linux exposes creation time only via
// statx, which the kernel derives elsewhere).
func setBirthTime(out *fuse.AttrOut, t time.Time) {}
