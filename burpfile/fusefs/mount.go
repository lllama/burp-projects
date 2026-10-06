package fusefs

import (
	"context"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"

	burpfile "burpfile"
)

// Mount exposes the project at mountpoint and returns the running server.
// The filesystem is mounted read-only ("ro" mount option, 0444/0555 modes,
// and no write handlers are implemented).
func Mount(mountpoint string, project *burpfile.Project, opts Options, debug bool) (*fuse.Server, error) {
	root, err := BuildTree(project, opts)
	if err != nil {
		return nil, err
	}
	rootOps := &fsNode{spec: root}
	return fs.Mount(mountpoint, rootOps, &fs.Options{
		MountOptions: fuse.MountOptions{
			Options: []string{"ro"},
			FsName:  "prub",
			Name:    "prub-fuse",
			Debug:   debug,
		},
		OnAdd: func(ctx context.Context) {
			// Attach the whole static tree once the root inode exists.
			for _, child := range root.Children {
				attach(ctx, child, &rootOps.Inode)
			}
		},
	})
}

// fsNode adapts one tree Node to the go-fuse node API.
type fsNode struct {
	fs.Inode
	spec *Node
}

func (n *fsNode) Getattr(ctx context.Context, fh fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	if n.spec.Kind == Dir {
		out.Mode = syscall.S_IFDIR | 0555
		out.Size = 4096
		out.Nlink = 2
	} else {
		out.Mode = syscall.S_IFREG | 0444
		out.Size = uint64(len(n.spec.Data))
		out.Nlink = 1
	}
	t := n.spec.Time
	out.SetTimes(&t, &t, &t)
	setBirthTime(out, t)
	return fs.OK
}

func (n *fsNode) Open(ctx context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	return nil, 0, fs.OK
}

// Statfs reports filesystem statistics. macFUSE waits for an INIT *and* a
// STATFS reply before completing the mount, so a sane answer matters there;
// the generic bridge would answer zeroed-out values.
func (n *fsNode) Statfs(ctx context.Context, out *fuse.StatfsOut) syscall.Errno {
	const blockSize = 4096
	out.Bsize = blockSize
	out.Blocks = (n.spec.rootSize + blockSize - 1) / blockSize
	out.Bfree = 0 // read-only
	out.Bavail = 0
	out.Files = n.spec.rootInodes
	out.Ffree = 0
	out.NameLen = 255
	out.Frsize = blockSize
	return fs.OK
}

func (n *fsNode) Read(ctx context.Context, fh fs.FileHandle, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	data := n.spec.Data
	if off < 0 || off >= int64(len(data)) {
		return fuse.ReadResultData(nil), fs.OK
	}
	data = data[off:]
	if len(data) > len(dest) {
		data = data[:len(dest)]
	}
	return fuse.ReadResultData(data), fs.OK
}

// attach recursively converts tree Nodes into inodes under parent.
func attach(ctx context.Context, spec *Node, parent *fs.Inode) {
	mode := uint32(syscall.S_IFREG)
	if spec.Kind == Dir {
		mode = syscall.S_IFDIR
	}
	inode := parent.NewInode(ctx, &fsNode{spec: spec}, fs.StableAttr{
		Ino:  spec.Ino,
		Mode: mode,
	})
	parent.AddChild(spec.Name, inode, false)
	for _, child := range spec.Children {
		attach(ctx, child, inode)
	}
}
