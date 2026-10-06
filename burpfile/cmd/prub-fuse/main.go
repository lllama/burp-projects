// Command prub-fuse mounts a Burp Suite project file as a read-only
// filesystem: browse tools as directories and request/response bytes as
// file contents (see burpfile/fusefs for the layout).
package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	burpfile "burpfile"
	"burpfile/fusefs"
)

func main() {
	debug := false
	args := os.Args[1:]
	if len(args) > 0 && args[0] == "--debug" {
		debug = true
		args = args[1:]
	}
	if len(args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: prub-fuse [--debug] <project.burp> <mountpoint>")
		os.Exit(2)
	}
	projectPath, mountpoint := args[0], args[1]

	project, err := burpfile.Open(projectPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "prub-fuse:", err)
		os.Exit(1)
	}
	metadata, err := project.Metadata()
	if err != nil {
		fmt.Fprintln(os.Stderr, "prub-fuse:", err)
		os.Exit(1)
	}
	name := "(unknown)"
	if metadata.ProjectName != nil {
		name = *metadata.ProjectName
	}

	server, err := fusefs.Mount(mountpoint, project, fusefs.Options{}, debug)
	if err != nil {
		fmt.Fprintln(os.Stderr, "prub-fuse:", err)
		os.Exit(1)
	}
	fmt.Printf("mounted %s (%s) at %s — read-only; unmount with Ctrl-C or `fusermount -u %s`\n",
		projectPath, name, mountpoint, mountpoint)

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-signals
		server.Unmount()
	}()

	server.Wait()
}
