// Command burpdump dumps parsed Burp project data as JSON.
//
// Usage: burpdump <metadata|proxy|repeater|target|all|record> <file.burp> [addr]
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	burpfmt "burpfmt"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: burpdump <metadata|proxy|repeater|target|all|record> <file.burp> [addr]")
		os.Exit(2)
	}
	command, path := os.Args[1], os.Args[2]

	project, err := burpfmt.Open(path)
	if err != nil {
		fatal(err)
	}

	switch command {
	case "metadata":
		v, err := project.Metadata()
		check(err)
		emit(v)
	case "proxy":
		v, err := project.Proxy()
		check(err)
		emit(v)
	case "repeater":
		v, err := project.Repeater()
		check(err)
		emit(v)
	case "target":
		v, err := project.Target()
		check(err)
		emit(v)
	case "all":
		metadata, err := project.Metadata()
		check(err)
		proxy, err := project.Proxy()
		check(err)
		repeater, err := project.Repeater()
		check(err)
		target, err := project.Target()
		check(err)
		emit(map[string]interface{}{
			"metadata": metadata,
			"proxy":    proxy,
			"repeater": repeater,
			"target":   target,
		})
	case "record":
		if len(os.Args) != 4 {
			fatal(fmt.Errorf("record command requires an address argument"))
		}
		var addr int64
		if _, err := fmt.Sscan(os.Args[3], &addr); err != nil {
			fatal(err)
		}
		payload, err := project.RecordPayload(addr)
		if err != nil {
			fatal(err)
		}
		fmt.Println(hex.Dump(payload))
	default:
		fatal(fmt.Errorf("unknown command %q", command))
	}
}

func emit(v interface{}) {
	out, err := json.MarshalIndent(v, "", " ")
	if err != nil {
		fatal(err)
	}
	fmt.Println(string(out))
}

func check(err error) {
	if err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "burpdump:", err)
	os.Exit(1)
}
