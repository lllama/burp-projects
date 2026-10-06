// Command prub replicates the prub Python CLI: it inspects and exports HTTP
// messages from Burp Suite project files.
package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"github.com/urfave/cli/v3"

	burpfile "burpfile"
)

func main() {
	cmd := &cli.Command{
		Name:  "prub",
		Usage: "Export HTTP messages from Burp Suite project files to JSON.",
		Commands: []*cli.Command{
			{
				Name:      "metadata",
				Usage:     "show project metadata",
				ArgsUsage: "PROJECT",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					project, err := burpfile.Open(cmd.Args().Get(0))
					if err != nil {
						return err
					}
					output, err := project.Metadata()
					if err != nil {
						return err
					}
					return printJSON(output)
				},
			},
			{
				Name:      "inspect",
				Usage:     "inspect supported Burp data",
				ArgsUsage: "TOOL PROJECT",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					tool := cmd.Args().Get(0)
					project, err := burpfile.Open(cmd.Args().Get(1))
					if err != nil {
						return err
					}
					switch tool {
					case "proxy":
						output, err := project.Proxy()
						if err != nil {
							return err
						}
						return printJSON(output)
					case "repeater":
						output, err := project.Repeater()
						if err != nil {
							return err
						}
						return printJSON(output)
					case "target":
						output, err := project.Target()
						if err != nil {
							return err
						}
						return printJSON(output)
					default:
						return fmt.Errorf(
							"argument tool: invalid choice: %q (choose from 'proxy', 'repeater', 'target')",
							tool)
					}
				},
			},
			{
				Name:      "record",
				Usage:     "read one raw byte record",
				ArgsUsage: "PROJECT OFFSET",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					offset, err := strconv.ParseInt(cmd.Args().Get(1), 0, 64)
					if err != nil {
						return fmt.Errorf("argument offset: invalid value: %q", cmd.Args().Get(1))
					}
					project, err := burpfile.Open(cmd.Args().Get(0))
					if err != nil {
						return err
					}
					record, err := project.ReadRecord(offset)
					if err != nil {
						return err
					}
					return printJSON(struct {
						LogicalLength int32  `json:"logical_length"`
						Offset        int64  `json:"offset"`
						PayloadBase64 string `json:"payload_base64"`
						TotalSize     int32  `json:"total_size"`
					}{
						LogicalLength: record.LogicalLength,
						Offset:        record.Offset,
						PayloadBase64: base64.StdEncoding.EncodeToString(record.Payload),
						TotalSize:     record.TotalSize,
					})
				},
			},
			{
				Name:      "export",
				Usage:     "write unified JSON export",
				ArgsUsage: "PROJECT OUTPUT",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					project, err := burpfile.Open(cmd.Args().Get(0))
					if err != nil {
						return err
					}
					document, err := project.Export()
					if err != nil {
						return err
					}
					return writeJSONFile(document, cmd.Args().Get(1))
				},
			},
		},
	}
	if err := cmd.Run(context.Background(), os.Args); err != nil {
		fmt.Fprintln(os.Stderr, "prub:", err)
		os.Exit(1)
	}
}

// printJSON writes one JSON document to stdout with two-space indentation
// and sorted object keys, matching prub's
// json.dumps(output, indent=2, sort_keys=True).
func printJSON(v any) error {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(v); err != nil {
		return err
	}
	_, err := os.Stdout.Write(buf.Bytes())
	return err
}

// writeJSONFile writes one JSON document plus a trailing newline to path,
// matching prub.exporter.export_project.
func writeJSONFile(v any, path string) error {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(v); err != nil {
		return err
	}
	return os.WriteFile(path, buf.Bytes(), 0o644)
}
