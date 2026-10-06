// Package fusefs exposes a Burp project as a read-only FUSE filesystem.
//
// The tree is described by a plain Node model (tree.go) that is built from a
// burpfile.Project and can be unit-tested headlessly; mount.go adapts it to
// github.com/hanwen/go-fuse/v2 (pure Go, no cgo).
//
// Provisional timestamp semantics (verified empirically against the
// controlled samples, see README): Proxy item Zp1u field 11 is the request
// time and field 30 the response time; Repeater pair Zx4g field 4 is the
// pair time; Site map message metadata Zfkk field 3 is the completion time.
// All are epoch milliseconds.
package fusefs

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	burpfile "burpfile"
)

// Kind distinguishes files from directories in the tree model.
type Kind int

const (
	// File is a regular file whose content is Node.Data.
	File Kind = iota
	// Dir is a directory whose content is Node.Children.
	Dir
)

// Node is one entry of the exposed tree. File payloads are slices of the
// project data (no copies); JSON files carry their own bytes.
type Node struct {
	Name     string
	Kind     Kind
	Data     []byte
	Time     time.Time
	Children []*Node

	Ino uint64

	// rootSize/rootInodes are filled on the root node for Statfs.
	rootSize   uint64
	rootInodes uint64
}

// Options controls tree construction.
type Options struct {
	// DefaultTime is used for files and directories that have no known
	// timestamp in the project format. Zero defaults to time.Now().
	DefaultTime time.Time
}

// BuildTree maps a parsed project onto the exposed filesystem layout:
//
//	/
//	├── header.json            storage header facts
//	├── metadata.json          project metadata (prub metadata shape)
//	├── proxy/0001/            one directory per unique history item
//	│   ├── info.json
//	│   ├── request            primary request bytes (Zp1u field 15)
//	│   ├── request.alt1       alternate request slot (field 16, if stored)
//	│   ├── response           primary response bytes (field 18)
//	│   └── response.alt1      alternate response slot (field 19, if stored)
//	├── repeater/tabs/001-<caption>/
//	│   ├── info.json
//	│   └── pair-0001/{request,response,info.json}
//	├── repeater/groups/001-<name>/info.json
//	└── target/sitemap/0001/{info.json,request,response}
//
// The alt1/alt2 files exist only when the corresponding byte-variant slot is
// populated; those slots are the storage location for modified/alternate
// request or response bytes (semantics provisional, see README).
func BuildTree(project *burpfile.Project, opts Options) (*Node, error) {
	if opts.DefaultTime.IsZero() {
		opts.DefaultTime = time.Now()
	}
	root := &Node{Name: "/", Kind: Dir, Time: opts.DefaultTime}

	root.Children = append(root.Children,
		fileNode("header.json", buildHeaderJSON(project), opts.DefaultTime),
		fileNode("metadata.json", buildMetadataJSON(project), opts.DefaultTime))

	proxy, err := buildProxyDir(project, opts)
	if err != nil {
		return nil, fmt.Errorf("proxy: %w", err)
	}
	repeater, err := buildRepeaterDir(project, opts)
	if err != nil {
		return nil, fmt.Errorf("repeater: %w", err)
	}
	target, err := buildTargetDir(project, opts)
	if err != nil {
		return nil, fmt.Errorf("target: %w", err)
	}
	root.Children = append(root.Children, proxy, repeater, target)

	total := assignInodes(root, 1) - 1
	root.rootInodes = total
	root.rootSize = fillRootSize(root, 0)
	return root, nil
}

func fillRootSize(node *Node, sum uint64) uint64 {
	if node.Kind == File {
		sum += uint64(len(node.Data))
	}
	for _, child := range node.Children {
		sum = fillRootSize(child, sum)
	}
	return sum
}

func fileNode(name string, data []byte, t time.Time) *Node {
	return &Node{Name: name, Kind: File, Data: data, Time: t}
}

func dirNode(name string, t time.Time, children ...*Node) *Node {
	return &Node{Name: name, Kind: Dir, Time: t, Children: children}
}

func assignInodes(node *Node, next uint64) uint64 {
	node.Ino = next
	next++
	for _, child := range node.Children {
		next = assignInodes(child, next)
	}
	return next
}

// ------------------------------------------------------------- metadata --

type headerInfo struct {
	AllocationCursor int64  `json:"allocation_cursor"`
	Compatibility    int32  `json:"compatibility"`
	FileSize         int64  `json:"file_size"`
	MetadataRoot     int64  `json:"metadata_root"`
	OuterVersion     int32  `json:"outer_version"`
	ProjectRoot      int64  `json:"project_root"`
	RandomIdentifier uint32 `json:"random_identifier"`
	SchemaCurrent    uint16 `json:"schema_current"`
	SchemaFloor      uint16 `json:"schema_floor"`
	SegmentSpan      int64  `json:"segment_span"`
}

func buildHeaderJSON(project *burpfile.Project) []byte {
	header := project.Header()
	data, err := json.MarshalIndent(headerInfo{
		AllocationCursor: header.AllocationCursor,
		Compatibility:    header.Compatibility,
		FileSize:         project.Size(),
		MetadataRoot:     header.MetadataRoot,
		OuterVersion:     header.OuterVersion,
		ProjectRoot:      header.ProjectRoot,
		RandomIdentifier: header.RandomIdentifier,
		SchemaCurrent:    header.SchemaCurrent,
		SchemaFloor:      header.SchemaFloor,
		SegmentSpan:      header.SegmentSpan,
	}, "", "  ")
	if err != nil {
		return []byte("{}")
	}
	return append(data, '\n')
}

func buildMetadataJSON(project *burpfile.Project) []byte {
	metadata, err := project.Metadata()
	if err != nil {
		return []byte("{}\n")
	}
	data, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return []byte("{}\n")
	}
	return append(data, '\n')
}

// --------------------------------------------------------------- proxy --

type proxyItemInfo struct {
	Address      int64                            `json:"address"`
	ByteVariants map[string]*burpfile.ByteVariant `json:"byte_variants"`
	RequestTime  string                           `json:"request_time,omitempty"`
	ResponseTime string                           `json:"response_time,omitempty"`
	Subtype      uint8                            `json:"subtype"`
	TypeID       uint8                            `json:"type_id"`
}

func buildProxyDir(project *burpfile.Project, opts Options) (*Node, error) {
	info, err := project.Proxy()
	if err != nil {
		return nil, err
	}
	proxy := dirNode("proxy", opts.DefaultTime)
	seen := make(map[int64]bool)
	index := 0
	for _, collection := range info.Collections {
		for _, item := range collection.Items {
			if seen[item.Address] {
				continue
			}
			seen[item.Address] = true
			index++
			node, err := buildProxyItem(project, item, index, opts)
			if err != nil {
				return nil, err
			}
			proxy.Children = append(proxy.Children, node)
		}
	}
	return proxy, nil
}

func buildProxyItem(project *burpfile.Project, item burpfile.ProxyItem, index int, opts Options) (*Node, error) {
	object, err := project.CompactObject(item.Address)
	if err != nil {
		return nil, err
	}
	requestMS, _, err := project.Int64Field(object, 11)
	if err != nil {
		return nil, err
	}
	responseMS, _, err := project.Int64Field(object, 30)
	if err != nil {
		return nil, err
	}
	requestTime := epochMS(requestMS, opts.DefaultTime)
	responseTime := epochMS(responseMS, requestTime)

	entry := dirNode(fmt.Sprintf("%04d", index), requestTime)
	payload := func(address *int64) []byte {
		if address == nil {
			return nil
		}
		record, err := project.ReadRecord(*address)
		if err != nil {
			return nil
		}
		return record.Payload
	}
	if data := payload(item.ByteVariants["15"].Address); data != nil {
		entry.Children = append(entry.Children, fileNode("request", data, requestTime))
	}
	for i, slot := range []string{"16", "17"} {
		variant := item.ByteVariants[slot]
		if variant == nil || variant.Address == nil {
			continue
		}
		if data := payload(variant.Address); data != nil {
			entry.Children = append(entry.Children,
				fileNode(fmt.Sprintf("request.alt%d", i+1), data, requestTime))
		}
	}
	if data := payload(item.ByteVariants["18"].Address); data != nil {
		entry.Children = append(entry.Children, fileNode("response", data, responseTime))
	}
	for i, slot := range []string{"19", "20"} {
		variant := item.ByteVariants[slot]
		if variant == nil || variant.Address == nil {
			continue
		}
		if data := payload(variant.Address); data != nil {
			entry.Children = append(entry.Children,
				fileNode(fmt.Sprintf("response.alt%d", i+1), data, responseTime))
		}
	}

	info := proxyItemInfo{
		Address:      item.Address,
		ByteVariants: item.ByteVariants,
		Subtype:      item.Subtype,
		TypeID:       item.TypeID,
	}
	if requestMS > 0 {
		info.RequestTime = formatTime(requestTime)
	}
	if responseMS > 0 {
		info.ResponseTime = formatTime(responseTime)
	}
	entry.Children = append(entry.Children,
		fileNode("info.json", marshalIndent(info), requestTime))
	return entry, nil
}

// ------------------------------------------------------------ repeater --

type tabInfo struct {
	Address               int64   `json:"address"`
	Caption               *string `json:"caption"`
	CurrentRequestAddress *int64  `json:"current_request_address"`
	GroupAddress          *int64  `json:"group_address"`
	PairCount             int     `json:"pair_count"`
	UUID                  *string `json:"uuid"`
}

type groupInfo struct {
	Address  int64   `json:"address"`
	ColorID  *uint8  `json:"color_id"`
	Expanded *bool   `json:"expanded"`
	Index    *int32  `json:"index"`
	Name     *string `json:"name"`
	UUID     *string `json:"uuid"`
}

type pairInfo struct {
	Address  int64              `json:"address"`
	Request  burpfile.RecordRef `json:"request"`
	Response burpfile.RecordRef `json:"response"`
	Time     string             `json:"time,omitempty"`
}

func buildRepeaterDir(project *burpfile.Project, opts Options) (*Node, error) {
	info, err := project.Repeater()
	if err != nil {
		return nil, err
	}
	repeater := dirNode("repeater", opts.DefaultTime)

	tabs := dirNode("tabs", opts.DefaultTime)
	for index, tab := range info.Tabs {
		caption := "(untitled tab)"
		if tab.Caption != nil {
			caption = *tab.Caption
		}
		entry := dirNode(fmt.Sprintf("%03d-%s", index+1, sanitizeName(caption)), opts.DefaultTime)
		tabInfoData := tabInfo{
			Address:               tab.Address,
			Caption:               tab.Caption,
			CurrentRequestAddress: tab.CurrentRequestAddress,
			GroupAddress:          tab.GroupAddress,
			PairCount:             len(tab.Pairs),
			UUID:                  tab.UUID,
		}
		entry.Children = append(entry.Children,
			fileNode("info.json", marshalIndent(tabInfoData), opts.DefaultTime))
		for pairIndex, pair := range tab.Pairs {
			pairTime := pairTime(project, pair.Address, opts.DefaultTime)
			pairDir := dirNode(fmt.Sprintf("pair-%04d", pairIndex+1), pairTime)
			if data := recordData(project, pair.Request.Address); data != nil {
				pairDir.Children = append(pairDir.Children, fileNode("request", data, pairTime))
			}
			if data := recordData(project, pair.Response.Address); data != nil {
				pairDir.Children = append(pairDir.Children, fileNode("response", data, pairTime))
			}
			info := pairInfo{
				Address:  pair.Address,
				Request:  pair.Request,
				Response: pair.Response,
			}
			info.Time = formatTime(pairTime)
			pairDir.Children = append(pairDir.Children,
				fileNode("info.json", marshalIndent(info), pairTime))
			entry.Children = append(entry.Children, pairDir)
		}
		tabs.Children = append(tabs.Children, entry)
	}

	groups := dirNode("groups", opts.DefaultTime)
	for index, group := range info.Groups {
		name := "(unnamed group)"
		if group.Name != nil {
			name = *group.Name
		}
		entry := dirNode(fmt.Sprintf("%03d-%s", index+1, sanitizeName(name)), opts.DefaultTime)
		entry.Children = append(entry.Children, fileNode("info.json",
			marshalIndent(groupInfo{
				Address:  group.Address,
				ColorID:  group.ColorID,
				Expanded: group.Expanded,
				Index:    group.Index,
				Name:     group.Name,
				UUID:     group.UUID,
			}), opts.DefaultTime))
		groups.Children = append(groups.Children, entry)
	}

	repeater.Children = []*Node{tabs, groups}
	return repeater, nil
}

func pairTime(project *burpfile.Project, address int64, fallback time.Time) time.Time {
	object, err := project.CompactObject(address)
	if err != nil {
		return fallback
	}
	ms, ok, err := project.Int64Field(object, 4)
	if err != nil || !ok || ms <= 0 {
		return fallback
	}
	return time.UnixMilli(ms)
}

// -------------------------------------------------------------- target --

type siteMapInfo struct {
	Address        int64              `json:"address"`
	Bucket         int                `json:"bucket"`
	Hash           int64              `json:"hash"`
	MessageAddress *int64             `json:"message_address"`
	Request        burpfile.RecordRef `json:"request"`
	Response       burpfile.RecordRef `json:"response"`
	Subtype        uint8              `json:"subtype"`
	Time           string             `json:"time,omitempty"`
	TypeID         uint8              `json:"type_id"`
	Value          int64              `json:"value"`
}

func buildTargetDir(project *burpfile.Project, opts Options) (*Node, error) {
	info, err := project.Target()
	if err != nil {
		return nil, err
	}
	sitemap := dirNode("sitemap", opts.DefaultTime)
	index := 0
	for _, node := range info.Nodes {
		if node.MessageAddress == nil {
			continue
		}
		if node.Request.Address == nil && node.Response.Address == nil {
			continue
		}
		index++
		completionTime := messageTime(project, *node.MessageAddress, opts.DefaultTime)
		entry := dirNode(fmt.Sprintf("%04d", index), completionTime)
		if data := recordData(project, node.Request.Address); data != nil {
			entry.Children = append(entry.Children, fileNode("request", data, completionTime))
		}
		if data := recordData(project, node.Response.Address); data != nil {
			entry.Children = append(entry.Children, fileNode("response", data, completionTime))
		}
		infoData := siteMapInfo{
			Address:        node.KeyAddress,
			Bucket:         node.Bucket,
			Hash:           node.Hash,
			MessageAddress: node.MessageAddress,
			Request:        node.Request,
			Response:       node.Response,
			Subtype:        node.Subtype,
			Time:           formatTime(completionTime),
			TypeID:         node.TypeID,
			Value:          node.Value,
		}
		entry.Children = append(entry.Children,
			fileNode("info.json", marshalIndent(infoData), completionTime))
		sitemap.Children = append(sitemap.Children, entry)
	}
	target := dirNode("target", opts.DefaultTime)
	target.Children = []*Node{sitemap}
	return target, nil
}

func messageTime(project *burpfile.Project, address int64, fallback time.Time) time.Time {
	object, err := project.CompactObject(address)
	if err != nil {
		return fallback
	}
	ms, ok, err := project.Int64Field(object, 3)
	if err != nil || !ok || ms <= 0 {
		return fallback
	}
	return time.UnixMilli(ms)
}

// -------------------------------------------------------------- helpers --

func recordData(project *burpfile.Project, address *int64) []byte {
	if address == nil {
		return nil
	}
	record, err := project.ReadRecord(*address)
	if err != nil {
		return nil
	}
	return record.Payload
}

func epochMS(ms int64, fallback time.Time) time.Time {
	if ms <= 0 {
		return fallback
	}
	return time.UnixMilli(ms)
}

func formatTime(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000Z07:00")
}

// sanitizeName makes a caption or group name safe for use as a directory
// name: non-printable characters and path separators become underscores.
func sanitizeName(name string) string {
	var b []byte
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '-', r == '_', r == '.', r == ' ':
			b = append(b, byte(r))
		default:
			b = append(b, '_')
		}
	}
	out := strings.TrimSpace(string(b))
	if out == "" {
		out = "unnamed"
	}
	if len(out) > 40 {
		out = out[:40]
	}
	return out
}

func marshalIndent(v any) []byte {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return []byte("{}\n")
	}
	return append(data, '\n')
}
