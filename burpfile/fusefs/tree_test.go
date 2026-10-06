package fusefs

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"syscall"

	burpfile "burpfile"
)

const (
	emptySample = "../../2026-09-23-empty.burp"
	fullSample  = "../../2026-09-23.burp"
)

func build(t *testing.T, path string, opts Options) *Node {
	t.Helper()
	project, err := burpfile.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	root, err := BuildTree(project, opts)
	if err != nil {
		t.Fatalf("build %s: %v", path, err)
	}
	return root
}

func child(t *testing.T, node *Node, name string) *Node {
	t.Helper()
	for _, c := range node.Children {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("node %q has no child %q (children: %v)", node.Name, name, names(node))
	return nil
}

func names(node *Node) []string {
	out := make([]string, len(node.Children))
	for i, c := range node.Children {
		out[i] = c.Name
	}
	return out
}

var fixedTime = time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)

func TestTreeLayoutFull(t *testing.T) {
	root := build(t, fullSample, Options{DefaultTime: fixedTime})
	for _, want := range []string{"header.json", "metadata.json", "proxy", "repeater", "target"} {
		child(t, root, want)
	}

	items := child(t, child(t, root, "proxy"), "0001")
	if got := names(items); len(got) != 3 || got[0] != "request" || got[1] != "response" || got[2] != "info.json" {
		t.Errorf("proxy/0001 children: %v", got)
	}
	request := child(t, items, "request")
	if !startsWith(request.Data, "GET / HTTP/1.1\r\n") {
		t.Errorf("request content wrong: %q", request.Data[:20])
	}
	response := child(t, items, "response")
	if len(response.Data) == 0 {
		t.Errorf("response content empty")
	}

	// Timestamps: Zp1u field 11/30 epoch-ms, verified empirically.
	wantReq := time.UnixMilli(1790199057733)
	if !request.Time.Equal(wantReq) {
		t.Errorf("request time = %v, want %v", request.Time, wantReq)
	}
	wantResp := time.UnixMilli(1790199058076)
	if !response.Time.Equal(wantResp) {
		t.Errorf("response time = %v, want %v", response.Time, wantResp)
	}

	// info.json carries the full variant map.
	var info proxyItemInfo
	if err := json.Unmarshal(child(t, items, "info.json").Data, &info); err != nil {
		t.Fatalf("info.json: %v", err)
	}
	if info.Address != 454818 || info.RequestTime != "2026-09-23T21:30:57.733Z" {
		t.Errorf("info.json content: %+v", info)
	}
	for _, slot := range []string{"15", "16", "17", "18", "19", "20"} {
		if info.ByteVariants[slot] == nil {
			t.Errorf("info.json missing variant %s", slot)
		}
	}

	repeater := child(t, root, "repeater")
	tab := child(t, child(t, repeater, "tabs"), "001-1")
	pair := child(t, tab, "pair-0001")
	if !startsWith(child(t, pair, "request").Data, "GET / HTTP/1.1\r\n") {
		t.Errorf("repeater pair request content wrong")
	}
	wantPair := time.UnixMilli(1790199148617)
	if got := child(t, pair, "request").Time; !got.Equal(wantPair) {
		t.Errorf("pair time = %v, want %v", got, wantPair)
	}

	sitemap := child(t, child(t, child(t, root, "target"), "sitemap"), "0001")
	if !startsWith(child(t, sitemap, "request").Data, "GET / HTTP/1.1\r\n") {
		t.Errorf("sitemap request content wrong")
	}

	// inode numbers are unique and positive
	seen := map[uint64]bool{}
	walk(root, func(n *Node) {
		if n.Ino == 0 || seen[n.Ino] {
			t.Errorf("inode %d repeated or unset", n.Ino)
		}
		seen[n.Ino] = true
	})
}

func TestTreeLayoutEmpty(t *testing.T) {
	root := build(t, emptySample, Options{DefaultTime: fixedTime})
	proxy := child(t, root, "proxy")
	if len(proxy.Children) != 0 {
		t.Errorf("expected empty proxy dir, got %v", names(proxy))
	}

	tab := child(t, child(t, child(t, root, "repeater"), "tabs"), "001-1")
	tabInfoNode := child(t, tab, "info.json")
	if len(tab.Children) != 1 {
		t.Errorf("unsent tab should hold only info.json, got %v", names(tab))
	}
	var tabData tabInfo
	if err := json.Unmarshal(tabInfoNode.Data, &tabData); err != nil {
		t.Fatalf("tab info.json: %v", err)
	}
	if tabData.Caption == nil || *tabData.Caption != "1" || tabData.PairCount != 0 {
		t.Errorf("tab info content: %+v", tabData)
	}
	if !tabInfoNode.Time.Equal(fixedTime) {
		t.Errorf("unsent tab time should be the default: %v", tabInfoNode.Time)
	}

	sitemap := child(t, child(t, root, "target"), "sitemap")
	if got := len(sitemap.Children); got != 0 {
		t.Errorf("expected empty sitemap, got %d", got)
	}
}

func TestGroupNamesSanitized(t *testing.T) {
	// The full sample has no groups; exercise sanitizeName directly.
	if got := sanitizeName("my group/with:bad*chars"); got != "my group_with_bad_chars" {
		t.Errorf("sanitizeName: %q", got)
	}
	if got := sanitizeName("   "); got != "unnamed" {
		t.Errorf("sanitizeName blank: %q", got)
	}
	if got := sanitizeName(string([]rune{0x2028, 'a'})); got != "_a" {
		t.Errorf("sanitizeName unicode: %q", got)
	}
}

func TestHeaderAndMetadataJSON(t *testing.T) {
	root := build(t, fullSample, Options{DefaultTime: fixedTime})
	var header headerInfo
	if err := json.Unmarshal(child(t, root, "header.json").Data, &header); err != nil {
		t.Fatalf("header.json: %v", err)
	}
	if header.SchemaCurrent != 227 || header.ProjectRoot != 250 || header.FileSize != 8388608 {
		t.Errorf("header.json: %+v", header)
	}
	var metadata burpfile.Metadata
	if err := json.Unmarshal(child(t, root, "metadata.json").Data, &metadata); err != nil {
		t.Fatalf("metadata.json: %v", err)
	}
	if metadata.ProjectName == nil || *metadata.ProjectName != "2026-09-23" {
		t.Errorf("metadata.json: %+v", metadata)
	}
}

// TestMountIntegration performs a real FUSE mount when /dev/fuse is
// available; it is skipped in environments without FUSE support (e.g. this
// container).
func TestMountIntegration(t *testing.T) {
	if _, err := os.Stat("/dev/fuse"); err != nil {
		t.Skip("no /dev/fuse; skipping live mount test")
	}
	mountpoint := t.TempDir()
	project, err := burpfile.Open(fullSample)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	server, err := Mount(mountpoint, project, Options{DefaultTime: fixedTime}, false)
	if err != nil {
		t.Fatalf("mount: %v", err)
	}
	go func() {
		time.Sleep(100 * time.Millisecond)
		data, err := os.ReadFile(filepath.Join(mountpoint, "proxy", "0001", "request"))
		if err != nil {
			t.Errorf("read request: %v", err)
		} else if !startsWith(data, "GET / HTTP/1.1\r\n") {
			t.Errorf("bad request content through fuse: %q", data[:20])
		}
		entries, err := os.ReadDir(filepath.Join(mountpoint, "repeater", "tabs"))
		if err != nil {
			t.Errorf("readdir tabs: %v", err)
		} else if len(entries) != 1 {
			t.Errorf("tabs entries: %d", len(entries))
		}
		info, err := os.Stat(filepath.Join(mountpoint, "proxy", "0001", "request"))
		if err != nil {
			t.Errorf("stat: %v", err)
		} else {
			if !info.ModTime().Equal(time.UnixMilli(1790199057733)) {
				t.Errorf("mtime through fuse: %v", info.ModTime())
			}
			if info.Mode().Perm() != 0o444 {
				t.Errorf("perm through fuse: %v", info.Mode().Perm())
			}
		}
		// write attempts must fail
		if err := os.WriteFile(filepath.Join(mountpoint, "proxy", "0001", "request"), []byte("x"), 0o644); err == nil {
			t.Errorf("write to ro mount unexpectedly succeeded")
		}
		server.Unmount()
	}()
	server.Wait()
}

func startsWith(data []byte, prefix string) bool {
	return len(data) >= len(prefix) && string(data[:len(prefix)]) == prefix
}

func walk(node *Node, fn func(*Node)) {
	fn(node)
	for _, c := range node.Children {
		walk(c, fn)
	}
}

var _ = syscall.S_IFREG // keep syscall import if integration test is skipped
