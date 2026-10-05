package burpfile

import (
	"encoding/json"
	"testing"
)

const (
	emptySample = "../2026-09-23-empty.burp"
	fullSample  = "../2026-09-23.burp"
)

func TestSamples(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		project := open(t, emptySample)
		metadata := mustMetadata(t, project)
		if metadata.ProjectName == nil || *metadata.ProjectName != "empty" {
			t.Fatalf("unexpected project name: %v", metadata.ProjectName)
		}
		if metadata.SchemaCurrent != 227 || metadata.SchemaFloor != 227 {
			t.Fatalf("unexpected schema: %d/%d", metadata.SchemaFloor, metadata.SchemaCurrent)
		}
		proxy := mustProxy(t, project)
		if len(proxy.Collections) != 2 || len(proxy.Collections[0].Items) != 0 ||
			len(proxy.Collections[1].Items) != 0 {
			t.Fatalf("unexpected proxy: %+v", proxy.Collections)
		}
		repeater := mustRepeater(t, project)
		if len(repeater.Tabs) != 1 || len(repeater.Groups) != 0 {
			t.Fatalf("unexpected repeater: %d tabs, %d groups", len(repeater.Tabs), len(repeater.Groups))
		}
		if repeater.Tabs[0].Caption == nil || *repeater.Tabs[0].Caption != "1" {
			t.Fatalf("unexpected tab caption: %v", repeater.Tabs[0].Caption)
		}
		target := mustTarget(t, project)
		if len(target.Nodes) != 0 {
			t.Fatalf("unexpected target nodes: %d", len(target.Nodes))
		}
	})

	t.Run("full", func(t *testing.T) {
		project := open(t, fullSample)
		mustMetadata(t, project)
		proxy := mustProxy(t, project)
		if len(proxy.Collections[0].Items) != 28 || len(proxy.Collections[1].Items) != 17 {
			t.Fatalf("unexpected proxy item counts: %d, %d",
				len(proxy.Collections[0].Items), len(proxy.Collections[1].Items))
		}
		repeater := mustRepeater(t, project)
		if len(repeater.Tabs) != 1 || len(repeater.Tabs[0].Pairs) != 3 {
			t.Fatalf("unexpected repeater: %d tabs", len(repeater.Tabs))
		}
		// The second pair holds a zero-length (padding) request record.
		if pair := repeater.Tabs[0].Pairs[1]; pair.Request.Address == nil ||
			*pair.Request.Length != 0 {
			t.Fatalf("expected zero-length request in pair 2: %+v", pair.Request)
		}
		target := mustTarget(t, project)
		if len(target.Nodes) != 337 {
			t.Fatalf("unexpected target nodes: %d", len(target.Nodes))
		}
	})
}

func TestExport(t *testing.T) {
	export := mustExport(t, open(t, fullSample))
	if len(export.Proxy) != 28 || len(export.Repeater) != 3 || len(export.Target) != 21 {
		t.Fatalf("unexpected export counts: proxy %d, repeater %d, target %d",
			len(export.Proxy), len(export.Repeater), len(export.Target))
	}
	if export.BurpSchema != 227 || export.ProjectName == nil {
		t.Fatalf("unexpected export header: schema %d, name %v",
			export.BurpSchema, export.ProjectName)
	}
}

// TestJSONKeyOrder pins the alphabetical field order of the view types: prub
// emits sort_keys=True output and the CLI must match it byte for byte.
func TestJSONKeyOrder(t *testing.T) {
	metadata, _ := json.Marshal(Metadata{})
	if string(metadata) != `{"header_random_identifier":0,"installation_id":null,"project_identifier":null,"project_name":null,"schema_current":0,"schema_floor":0}` {
		t.Fatalf("Metadata key order changed: %s", metadata)
	}
}

func open(t *testing.T, path string) *Project {
	t.Helper()
	project, err := Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	return project
}

func mustMetadata(t *testing.T, project *Project) *Metadata {
	t.Helper()
	metadata, err := project.Metadata()
	if err != nil {
		t.Fatalf("metadata: %v", err)
	}
	return metadata
}

func mustProxy(t *testing.T, project *Project) *ProxyInfo {
	t.Helper()
	proxy, err := project.Proxy()
	if err != nil {
		t.Fatalf("proxy: %v", err)
	}
	return proxy
}

func mustRepeater(t *testing.T, project *Project) *RepeaterInfo {
	t.Helper()
	repeater, err := project.Repeater()
	if err != nil {
		t.Fatalf("repeater: %v", err)
	}
	return repeater
}

func mustTarget(t *testing.T, project *Project) *TargetInfo {
	t.Helper()
	target, err := project.Target()
	if err != nil {
		t.Fatalf("target: %v", err)
	}
	return target
}

func mustExport(t *testing.T, project *Project) *Export {
	t.Helper()
	export, err := project.Export()
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	return export
}
