package main

import (
	"fmt"
	"strings"
	"testing"

	"charm.land/bubbletea/v2"

	burpfile "burpfile"
)

const (
	emptySample = "../../../2026-09-23-empty.burp"
	fullSample  = "../../../2026-09-23.burp"
)

func key(s string) tea.KeyPressMsg {
	switch s {
	case "enter":
		return tea.KeyPressMsg{Code: tea.KeyEnter}
	case "esc":
		return tea.KeyPressMsg{Code: tea.KeyEscape}
	case "up":
		return tea.KeyPressMsg{Code: tea.KeyUp}
	case "down":
		return tea.KeyPressMsg{Code: tea.KeyDown}
	case "pgdown":
		return tea.KeyPressMsg{Code: tea.KeyPgDown}
	case "pgup":
		return tea.KeyPressMsg{Code: tea.KeyPgUp}
	default:
		return tea.KeyPressMsg{Code: rune(s[0]), Text: s}
	}
}

func send(m *model, keys ...string) *model {
	for _, k := range keys {
		next, _ := m.Update(key(k))
		m = next.(*model)
	}
	return m
}

// projectNodes re-derives the Target walk for consistency assertions.
func (m *model) projectNodes() []burpfile.TargetNode {
	info, err := m.project.Target()
	if err != nil {
		return nil
	}
	return info.Nodes
}

func newTestModel(t *testing.T, path string) *model {
	t.Helper()
	project, err := burpfile.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	metadata, err := project.Metadata()
	if err != nil {
		t.Fatalf("metadata: %v", err)
	}
	m := newModel(project, metadata)
	m.width, m.height = 100, 30
	return m
}

func TestMenuNavigation(t *testing.T) {
	m := newTestModel(t, fullSample)
	view := m.View().Content
	for _, want := range []string{"Proxy", "Repeater", "Target (Site map)", "Project metadata", "Intruder", "Scope"} {
		if !strings.Contains(view, want) {
			t.Errorf("menu missing %q", want)
		}
	}
	// quit key is reported through the returned command, not the model
	_, cmd := m.Update(key("q"))
	if cmd == nil {
		t.Error("expected quit command for q")
	}
}

func TestMetadataView(t *testing.T) {
	m := send(newTestModel(t, fullSample), "enter")
	view := m.View().Content
	for _, want := range []string{"2026-09-23", "9lnul0pxq1f7a7vd2z18", "227 / 227", "Allocation cursor"} {
		if !strings.Contains(view, want) {
			t.Errorf("metadata view missing %q", want)
		}
	}
	back := send(m, "esc")
	if back.screen != screenMenu {
		t.Errorf("esc did not return to menu: %v", back.screen)
	}
}

func selectMenu(t *testing.T, m *model, label string) *model {
	t.Helper()
	for i, entry := range m.menu {
		if entry.label == label {
			m.cursor = i
			return send(m, "enter")
		}
	}
	t.Fatalf("menu entry %q not found", label)
	return nil
}

func TestProxyListView(t *testing.T) {
	m := selectMenu(t, newTestModel(t, fullSample), "Proxy")
	if m.screen != screenList || m.current == nil {
		t.Fatalf("proxy did not open: %v", m.screen)
	}
	if len(m.current.entries) != 28 {
		t.Fatalf("expected 28 unique proxy items, got %d", len(m.current.entries))
	}
	view := m.View().Content
	if !strings.Contains(view, "45 items (28 unique)") {
		t.Errorf("proxy summary missing: %s", view[:200])
	}
	if !strings.Contains(view, "GET / HTTP/1.1") {
		t.Errorf("proxy first-line preview missing")
	}
}

func TestRepeaterAndTarget(t *testing.T) {
	m := selectMenu(t, newTestModel(t, fullSample), "Repeater")
	if len(m.current.entries) != 3 {
		t.Fatalf("expected 3 repeater pairs, got %d", len(m.current.entries))
	}
	if !strings.Contains(m.View().Content, "1 tabs, 0 groups") {
		t.Errorf("repeater summary missing")
	}

	m = selectMenu(t, newTestModel(t, fullSample), "Target (Site map)")
	// entries are the message-bearing nodes that actually hold bytes
	stored := 0
	for _, node := range m.projectNodes() {
		if node.MessageAddress != nil &&
			(node.Request.Address != nil || node.Response.Address != nil) {
			stored++
		}
	}
	if len(m.current.entries) != stored {
		t.Fatalf("expected %d target entries, got %d", stored, len(m.current.entries))
	}
	if !strings.Contains(m.View().Content, "337 nodes") {
		t.Errorf("target summary missing")
	}
}

func TestDetailView(t *testing.T) {
	m := send(selectMenu(t, newTestModel(t, fullSample), "Proxy"), "enter")
	if m.screen != screenDetail {
		t.Fatalf("enter did not open detail: %v", m.screen)
	}
	view := m.View().Content
	if !strings.Contains(view, "REQUEST —") || !strings.Contains(view, "RESPONSE —") {
		t.Errorf("detail sections missing")
	}
	if !strings.Contains(view, "Host: nmap.org") {
		t.Errorf("request body missing")
	}
	// scroll to the bottom: G should clamp at maxScroll
	m = send(m, "G")
	if m.scroll != m.maxScroll() {
		t.Errorf("G did not scroll to bottom: %d vs %d", m.scroll, m.maxScroll())
	}
	back := send(m, "esc")
	if back.screen != screenList {
		t.Errorf("esc did not return to list: %v", back.screen)
	}
}

func TestListScrolling(t *testing.T) {
	m := selectMenu(t, newTestModel(t, fullSample), "Target (Site map)")
	total := len(m.current.entries)
	visible := m.visibleRows()
	// walk past the end: cursor clamps on the last entry, viewport follows
	for i := 0; i < total+3; i++ {
		m = send(m, "j")
	}
	if m.cursor != total-1 {
		t.Fatalf("cursor did not reach the last entry: %d", m.cursor)
	}
	if want := max(0, total-visible); m.offset != want {
		t.Errorf("viewport offset wrong: %d, want %d", m.offset, want)
	}
	view := m.View().Content
	if !strings.Contains(view, fmt.Sprintf("%d/%d", total, total)) {
		t.Errorf("position indicator missing")
	}
}

func TestEmptyProject(t *testing.T) {
	m := selectMenu(t, newTestModel(t, emptySample), "Proxy")
	if len(m.current.entries) != 0 {
		t.Fatalf("expected empty proxy, got %d", len(m.current.entries))
	}
	if !strings.Contains(m.View().Content, "(no stored content for this tool)") {
		t.Errorf("empty-state message missing")
	}
	m = send(m, "esc")
	m = selectMenu(t, m, "Repeater")
	if len(m.current.entries) != 1 {
		t.Fatalf("expected the unsent tab entry, got %d", len(m.current.entries))
	}
	if !strings.Contains(m.View().Content, "(no stored pairs)") {
		t.Errorf("unsent-tab entry missing")
	}
	// opening it should still produce a readable detail view
	m = send(m, "enter")
	if m.screen != screenDetail || !strings.Contains(m.View().Content, "REQUEST — none") {
		t.Errorf("unsent tab detail view broken")
	}
}
