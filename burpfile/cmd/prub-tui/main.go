// Command prub-tui is a read-only Bubbletea viewer for Burp Suite project
// files: pick a tool (Proxy, Repeater, Target/Site map), browse the content
// stored for it, and inspect raw request/response bytes. Project metadata
// has its own view.
package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"unicode/utf8"

	"charm.land/bubbletea/v2"

	burpfile "burpfile"
)

// ------------------------------------------------------------------ model --

type screen int

const (
	screenMenu screen = iota
	screenMetadata
	screenList
	screenDetail
	screenUnmapped
)

type entryKind int

const (
	kindMetadata entryKind = iota
	kindTool
	kindUnmapped
)

type menuEntry struct {
	label       string
	description string
	kind        entryKind
	tool        string // for kindTool
}

// entry is one browsable row of a tool list.
type entry struct {
	label    string
	sub      string
	context  []string // detail header lines (tab/group info)
	request  *int64
	response *int64
}

// tool is the built content list of one Burp tool.
type tool struct {
	title   string
	summary string
	entries []entry
}

type detail struct {
	title string
	lines []string
}

type model struct {
	project  *burpfile.Project
	metadata *burpfile.Metadata

	screen       screen
	menu         []menuEntry
	cursor       int // cursor index within the active screen (menu/list)
	offset       int // first visible row of the list viewport
	scroll       int // scroll offset of the detail text
	tools        map[string]*tool
	current      *tool
	detail       *detail
	metadataView []string

	width  int
	height int
}

func newModel(project *burpfile.Project, metadata *burpfile.Metadata) *model {
	menu := []menuEntry{
		{label: "Project metadata", description: "identity and storage header", kind: kindMetadata},
		{label: "Proxy", description: "HTTP history", kind: kindTool, tool: "proxy"},
		{label: "Repeater", description: "tabs and stored exchanges", kind: kindTool, tool: "repeater"},
		{label: "Target (Site map)", description: "site map nodes", kind: kindTool, tool: "target"},
		{label: "Intruder", description: "not mapped yet", kind: kindUnmapped},
		{label: "Scope", description: "not mapped yet", kind: kindUnmapped},
	}
	return &model{
		project:  project,
		metadata: metadata,
		screen:   screenMenu,
		menu:     menu,
		tools:    make(map[string]*tool),
		width:    80,
		height:   24,
	}
}

// ----------------------------------------------------------------- update --

func (m *model) Init() tea.Cmd { return nil }

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
	case tea.KeyPressMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			return m, tea.Quit
		case "esc":
			switch m.screen {
			case screenDetail:
				m.screen = screenList
			case screenList, screenMetadata, screenUnmapped:
				m.screen = screenMenu
				m.cursor = 0
			}
		case "up", "k":
			m.moveCursor(-1)
		case "down", "j":
			m.moveCursor(1)
		case "pgup", "ctrl+u":
			m.moveCursor(-m.visibleRows())
		case "pgdown", "ctrl+d":
			m.moveCursor(m.visibleRows())
		case "g", "home":
			if m.screen == screenDetail {
				m.scroll = 0
			} else {
				m.cursor, m.offset = 0, 0
			}
		case "G", "end":
			if m.screen == screenDetail {
				m.scroll = m.maxScroll()
			} else {
				m.cursor = m.rowCount() - 1
				m.clampOffset()
			}
		case "enter":
			m.activate()
		}
	}
	return m, nil
}

func (m *model) rowCount() int {
	switch m.screen {
	case screenMenu:
		return len(m.menu)
	case screenList:
		if m.current == nil {
			return 0
		}
		return len(m.current.entries)
	}
	return 0
}

func (m *model) moveCursor(delta int) {
	switch m.screen {
	case screenList:
		// In lists the cursor moves within entries; the viewport follows.
		m.cursor = clamp(m.cursor+delta, 0, m.rowCount()-1)
		m.clampOffset()
	case screenDetail:
		m.scroll = clamp(m.scroll+delta, 0, m.maxScroll())
	case screenMenu:
		m.cursor = clamp(m.cursor+delta, 0, m.rowCount()-1)
	}
}

func (m *model) activate() {
	switch m.screen {
	case screenMenu:
		selected := m.menu[m.cursor]
		switch selected.kind {
		case kindMetadata:
			m.metadataView = buildMetadataLines(m.project, m.metadata)
			m.screen = screenMetadata
		case kindTool:
			view, err := m.toolView(selected.tool)
			if err != nil {
				// Render load failures as an entry-level message instead of
				// crashing the program.
				view = &tool{
					title:   selected.label,
					summary: err.Error(),
					entries: []entry{{label: "(could not load this tool)", sub: err.Error()}},
				}
			}
			m.current = view
			m.cursor, m.offset = 0, 0
			m.screen = screenList
		case kindUnmapped:
			m.screen = screenUnmapped
		}
	case screenList:
		if m.current == nil || m.cursor >= len(m.current.entries) {
			return
		}
		m.detail = m.buildDetail(m.current.entries[m.cursor])
		m.scroll = 0
		m.screen = screenDetail
	}
}

func (m *model) toolView(name string) (*tool, error) {
	if cached, ok := m.tools[name]; ok {
		return cached, nil
	}
	var (
		tool *tool
		err  error
	)
	switch name {
	case "proxy":
		tool, err = buildProxyTool(m.project)
	case "repeater":
		tool, err = buildRepeaterTool(m.project)
	case "target":
		tool, err = buildTargetTool(m.project)
	}
	if err != nil {
		return nil, err
	}
	m.tools[name] = tool
	return tool, nil
}

func (m *model) buildDetail(e entry) *detail {
	d := &detail{title: e.label, lines: []string{}}
	d.lines = append(d.lines, e.context...)
	reqLabel, reqLines := m.payloadSection(e.request)
	d.lines = append(d.lines, "REQUEST — "+reqLabel)
	d.lines = append(d.lines, reqLines...)
	d.lines = append(d.lines, "")
	respLabel, respLines := m.payloadSection(e.response)
	d.lines = append(d.lines, "RESPONSE — "+respLabel)
	d.lines = append(d.lines, respLines...)
	return d
}

func (m *model) payloadSection(address *int64) (string, []string) {
	if address == nil {
		return "none", []string{"(no stored bytes)"}
	}
	record, err := m.project.ReadRecord(*address)
	if err != nil {
		return "unreadable", []string{"(error: " + err.Error() + ")"}
	}
	text := sanitize(record.Payload)
	label := humanBytes(int64(len(record.Payload)))
	return label, strings.Split(text, "\n")
}

// ------------------------------------------------------------- data views --

func buildProxyTool(project *burpfile.Project) (*tool, error) {
	info, err := project.Proxy()
	if err != nil {
		return nil, err
	}
	t := &tool{title: "Proxy history"}
	total := 0
	seen := make(map[int64]bool)
	for _, collection := range info.Collections {
		total += len(collection.Items)
		for _, item := range collection.Items {
			if seen[item.Address] {
				continue
			}
			seen[item.Address] = true
			request := firstVariant(item.ByteVariants, "15", "16", "17")
			response := firstVariant(item.ByteVariants, "18", "19", "20")
			label := "(no request bytes)"
			if request != nil && request.Address != nil {
				if record, err := project.ReadRecord(*request.Address); err == nil {
					if line := firstLine(record.Payload); line != "" {
						label = line
					}
				}
			}
			t.entries = append(t.entries, entry{
				label:    label,
				sub:      fmt.Sprintf("req %s · resp %s", variantSize(request), variantSize(response)),
				request:  variantAddress(request),
				response: variantAddress(response),
			})
		}
	}
	t.summary = fmt.Sprintf("%d items (%d unique)", total, len(t.entries))
	return t, nil
}

func firstVariant(variants map[string]*burpfile.ByteVariant, names ...string) *burpfile.ByteVariant {
	for _, name := range names {
		if v := variants[name]; v != nil && v.Address != nil {
			return v
		}
	}
	return nil
}

func variantAddress(v *burpfile.ByteVariant) *int64 {
	if v == nil {
		return nil
	}
	return v.Address
}

func variantSize(v *burpfile.ByteVariant) string {
	if v == nil || v.Length == nil {
		return "none"
	}
	return humanBytes(int64(*v.Length))
}

func buildRepeaterTool(project *burpfile.Project) (*tool, error) {
	info, err := project.Repeater()
	if err != nil {
		return nil, err
	}
	t := &tool{
		title:   "Repeater",
		summary: fmt.Sprintf("%d tabs, %d groups", len(info.Tabs), len(info.Groups)),
	}
	for _, tab := range info.Tabs {
		caption := "(untitled tab)"
		if tab.Caption != nil {
			caption = *tab.Caption
		}
		context := []string{fmt.Sprintf("Tab: %s", caption)}
		if tab.UUID != nil {
			context = append(context, "UUID: "+*tab.UUID)
		}
		if len(tab.Pairs) == 0 {
			t.entries = append(t.entries, entry{
				label:   caption + " (no stored pairs)",
				sub:     "unsent",
				context: context,
			})
			continue
		}
		for index, pair := range tab.Pairs {
			label := "(no request bytes)"
			if pair.Request.Address != nil {
				if record, err := project.ReadRecord(*pair.Request.Address); err == nil {
					if line := firstLine(record.Payload); line != "" {
						label = line
					}
				}
			}
			entry := entry{
				label: fmt.Sprintf("%s · pair %d — %s", caption, index+1, label),
				sub: fmt.Sprintf("req %s · resp %s",
					refSize(pair.Request), refSize(pair.Response)),
				request:  pair.Request.Address,
				response: pair.Response.Address,
			}
			entry.context = append(context, fmt.Sprintf("Pair: %d of %d", index+1, len(tab.Pairs)))
			t.entries = append(t.entries, entry)
		}
	}
	return t, nil
}

func refSize(ref burpfile.RecordRef) string {
	if ref.Length == nil {
		return "none"
	}
	return humanBytes(int64(*ref.Length))
}

func buildTargetTool(project *burpfile.Project) (*tool, error) {
	info, err := project.Target()
	if err != nil {
		return nil, err
	}
	t := &tool{title: "Target — Site map"}
	withMessages, withBytes := 0, 0
	for _, node := range info.Nodes {
		if node.MessageAddress == nil {
			continue
		}
		withMessages++
		if node.Request.Address == nil && node.Response.Address == nil {
			continue
		}
		withBytes++
		label := "(no request bytes)"
		if node.Request.Address != nil {
			if record, err := project.ReadRecord(*node.Request.Address); err == nil {
				if line := firstLine(record.Payload); line != "" {
					label = line
				}
			}
		}
		t.entries = append(t.entries, entry{
			label:    label,
			sub:      fmt.Sprintf("req %s · resp %s", refSize(node.Request), refSize(node.Response)),
			request:  node.Request.Address,
			response: node.Response.Address,
		})
	}
	t.summary = fmt.Sprintf(
		"%d nodes · %d with messages · %d with stored bytes",
		len(info.Nodes), withMessages, withBytes)
	return t, nil
}

func buildMetadataLines(project *burpfile.Project, metadata *burpfile.Metadata) []string {
	header := project.Header()
	stringOr := func(s *string) string {
		if s == nil {
			return "(none)"
		}
		return *s
	}
	rows := [][2]string{
		{"Project name", stringOr(metadata.ProjectName)},
		{"Installation ID", stringOr(metadata.InstallationID)},
		{"Project identifier", stringOr(metadata.ProjectIdentifier)},
		{"Schema (floor / current)", fmt.Sprintf("%d / %d", metadata.SchemaFloor, metadata.SchemaCurrent)},
		{"Header random identifier", strconv.FormatUint(uint64(metadata.HeaderRandomIdentifier), 10)},
		{"File size", fmt.Sprintf("%s (%d bytes)", humanBytes(project.Size()), project.Size())},
		{"Allocation cursor", strconv.FormatInt(header.AllocationCursor, 10)},
		{"Segment span", fmt.Sprintf("%#x", uint64(header.SegmentSpan))},
		{"Metadata root", strconv.FormatInt(header.MetadataRoot, 10)},
		{"Project root", strconv.FormatInt(header.ProjectRoot, 10)},
		{"Outer version", strconv.FormatInt(int64(header.OuterVersion), 10)},
	}
	lines := make([]string, 0, len(rows))
	for _, row := range rows {
		lines = append(lines, fmt.Sprintf("%-26s %s", row[0]+":", row[1]))
	}
	return lines
}

// ------------------------------------------------------------------ view --

func (m *model) View() tea.View {
	return tea.View{Content: m.render(), AltScreen: true}
}

func (m *model) render() string {
	var b strings.Builder
	b.WriteString(m.headerLine())
	b.WriteString("\n\n")
	switch m.screen {
	case screenMenu:
		m.renderMenu(&b)
	case screenMetadata:
		m.renderText(&b, m.metadataView)
	case screenList:
		m.renderList(&b)
	case screenDetail:
		m.renderDetail(&b)
	case screenUnmapped:
		m.renderUnmapped(&b)
	}
	b.WriteString("\n")
	b.WriteString(m.footer())
	return b.String()
}

func (m *model) headerLine() string {
	name := "(unknown)"
	if m.metadata != nil && m.metadata.ProjectName != nil {
		name = *m.metadata.ProjectName
	}
	title := "prub-tui"
	switch m.screen {
	case screenList:
		if m.current != nil {
			title += " — " + m.current.title
			if m.current.summary != "" {
				title += "  (" + m.current.summary + ")"
			}
		}
	case screenDetail:
		if m.detail != nil {
			title += " — " + m.detail.title
		}
	case screenMetadata:
		title += " — project metadata"
	}
	return bold(truncate(fmt.Sprintf("%s  ·  %s", title, name), m.width))
}

func (m *model) renderMenu(b *strings.Builder) {
	rows := make([]string, 0, len(m.menu))
	for i, entry := range m.menu {
		line := fmt.Sprintf("%-20s %s", entry.label, entry.description)
		rows = append(rows, m.row(i, line))
	}
	b.WriteString(strings.Join(rows, "\n"))
}

func (m *model) renderList(b *strings.Builder) {
	if m.current == nil {
		b.WriteString("(nothing loaded)")
		return
	}
	if len(m.current.entries) == 0 {
		b.WriteString("(no stored content for this tool)")
		return
	}
	visible := m.visibleRows()
	first := m.offset
	last := min(first+visible, len(m.current.entries))
	rows := make([]string, 0, last-first)
	for i := first; i < last; i++ {
		e := m.current.entries[i]
		rows = append(rows, m.row(i, m.entryLine(e)))
	}
	b.WriteString(strings.Join(rows, "\n"))
}

func (m *model) entryLine(e entry) string {
	line := e.label
	if e.sub != "" {
		avail := m.width - utf8.RuneCountInString(e.sub) - 2
		line = truncate(e.label, avail)
		if pad := m.width - utf8.RuneCountInString(line) - utf8.RuneCountInString(e.sub); pad > 0 {
			line += strings.Repeat(" ", pad) + e.sub
		}
	}
	return line
}

func (m *model) renderDetail(b *strings.Builder) {
	if m.detail == nil {
		b.WriteString("(nothing selected)")
		return
	}
	visible := m.visibleRows()
	first := min(m.scroll, m.maxScroll())
	last := min(first+visible, len(m.detail.lines))
	rows := make([]string, 0, last-first)
	for i := first; i < last; i++ {
		rows = append(rows, truncate(m.detail.lines[i], m.width))
	}
	if len(rows) == 0 {
		rows = append(rows, "(empty)")
	}
	b.WriteString(strings.Join(rows, "\n"))
}

// renderText draws fixed lines, truncated to the terminal width.
func (m *model) renderText(b *strings.Builder, lines []string) {
	rows := make([]string, 0, len(lines))
	for _, line := range lines {
		rows = append(rows, truncate(line, m.width))
	}
	b.WriteString(strings.Join(rows, "\n"))
}

func (m *model) renderUnmapped(b *strings.Builder) {
	b.WriteString(wrapLines(
		"This Burp tool's project structures have not been reverse engineered\n"+
			"from the storage format yet.\n\n"+
			"Currently verified mappings cover Proxy history, Repeater tabs and\n"+
			"groups, and the Target/Site map identity index. See\n"+
			"prub/ai-docs/format-specification.md for the field-level details.", m.width))
}

func (m *model) row(index int, line string) string {
	line = truncate(line, m.width)
	if index == m.cursor {
		return reverse(pad(line, m.width))
	}
	return line
}

func (m *model) footer() string {
	var hints string
	switch m.screen {
	case screenMenu:
		hints = "↑/↓ move · enter open · q quit"
	case screenList:
		hints = "↑/↓ move · enter inspect · esc back · q quit"
	case screenDetail:
		hints = "↑/↓ scroll · pgup/pgdn page · g/G top/bottom · esc back · q quit"
	case screenMetadata, screenUnmapped:
		hints = "esc back · q quit"
	}
	position := ""
	if m.screen == screenList && m.current != nil && len(m.current.entries) > 0 {
		position = fmt.Sprintf(" %d/%d", m.cursor+1, len(m.current.entries))
	}
	line := hints + position
	return dim(pad(truncate(line, m.width), m.width))
}

func (m *model) visibleRows() int {
	// Header, blank line, footer, and one spare line of chrome.
	return max(1, m.height-5)
}

func (m *model) maxScroll() int {
	if m.detail == nil {
		return 0
	}
	return max(0, len(m.detail.lines)-m.visibleRows())
}

func (m *model) clampOffset() {
	visible := m.visibleRows()
	if m.cursor < m.offset {
		m.offset = m.cursor
	}
	if m.cursor >= m.offset+visible {
		m.offset = m.cursor - visible + 1
	}
	m.offset = clamp(m.offset, 0, max(0, len(m.current.entries)-visible))
}

// ---------------------------------------------------------------- helpers --

func clamp(v, low, high int) int {
	if v < low {
		return low
	}
	if v > high {
		return high
	}
	return v
}

func pad(s string, width int) string {
	if missing := width - utf8.RuneCountInString(s); missing > 0 {
		return s + strings.Repeat(" ", missing)
	}
	return s
}

func truncate(s string, max int) string {
	if max < 0 {
		return ""
	}
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	if max == 0 {
		return ""
	}
	return string(runes[:max-1]) + "…"
}

func wrapLines(text string, width int) string {
	lines := strings.Split(text, "\n")
	out := make([]string, len(lines))
	for i, line := range lines {
		out[i] = truncate(line, width)
	}
	return strings.Join(out, "\n")
}

func bold(s string) string    { return "\x1b[1m" + s + "\x1b[0m" }
func dim(s string) string     { return "\x1b[2m" + s + "\x1b[0m" }
func reverse(s string) string { return "\x1b[7m" + s + "\x1b[0m" }

func humanBytes(n int64) string {
	switch {
	case n < 0:
		return "?"
	case n < 1024:
		return fmt.Sprintf("%d B", n)
	case n < 1024*1024:
		return fmt.Sprintf("%.1f kB", float64(n)/1024)
	default:
		return fmt.Sprintf("%.1f MB", float64(n)/(1024*1024))
	}
}

// sanitize makes raw record bytes safe to print: CRLF becomes LF, other
// control characters become '·'.
func sanitize(raw []byte) string {
	text := strings.ReplaceAll(string(raw), "\r\n", "\n")
	return strings.Map(func(r rune) rune {
		if r == '\n' {
			return r
		}
		if r < 0x20 || r == 0x7f {
			return '·'
		}
		return r
	}, text)
}

func firstLine(raw []byte) string {
	text := sanitize(raw)
	if index := strings.IndexByte(text, '\n'); index >= 0 {
		text = text[:index]
	}
	return strings.TrimSpace(text)
}

// ------------------------------------------------------------------- main --

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: prub-tui <project.burp>")
		os.Exit(2)
	}
	project, err := burpfile.Open(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "prub-tui:", err)
		os.Exit(1)
	}
	metadata, err := project.Metadata()
	if err != nil {
		fmt.Fprintln(os.Stderr, "prub-tui:", err)
		os.Exit(1)
	}
	program := tea.NewProgram(newModel(project, metadata))
	if _, err := program.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "prub-tui:", err)
		os.Exit(1)
	}
}
