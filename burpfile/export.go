package burpfile

import (
	"encoding/base64"
	"fmt"
)

// Export message types mirroring prub's exporter. Fields are declared in
// alphabetical order to match prub's sort_keys=True output.

// ExportMessage is one base64-encoded HTTP exchange.
type ExportMessage struct {
	ID             string  `json:"id"`
	RequestBase64  *string `json:"request_base64"`
	ResponseBase64 *string `json:"response_base64"`
}

// ExportTabContext is the owning Repeater tab of a message.
type ExportTabContext struct {
	Caption *string `json:"caption"`
	UUID    *string `json:"uuid"`
}

// ExportGroupContext is the owning Repeater group of a message.
type ExportGroupContext struct {
	ColorID *uint8  `json:"color_id"`
	Name    *string `json:"name"`
	UUID    *string `json:"uuid"`
}

// ExportRepeaterMessage is one Repeater exchange with tab/group context.
type ExportRepeaterMessage struct {
	Group          *ExportGroupContext `json:"group"`
	ID             string              `json:"id"`
	PairIndex      int                 `json:"pair_index"`
	RequestBase64  *string             `json:"request_base64"`
	ResponseBase64 *string             `json:"response_base64"`
	Tab            ExportTabContext    `json:"tab"`
}

// Export is the unified export document (prub.exporter.build_export).
type Export struct {
	BurpSchema  uint16                  `json:"burp_schema"`
	ProjectName *string                 `json:"project_name"`
	Proxy       []ExportMessage         `json:"proxy"`
	Repeater    []ExportRepeaterMessage `json:"repeater"`
	Target      []ExportMessage         `json:"target"`
}

func (p *Project) encodeRecord(address *int64) (*string, error) {
	if address == nil {
		return nil, nil
	}
	record, err := p.ReadRecord(*address)
	if err != nil {
		return nil, err
	}
	encoded := base64.StdEncoding.EncodeToString(record.Payload)
	return &encoded, nil
}

// Export builds the unified export document with separate Burp tool
// sections, mirroring prub.exporter.build_export: Proxy items are deduped by
// item address; Repeater pairs are grouped by tab with group context; Target
// messages are deduped by their (request, response) address pair.
func (p *Project) Export() (*Export, error) {
	metadata, err := p.Metadata()
	if err != nil {
		return nil, err
	}
	proxy, err := p.Proxy()
	if err != nil {
		return nil, err
	}
	repeater, err := p.Repeater()
	if err != nil {
		return nil, err
	}
	target, err := p.Target()
	if err != nil {
		return nil, err
	}

	out := &Export{
		BurpSchema:  p.header.SchemaCurrent,
		ProjectName: metadata.ProjectName,
		Proxy:       []ExportMessage{},
		Repeater:    []ExportRepeaterMessage{},
		Target:      []ExportMessage{},
	}

	seenProxyItems := make(map[int64]bool)
	for _, collection := range proxy.Collections {
		for _, item := range collection.Items {
			if seenProxyItems[item.Address] {
				continue
			}
			seenProxyItems[item.Address] = true
			message := ExportMessage{
				ID: fmt.Sprintf("proxy-%06d", len(out.Proxy)+1),
			}
			if message.RequestBase64, err = p.encodeRecord(item.ByteVariants["15"].Address); err != nil {
				return nil, err
			}
			if message.ResponseBase64, err = p.encodeRecord(item.ByteVariants["18"].Address); err != nil {
				return nil, err
			}
			out.Proxy = append(out.Proxy, message)
		}
	}

	groupsByAddress := make(map[int64]RepeaterGroup, len(repeater.Groups))
	for _, group := range repeater.Groups {
		groupsByAddress[group.Address] = group
	}
	for _, tab := range repeater.Tabs {
		var groupContext *ExportGroupContext
		if tab.GroupAddress != nil {
			if group, ok := groupsByAddress[*tab.GroupAddress]; ok {
				groupContext = &ExportGroupContext{
					ColorID: group.ColorID,
					Name:    group.Name,
					UUID:    group.UUID,
				}
			}
		}
		for pairIndex, pair := range tab.Pairs {
			message := ExportRepeaterMessage{
				ID:        fmt.Sprintf("repeater-%06d", len(out.Repeater)+1),
				PairIndex: pairIndex + 1,
				Tab: ExportTabContext{
					Caption: tab.Caption,
					UUID:    tab.UUID,
				},
				Group: groupContext,
			}
			if message.RequestBase64, err = p.encodeRecord(pair.Request.Address); err != nil {
				return nil, err
			}
			if message.ResponseBase64, err = p.encodeRecord(pair.Response.Address); err != nil {
				return nil, err
			}
			out.Repeater = append(out.Repeater, message)
		}
	}

	type messageKey struct {
		request  *int64
		response *int64
	}
	seenTargetMessages := make(map[messageKey]bool)
	for _, node := range target.Nodes {
		key := messageKey{request: node.Request.Address, response: node.Response.Address}
		if key.request == nil && key.response == nil {
			continue
		}
		if seenTargetMessages[key] {
			continue
		}
		seenTargetMessages[key] = true
		message := ExportMessage{
			ID: fmt.Sprintf("target-%06d", len(out.Target)+1),
		}
		if message.RequestBase64, err = p.encodeRecord(node.Request.Address); err != nil {
			return nil, err
		}
		if message.ResponseBase64, err = p.encodeRecord(node.Response.Address); err != nil {
			return nil, err
		}
		out.Target = append(out.Target, message)
	}
	return out, nil
}
