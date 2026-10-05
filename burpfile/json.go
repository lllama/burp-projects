package burpfile

// JSON view types mirroring the shapes of prub's inspect_* dicts and export
// document. Struct fields are deliberately declared in alphabetical order so
// that encoding/json emits keys sorted, matching prub's sort_keys=True.

// Metadata is the project identity reported by inspect_project_metadata.
type Metadata struct {
	HeaderRandomIdentifier uint32  `json:"header_random_identifier"`
	InstallationID         *string `json:"installation_id"`
	ProjectIdentifier      *string `json:"project_identifier"`
	ProjectName            *string `json:"project_name"`
	SchemaCurrent          uint16  `json:"schema_current"`
	SchemaFloor            uint16  `json:"schema_floor"`
}

// ByteVariant reports one raw byte variant of a Proxy history item.
type ByteVariant struct {
	Address *int64 `json:"address"`
	Length  *int32 `json:"length,omitempty"`
}

// RecordRef reports one raw request/response byte record.
type RecordRef struct {
	Address *int64 `json:"address"`
	Length  *int32 `json:"length,omitempty"`
}

// ProxyItem is one Proxy history entry view.
type ProxyItem struct {
	Address      int64                   `json:"address"`
	ByteVariants map[string]*ByteVariant `json:"byte_variants"`
	Subtype      uint8                   `json:"subtype"`
	TypeID       uint8                   `json:"type_id"`
}

// ProxyCollection is one chunked Proxy history view.
type ProxyCollection struct {
	Address int64       `json:"address"`
	FieldID int         `json:"field_id"`
	Items   []ProxyItem `json:"items"`
}

// ProxyInfo mirrors prub's inspect_proxy_items JSON shape.
type ProxyInfo struct {
	Collections []ProxyCollection `json:"collections"`
	RootAddress int64             `json:"root_address"`
}

// RepeaterPair is one Repeater request/response exchange.
type RepeaterPair struct {
	Address  int64     `json:"address"`
	Request  RecordRef `json:"request"`
	Response RecordRef `json:"response"`
}

// RepeaterTab is one Repeater tab.
type RepeaterTab struct {
	Address               int64          `json:"address"`
	Caption               *string        `json:"caption"`
	CurrentRequestAddress *int64         `json:"current_request_address"`
	GroupAddress          *int64         `json:"group_address"`
	Pairs                 []RepeaterPair `json:"pairs"`
	TypeID                uint8          `json:"type_id"`
	UUID                  *string        `json:"uuid"`
}

// RepeaterGroup is one Repeater tab group.
type RepeaterGroup struct {
	Address   int64   `json:"address"`
	ColorEnum *string `json:"color_enum"`
	ColorID   *uint8  `json:"color_id"`
	Expanded  *bool   `json:"expanded"`
	Index     *int32  `json:"index"`
	Name      *string `json:"name"`
	UUID      *string `json:"uuid"`
}

// RepeaterInfo mirrors prub's inspect_repeater_items JSON shape.
type RepeaterInfo struct {
	GroupCollectionAddress *int64          `json:"group_collection_address"`
	Groups                 []RepeaterGroup `json:"groups"`
	RootAddress            int64           `json:"root_address"`
	TabCollectionAddress   *int64          `json:"tab_collection_address"`
	Tabs                   []RepeaterTab   `json:"tabs"`
}

// TargetNode is one Site Map identity-index entry with its hierarchy node.
type TargetNode struct {
	Bucket         int       `json:"bucket"`
	Hash           int64     `json:"hash"`
	KeyAddress     int64     `json:"key_address"`
	MessageAddress *int64    `json:"message_address"`
	Request        RecordRef `json:"request"`
	Response       RecordRef `json:"response"`
	Subtype        uint8     `json:"subtype"`
	TypeID         uint8     `json:"type_id"`
	Value          int64     `json:"value"`
}

// TargetInfo mirrors prub's inspect_target_items JSON shape.
type TargetInfo struct {
	IdentityIndexAddress *int64       `json:"identity_index_address"`
	Nodes                []TargetNode `json:"nodes"`
	RootAddress          int64        `json:"root_address"`
}
