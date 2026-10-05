meta:
  id: burp_project
  title: Burp Suite project file (outer storage version 1)
  file-extension: burp
  endian: be
  ks-version: 0.11
  license: MIT

# Structural layer of Burp Suite project (.burp) save files, reverse
# engineered from Burp Suite 2026.7.x with schema 226/227. See
# prub/ai-docs/format-specification.md for the full format notes.
#
# Addresses are absolute byte offsets in the file. Persisted object
# references are signed 64-bit big-endian values; 0 means "absent".
#
# Compact objects carry a self-describing descriptor table (field-id ->
# relative offset, in data order, not id order). The find_* types locate a
# descriptor for a given field id by reading entries until a match or the
# end of the table (repeat-until over _io.pos), then read the typed value
# at base + relative_offset. Value entries are guarded by "if" so absent
# fields stay null instead of reading bogus positions.

seq:
  - id: header
    type: header
  - id: roots
    type: roots


types:
  roots:
    seq: []
    instances:
      metadata_root_obj:
        doc: Object at header metadata root (string chunk recycling pool).
        pos: _root.header.metadata_root
        type: "compact_object(_root.header.metadata_root)"
      project_root_obj:
        doc: Compact object at header project root (follow forwarding via nav layer).
        pos: _root.header.project_root
        type: "compact_object(_root.header.project_root)"

  header:
    doc: 72-byte big-endian outer header.
    seq:
      - id: magic
        contents: [0x66, 0x85, 0x82, 0x80]
      - id: outer_version
        type: s4
      - id: compatibility
        type: s4
      - id: schema_floor
        type: u2
      - id: schema_current
        type: u2
      - id: random_identifier
        type: u4
      - id: reserved
        size: 20
      - id: metadata_root
        type: s8
      - id: segment_span
        type: s8
      - id: allocation_cursor
        type: s8
      - id: project_root
        type: s8

  # ------------------------------------------------------------------
  # Variable records: int32 total_size, int32 logical_length, payload.
  # Zero-length records reserve one padding byte (total_size = 9).
  # ------------------------------------------------------------------
  var_record:
    seq:
      - id: total_size
        type: s4
      - id: logical_length
        type: s4
      - id: data
        size: logical_length
      - id: padding
        size: 1
        if: logical_length == 0

  # Fixed-width element arrays share the var-record framing; element count
  # replaces logical length. Address arrays use 8-byte elements.
  utf16_array:
    doc: Variable array of UTF-16BE code units (string character storage).
    seq:
      - id: total_size
        type: s4
      - id: char_count
        type: s4
      - id: data
        size: char_count * 2
      - id: padding
        size: 1
        if: char_count == 0

  address_array:
    seq:
      - id: total_size
        type: s4
      - id: element_count
        type: s4
      - id: padding
        size: 1
        if: element_count == 0
      - id: addresses
        type: s8
        repeat: expr

        repeat-expr: element_count

  # 24-byte hash/key/value tuples used by the Target identity index.
  bucket_tuple:
    seq:
      - id: hash
        type: s8
      - id: key_address
        type: s8
      - id: value
        type: s8

  bucket_tuples:
    seq:
      - id: total_size
        type: s4
      - id: element_count
        type: s4
      - id: padding
        size: 1
        if: element_count == 0
      - id: tuples
        type: bucket_tuple
        repeat: expr

        repeat-expr: element_count

  descriptor:
    doc: 3-byte descriptor entry (field id, relative offset from object start).
    seq:
      - id: field_id
        type: u1
      - id: relative_offset
        type: s2

  # ------------------------------------------------------------------
  # Compact object header. flags bit 0 marks a forwarding record; normal
  # objects read type/subtype/descriptor count and the descriptor table.
  # For forwarding records the type/subtype/count bytes overlap the 8-byte
  # forwarding address and are meaningless; descriptors are not parsed.
  # type_id/subtype/descriptor_count are read unconditionally so
  # table_end always evaluates without null dereferences.
  # ------------------------------------------------------------------
  compact_object:
    params:
      - id: base
        type: s8
    seq:
      - id: flags
        type: u1
      - id: type_id
        type: u1
      - id: subtype
        type: u1
      - id: descriptor_count
        type: u1
      - id: descriptors
        type: descriptor
        repeat: expr

        repeat-expr: descriptor_count
        if: (flags & 1) == 0
    instances:
      is_forwarding:
        value: (flags & 1) != 0
      fwd_addr:
        pos: base + 1
        type: s8
        if: (flags & 1) != 0
      table_end:
        value: ((base + 4 + (descriptor_count.as<s8> * 3)).as<s8>)

  # ------------------------------------------------------------------
  # Descriptor search + typed field read. Scans descriptors from the table
  # start (the instance is placed at base + 4) until the target field id is
  # found or the table is exhausted, then reads the value.
  # ------------------------------------------------------------------
  find_i32:
    params:
      - id: target
        type: u1
      - id: base
        type: s8
      - id: table_end
        type: s8
    seq:
      - id: entry
        type: descriptor
        repeat: until
        repeat-until: (entry.last.field_id == target) or (_io.pos >= table_end)
    instances:
      found:
        value: entry.last.field_id == target
      value:
        pos: base + entry.last.relative_offset.as<s8>
        type: s4
        if: entry.last.field_id == target

  find_addr:
    params:
      - id: target
        type: u1
      - id: base
        type: s8
      - id: table_end
        type: s8
    seq:
      - id: entry
        type: descriptor
        repeat: until
        repeat-until: (entry.last.field_id == target) or (_io.pos >= table_end)
    instances:
      found:
        value: entry.last.field_id == target
      value:
        pos: base + entry.last.relative_offset.as<s8>
        type: s8
        if: entry.last.field_id == target

  find_u8:
    params:
      - id: target
        type: u1
      - id: base
        type: s8
      - id: table_end
        type: s8
    seq:
      - id: entry
        type: descriptor
        repeat: until
        repeat-until: (entry.last.field_id == target) or (_io.pos >= table_end)
    instances:
      found:
        value: entry.last.field_id == target
      value:
        pos: base + entry.last.relative_offset.as<s8>
        type: u1
        if: entry.last.field_id == target

  find_u64:
    params:
      - id: target
        type: u1
      - id: base
        type: s8
      - id: table_end
        type: s8
    seq:
      - id: entry
        type: descriptor
        repeat: until
        repeat-until: (entry.last.field_id == target) or (_io.pos >= table_end)
    instances:
      found:
        value: entry.last.field_id == target
      value:
        pos: base + entry.last.relative_offset.as<s8>
        type: u8
        if: entry.last.field_id == target

  # ------------------------------------------------------------------
  # Known object layouts (schema 226/227). String payloads are addressed
  # through find_addr and materialized by the nav layer (UTF-16BE decode).
  # ------------------------------------------------------------------
  uuid_obj:
    doc: Two-long UUID object (Repeater tabs and groups).
    params:
      - id: base
        type: s8
    seq:
      - id: obj
        type: "compact_object(base)"
    instances:
      high:
        pos: base + 4
        type: "find_u64(0, base, obj.table_end)"
      low:
        pos: base + 4
        type: "find_u64(1, base, obj.table_end)"

  immutable_string:
    doc: Zv1/Zmju immutable string; field 0 points at a UTF-16BE char array.
    params:
      - id: base
        type: s8
    seq:
      - id: obj
        type: "compact_object(base)"
    instances:
      chars_addr:
        pos: base + 4
        type: "find_addr(0, base, obj.table_end)"

  mutable_string:
    doc: Zvp/Zmjj chunked mutable string (Repeater captions).
    params:
      - id: base
        type: s8
    seq:
      - id: obj
        type: "compact_object(base)"
    instances:
      length:
        pos: base + 4
        type: "find_i32(0, base, obj.table_end)"
      chunk_width:
        pos: base + 4
        type: "find_i32(2, base, obj.table_end)"
      chunks_addr:
        pos: base + 4
        type: "find_addr(3, base, obj.table_end)"

  direct_collection:
    doc: Zg_i/Zmex collection; logical size plus one backing address array.
    params:
      - id: base
        type: s8
    seq:
      - id: obj
        type: "compact_object(base)"
    instances:
      size:
        pos: base + 4
        type: "find_i32(0, base, obj.table_end)"
      backing_addr:
        pos: base + 4
        type: "find_addr(1, base, obj.table_end)"

  chunk_list:
    doc: Chunk list for Zwtw chunked collections.
    params:
      - id: base
        type: s8
    seq:
      - id: obj
        type: "compact_object(base)"
    instances:
      chunk_count:
        pos: base + 4
        type: "find_i32(0, base, obj.table_end)"
      chunk_array_addr:
        pos: base + 4
        type: "find_addr(1, base, obj.table_end)"

  chunked_collection:
    doc: Zwtw/Zmea chunked collection (Proxy history views, identity buckets).
    params:
      - id: base
        type: s8
    seq:
      - id: obj
        type: "compact_object(base)"
    instances:
      size:
        pos: base + 4
        type: "find_i32(0, base, obj.table_end)"
      chunk_size:
        pos: base + 4
        type: "find_i32(1, base, obj.table_end)"
      chunk_list_addr:
        pos: base + 4
        type: "find_addr(2, base, obj.table_end)"
      leading_offset:
        pos: base + 4
        type: "find_i32(3, base, obj.table_end)"

  project_root:
    doc: Schema-226/227 project root.
    params:
      - id: base
        type: s8
    seq:
      - id: obj
        type: "compact_object(base)"
    instances:
      install_id:
        pos: base + 4
        type: "find_addr(0, base, obj.table_end)"
      proxy_root_addr:
        pos: base + 4
        type: "find_addr(1, base, obj.table_end)"
      repeater_root_addr:
        pos: base + 4
        type: "find_addr(2, base, obj.table_end)"
      target_root_addr:
        pos: base + 4
        type: "find_addr(3, base, obj.table_end)"
      project_name:
        pos: base + 4
        type: "find_addr(6, base, obj.table_end)"
      project_identifier:
        pos: base + 4
        type: "find_addr(15, base, obj.table_end)"

  proxy_root:
    doc: Proxy root Zkx; fields 0 and 1 are chunked history views.
    params:
      - id: base
        type: s8
    seq:
      - id: obj
        type: "compact_object(base)"
    instances:
      history_all_addr:
        pos: base + 4
        type: "find_addr(0, base, obj.table_end)"
      history_unique_addr:
        pos: base + 4
        type: "find_addr(1, base, obj.table_end)"

  proxy_item:
    doc: Proxy history item Zp1u (descriptor Zdr); 15/18 are the raw exchange.
    params:
      - id: base
        type: s8
    seq:
      - id: obj
        type: "compact_object(base)"
    instances:
      request_addr:
        pos: base + 4
        type: "find_addr(15, base, obj.table_end)"
      request_alt1_addr:
        pos: base + 4
        type: "find_addr(16, base, obj.table_end)"
      request_alt2_addr:
        pos: base + 4
        type: "find_addr(17, base, obj.table_end)"
      response_addr:
        pos: base + 4
        type: "find_addr(18, base, obj.table_end)"
      response_alt1_addr:
        pos: base + 4
        type: "find_addr(19, base, obj.table_end)"
      response_alt2_addr:
        pos: base + 4
        type: "find_addr(20, base, obj.table_end)"

  repeater_root:
    doc: Repeater root; field 1 tabs, field 4 groups (direct collections).
    params:
      - id: base
        type: s8
    seq:
      - id: obj
        type: "compact_object(base)"
    instances:
      tabs_addr:
        pos: base + 4
        type: "find_addr(1, base, obj.table_end)"
      groups_addr:
        pos: base + 4
        type: "find_addr(4, base, obj.table_end)"

  repeater_tab:
    doc: Repeater tab (caption field 0, pairs field 2, current request field 4).
    params:
      - id: base
        type: s8
    seq:
      - id: obj
        type: "compact_object(base)"
    instances:
      caption_addr:
        pos: base + 4
        type: "find_addr(0, base, obj.table_end)"
      pairs_addr:
        pos: base + 4
        type: "find_addr(2, base, obj.table_end)"
      current_request_addr:
        pos: base + 4
        type: "find_addr(4, base, obj.table_end)"
      group_addr:
        pos: base + 4
        type: "find_addr(32, base, obj.table_end)"
      uuid_addr:
        pos: base + 4
        type: "find_addr(33, base, obj.table_end)"

  repeater_pair:
    doc: Zx4g message pair (descriptor Zdg); fields 2/3 are raw request/response.
    params:
      - id: base
        type: s8
    seq:
      - id: obj
        type: "compact_object(base)"
    instances:
      request_addr:
        pos: base + 4
        type: "find_addr(2, base, obj.table_end)"
      response_addr:
        pos: base + 4
        type: "find_addr(3, base, obj.table_end)"

  repeater_group:
    doc: Repeater tab group.
    params:
      - id: base
        type: s8
    seq:
      - id: obj
        type: "compact_object(base)"
    instances:
      name_addr:
        pos: base + 4
        type: "find_addr(0, base, obj.table_end)"
      color_id:
        pos: base + 4
        type: "find_u8(1, base, obj.table_end)"
      expanded:
        pos: base + 4
        type: "find_u8(2, base, obj.table_end)"
      index:
        pos: base + 4
        type: "find_i32(3, base, obj.table_end)"
      uuid_addr:
        pos: base + 4
        type: "find_addr(4, base, obj.table_end)"

  target_root:
    doc: Shared Target/Scanner indexes Zg70; field 3 is the identity index.
    params:
      - id: base
        type: s8
    seq:
      - id: obj
        type: "compact_object(base)"
    instances:
      identity_index_addr:
        pos: base + 4
        type: "find_addr(3, base, obj.table_end)"

  identity_index:
    doc: Zpt2 identity index; field 2 expected size, field 3 bucket collection.
    params:
      - id: base
        type: s8
    seq:
      - id: obj
        type: "compact_object(base)"
    instances:
      expected_size:
        pos: base + 4
        type: "find_i32(2, base, obj.table_end)"
      buckets_addr:
        pos: base + 4
        type: "find_addr(3, base, obj.table_end)"

  bucket:
    doc: Identity index bucket; field 0 size, field 1 hash/key/value tuples.
    params:
      - id: base
        type: s8
    seq:
      - id: obj
        type: "compact_object(base)"
    instances:
      size:
        pos: base + 4
        type: "find_i32(0, base, obj.table_end)"
      tuples_addr:
        pos: base + 4
        type: "find_addr(1, base, obj.table_end)"

  target_node:
    doc: Site Map hierarchy node; field 33 references message metadata Zfkk.
    params:
      - id: base
        type: s8
    seq:
      - id: obj
        type: "compact_object(base)"
    instances:
      message_addr:
        pos: base + 4
        type: "find_addr(33, base, obj.table_end)"

  site_message:
    doc: Zfkk message metadata (descriptor Zkp); fields 0/1 raw request/response.
    params:
      - id: base
        type: s8
    seq:
      - id: obj
        type: "compact_object(base)"
    instances:
      request_addr:
        pos: base + 4
        type: "find_addr(0, base, obj.table_end)"
      response_addr:
        pos: base + 4
        type: "find_addr(1, base, obj.table_end)"
