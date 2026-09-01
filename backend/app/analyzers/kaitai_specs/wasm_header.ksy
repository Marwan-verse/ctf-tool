meta:
  id: forenscope_webassembly
  title: Bounded WebAssembly section table
  endian: le
seq:
  - id: magic
    contents: [0x00, 0x61, 0x73, 0x6d]
  - id: version
    type: u4
  - id: sections
    type: section
    repeat: eos
types:
  section:
    seq:
      - id: section_id
        type: u1
      - id: payload_size
        type: vlq_base128_le
      - id: payload
        size: payload_size.value
  vlq_base128_le:
    seq:
      - id: groups
        type: group
        repeat: until
        repeat-until: not _.has_next
    instances:
      value:
        value: groups[0].value + (groups.size > 1 ? groups[1].value << 7 : 0) + (groups.size > 2 ? groups[2].value << 14 : 0) + (groups.size > 3 ? groups[3].value << 21 : 0) + (groups.size > 4 ? groups[4].value << 28 : 0)
  group:
    seq:
      - id: raw
        type: u1
    instances:
      has_next:
        value: (raw & 0x80) != 0
      value:
        value: raw & 0x7f
