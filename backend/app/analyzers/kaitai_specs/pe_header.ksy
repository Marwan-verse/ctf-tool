meta:
  id: remanence_pe_header
  title: Bounded Portable Executable header
  endian: le
seq:
  - id: mz_magic
    contents: [0x4d, 0x5a]
  - id: dos_stub_prefix
    size: 58
  - id: pe_offset
    type: u4
  - id: before_pe
    size: pe_offset - 64
  - id: pe_magic
    contents: [0x50, 0x45, 0x00, 0x00]
  - id: machine
    type: u2
  - id: section_count
    type: u2
  - id: timestamp
    type: u4
  - id: symbol_table_offset
    type: u4
  - id: symbol_count
    type: u4
  - id: optional_header_size
    type: u2
  - id: characteristics
    type: u2
  - id: optional_header
    size: optional_header_size
  - id: sections
    type: section
    repeat: expr
    repeat-expr: section_count
types:
  section:
    seq:
      - id: name
        size: 8
      - id: virtual_size
        type: u4
      - id: virtual_address
        type: u4
      - id: raw_size
        type: u4
      - id: raw_offset
        type: u4
      - id: relocation_offset
        type: u4
      - id: line_number_offset
        type: u4
      - id: relocation_count
        type: u2
      - id: line_number_count
        type: u2
      - id: characteristics
        type: u4
