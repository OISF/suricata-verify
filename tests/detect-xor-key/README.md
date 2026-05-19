# Feature 7847: XOR transform with byte_extract variable keys

Tests for using `byte_extract` variables as XOR keys in the `xor`
transform, including the `offset` parameter.

## Test cases

### Positive tests

- **01** — 1-byte key extracted at offset 0, XOR starts at offset 1
- **02** — Same as 01 but content match is absent in the decrypted data (0 alerts)
- **03** — 4-byte key extracted at offset 0, XOR starts at offset 4
- **06** — Extra whitespace in offset syntax (`offset   1,  "xor_key"`)
- **10** — `byte_extract` and `xor` separated by a `content` keyword (non-adjacent)
- **12** — Two rules on the same buffer with different variable key locations both alert;
  verifies that each variable key location produces a distinct `DetectBufferType` so each
  rule's transform is applied independently

### Error tests (rule load failures)

- **04** — Nonexistent variable name
- **05** — `byte_extract` with relative offset (not supported)
- **07** — Invalid offset value (`offset abc`)
- **08** — Offset specified without a key (`offset 1` with no comma/key)
- **09** — Offset keyword with empty value (`offset ,"xor_key"`)
- **11** — Empty quoted hex key (`xor:""`) is rejected at rule load time

## PCAPs

Tests 01, 02, 05–11 share the same PCAP: an HTTP POST with a 1-byte
XOR key (0x42) at offset 0 followed by `"password=secret"` encrypted
with that key.

Test 03 uses a separate PCAP with a 4-byte XOR key (`0d0ac8ff`) at
offset 0 followed by `"password=supersecret"` encrypted with that key.

Test 12 uses its own PCAP: an HTTP POST whose 12-byte body contains two
independently keyed sections — a 1-byte key (0x42) at offset 0 with
`"hello"` XOR-encoded at offsets 1–5, and a second 1-byte key (0x37) at
offset 6 with `"world"` XOR-encoded at offsets 7–11.
