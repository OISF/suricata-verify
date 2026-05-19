# Feature 7847: XOR transform with variable keys

Tests for using the `var <nbytes> <offset>` syntax in the `xor` transform,
including the `offset` parameter.

## Test cases

### Positive tests

- **01** — 1-byte key at body offset 0, XOR starts at offset 1
  (`xor:offset 1,var 1 0`); 1 alert
- **02** — Same rule as 01 but content match absent in decoded data; 0 alerts
- **03** — 4-byte key at body offset 0, XOR starts at offset 4
  (`xor:offset 4,var 4 0`); 1 alert
- **06** — Extra whitespace in offset syntax (`offset   1,  var 1 0`) is
  accepted; 1 alert
- **10** — `xor` preceded by a `content` keyword on the same buffer; 1 alert
- **12** — Two rules with different variable key locations both alert
  independently; verifies that buffer identity is per key location so each
  rule decodes with its own key; 2 alerts
- **13** — Variable key location (offset 200) is beyond the buffer length;
  transform silently skips and content is not matched; 0 alerts
- **14** — Variable key on `http.uri` rather than `http.request_body`;
  1-byte key at URI offset 1, XOR starts at offset 2; 1 alert
- **15** — Static hex key (`xor:"42"`) and variable key (`xor:offset 1,var 1 0`)
  on the same buffer in two separate rules; verifies that static-key and
  variable-key rules coexist and each fires independently; 2 alerts

### Error tests (rule load failures)

- **04** — Variable key with zero nbytes (`var 0 0`); Suricata exits with code 1
- **05** — Variable key with missing offset argument (`var 1`); exits with code 1
- **07** — Invalid offset value (`offset abc`); exits with code 1
- **08** — Offset keyword without a comma or key (`offset 1`); exits with code 1
- **09** — Offset keyword with empty offset value (`offset ,"xor_key"`);
  exits with code 1
- **11** — Empty quoted hex key (`xor:""`); exits with code 1

## PCAPs

Tests **01, 02, 04–11, 13, 15** share the PCAP from `detect-xor-key-01`:
an HTTP POST whose body has a 1-byte XOR key (0x42) at offset 0 followed by
`"password=secret"` encoded with that key.

Test **03** has its own PCAP: an HTTP POST whose body has a 4-byte XOR key
(`0d0ac8ff`) at offset 0 followed by `"password=supersecret"` encoded with
that key.

Test **12** has its own PCAP: an HTTP POST whose 12-byte body contains two
independently keyed sections — a 1-byte key (0x42) at offset 0 with `"hello"`
encoded at offsets 1–5, and a 1-byte key (0x37) at offset 6 with `"world"`
encoded at offsets 7–11.

Test **14** has its own PCAP: an HTTP GET request whose URI is
`/[key_byte][encoded_data]` — a 1-byte key (0x30, ASCII `'0'`) at URI offset 1
followed by `"path"` XOR-encoded with that key at offsets 2–5.
