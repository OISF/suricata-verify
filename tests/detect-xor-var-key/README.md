# Issue 7847: XOR transform with a byte_extract/byte_math variable key

Tests for the `xor:var <name> [<width>]` syntax, where the XOR key is read
from a `byte_extract` or `byte_math` variable at inspection time instead of
given as a literal hex string. The variable is set on a buffer inspected
before the transformed buffer (here `http.uri`), and used when the
transformed buffer (`http.request_body`) is built.

## Test cases

### Positive tests

- 01: 1-byte key extracted from the URI with `byte_extract:1,1,xkey` and used
  to decode the body (`xor:var xkey`, width defaults to the read width);
  1 alert.
- 02: Same rule as 01, but the content is absent from the decoded data;
  0 alerts, so the match depends on correct decoding.
- 03: Key computed with `byte_math` and given an explicit width
  (`xor:var xkey 1`); 1 alert.
- 04: A static-key rule (`xor:"43"`) and a variable-key rule (`xor:var xkey`)
  on the same buffer both fire; 2 alerts.
- 05: 2-byte key extracted with `byte_extract:2,1,xkey`; `xor:var` uses it
  most significant byte first; 1 alert.
- 12: Variable key combined with a decode offset (`xor:offset 4,var xkey`):
  a 4-byte plaintext header is copied through unchanged and decoding starts
  after it; 1 alert.
- 13: Explicit width narrower than the default width
  (`byte_extract:2,0,xkey; xor:var xkey 1`): the width selects the low byte
  of the 2-byte value (`0x43`), which decodes the body; the default 2-byte
  key would not match; 1 alert.
- 14: The variable holds the wrong key value (`byte_extract:1,2,xkey` reads
  `0x44` instead of `0x43`): the body decodes to garbage and the content is
  not found; 0 alerts, so the extracted value drives decoding.
- 16: `byte_extract` with `string` and an explicit width
  (`byte_extract:2,1,xkey,string,hex; xor:var xkey 1`): the text `"43"`
  parses to the value `0x43`, which decodes the body; 1 alert.
- 17: Little-endian `byte_extract` (`byte_extract:2,1,xkey,little`): the
  bytes `0x41 0x42` parse to `0x4241`, which `xor:var` uses as the key
  `0x42 0x41`, most significant byte first; 1 alert.
- 19: An in-buffer `extract` key rule (`xor:offset 1,extract 1 0`) and a
  `byte_extract` `var` key rule (`xor:var xkey`) on the same buffer both
  fire; 2 alerts.
- 20: Two `var` key rules on the same buffer with different keys, read from
  URI offsets 1 and 2. Both variables use slot 0, and each rule must decode
  the body with its own key; 2 alerts, one per rule.
- 22: The request body arrives in a later TCP segment than the headers, so
  the URI is inspected on an earlier packet. The value `byte_extract` stored
  is still there when the body is decoded; 1 alert.

### Engine-analysis test

- 11: Three rules. The static-key rule (`xor:"43"`) gets its body content as
  the fast pattern. The variable-key rule with only a body content gets no
  fast pattern, because its key variable is set during rule inspection,
  after prefilter. The variable-key rule that also has a `http.uri` content
  gets that content as the fast pattern.

### Error tests (rule load failures, exit code 1)

- 06: `byte_math` key without an explicit width.
- 07: `xor:var` naming a variable that no `byte_extract` or `byte_math`
  keyword defines.
- 08: Explicit width greater than 8 (`xor:var xkey 9`).
- 09: Explicit width of zero (`xor:var xkey 0`).
- 10: Non-numeric width (`xor:var xkey wide`).
- 15: `byte_extract` with `string` and no explicit width
  (`byte_extract:2,1,xkey,string,hex; xor:var xkey`): with `string` the read
  count is a number of characters, so the width is required.
- 18: `extract` followed by `var` in one `xor` transform
  (`xor:extract 1 0 var xkey`).
- 21: `var` followed by `extract` in one `xor` transform
  (`xor:var xkey extract 1 0`).
- 23: `xor:var` naming a `byte_extract` variable set on the packet payload;
  the error says the variable is on the packet payload.

## PCAPs

Tests 01-04, 06-10, 13-15, 18, 21 and 23 use the PCAP from
`detect-xor-var-key-01`: an HTTP POST whose URI is `/CD/app` (offset 1 holds
the key `0x43`, `'C'`, and offset 2 holds `0x44`, `'D'`, used by the
`byte_math` test) and whose body is `"login SECRET token=1"` encoded with the
1-byte key `0x43`.

Test 05 has its own PCAP: an HTTP POST whose URI is `/AB/app` (offsets 1-2
hold the 2-byte key `0x41 0x42`) and whose body is `"data SECRET here"`
encoded with that repeating 2-byte key.

Test 12 has its own PCAP: the same `/CD/app` URI, but the body is a 4-byte
plaintext header `"HDR:"` followed by `"login SECRET token=1"` encoded with
`0x43`, so the decode offset skips the header.

Tests 16 and 17 have their own PCAPs: test 16 uses the URI `/43/app` (the
text `"43"` at offsets 1-2) with the body encoded by `0x43`; test 17 uses the
URI `/AB/app` (`0x41 0x42` at offsets 1-2) with the body encoded by
`0x42 0x41`.

Test 19 has its own PCAP: the same `/CD/app` URI, but the body is the key
byte `0x43` followed by `"login SECRET token=1"` encoded with `0x43`, so both
the in-buffer `extract` rule and the `byte_extract` `var` rule decode it.

Test 20 has its own PCAP: the same `/CD/app` URI, with the body
`"login SECRET "` encoded with `0x43` followed by `"OTHER"` encoded with
`0x44`.

Test 22 has its own PCAP: the same request as test 01, with the headers and
the body sent in two TCP segments.

Test 11 uses no PCAP (`--engine-analysis` only).
