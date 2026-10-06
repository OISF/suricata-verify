# Issue 7847: XOR transform with a byte_extract/byte_math variable key

Tests for the `xor:var <name> [<nbytes>]` syntax, where the XOR key is read
from a `byte_extract` or `byte_math` variable at inspection time rather than
given as a literal hex string. The variable is produced on a buffer inspected
before the transformed buffer (here `http.uri`), and consumed when the
transformed buffer (`http.request_body`) is built.

## Test cases

### Positive tests

- **01** — 1-byte key extracted from the URI with `byte_extract:1,1,xkey` and
  used to decode the body (`xor:var xkey`, width defaults to the read width);
  1 alert
- **02** — Same rule as 01 but the content is absent from the decoded data;
  0 alerts (confirms the match depends on correct decoding)
- **03** — Key computed with `byte_math` (no inherent width) and an explicit
  width (`xor:var xkey 1`); 1 alert
- **04** — A static-key rule (`xor:"43"`) and a variable-key rule
  (`xor:var xkey`) on the same buffer both fire independently; verifies the
  two key kinds get distinct inspection buffers; 2 alerts
- **19** — An in-buffer `extract`-key rule (`xor:offset 1,extract 1 0`) and a
  `byte_extract` `var`-key rule (`xor:var xkey`) on the same buffer both fire;
  verifies the two variable-key kinds get distinct inspection buffers; 2 alerts
- **05** — 2-byte key extracted with `byte_extract:2,1,xkey`; `xor:var`
  renders it big-endian, exercising the multi-byte key path; 1 alert
- **12** — Variable key combined with a decode offset
  (`xor:offset 4,var xkey`): a 4-byte plaintext header is copied through
  unchanged and decoding starts after it; 1 alert
- **13** — Explicit width narrower than the variable's natural width
  (`byte_extract:2,0,xkey; xor:var xkey 1`): the override selects the low byte
  of the 2-byte value (`0x43`), which decodes the body; without the override
  the natural 2-byte key would not match; 1 alert
- **14** — The variable resolves to the wrong key value
  (`byte_extract:1,2,xkey` reads `0x44` instead of `0x43`): decoding produces
  garbage and the content is not found; 0 alerts (confirms the extracted value
  drives decoding)
- **16** — String-mode `byte_extract` with an explicit width
  (`byte_extract:2,1,xkey,string,hex; xor:var xkey 1`): the ASCII text `"43"`
  parses to the value `0x43`, which decodes the body; 1 alert
- **17** — Little-endian `byte_extract` (`byte_extract:2,1,xkey,little`): the
  on-wire bytes `0x41 0x42` parse to `0x4241`, which `xor:var` renders
  big-endian to the key `[0x42, 0x41]`, confirming the key is big-endian
  regardless of the keyword's endianness; 1 alert

### Engine-analysis test

- **11** — Two rules with a trailing `content`, one static-key
  (`xor:"43"`) and one variable-key (`xor:var xkey`). Engine analysis confirms
  the static-key rule is prefiltered (its content becomes the MPM), while the
  variable-key rule is disqualified from prefilter and gets no MPM, since a
  runtime key cannot be precomputed at load time.

### Error tests (rule load failures, exit code 1)

- **06** — `byte_math` key without an explicit width: a computed value has no
  inherent width, so the width is required
- **07** — `xor:var` naming a variable that no `byte_extract`/`byte_math`
  keyword defines
- **08** — Explicit width greater than 8 (`xor:var xkey 9`)
- **09** — Explicit width of zero (`xor:var xkey 0`)
- **10** — Non-numeric width (`xor:var xkey wide`)
- **15** — String-mode `byte_extract` without an explicit width
  (`byte_extract:2,1,xkey,string,hex; xor:var xkey`): a string-mode read count
  is a number of characters, not a value width, so the width is required
- **18** — `extract` and `var` are mutually exclusive key sources; combining
  them in one `xor` transform (`xor:extract 1 0 var xkey`, and the reverse
  ordering) must fail to load

## PCAPs

Tests **01-04**, **06-10**, **13** and **14** share the PCAP from
`detect-xor-var-key-01`: an HTTP POST whose URI is `/CD/app` — byte at offset 1
is the key (`0x43`, `'C'`) and byte at offset 2 is the key + 1 (`0x44`, `'D'`,
used by the `byte_math` test) — and whose body is `"login SECRET token=1"`
encoded with the 1-byte key `0x43`.

Test **05** has its own PCAP: an HTTP POST whose URI is `/AB/app` — bytes at
offsets 1-2 are the 2-byte key (`0x41 0x42`, `'A','B'`) — and whose body is
`"data SECRET here"` encoded with that repeating 2-byte key.

Test **12** has its own PCAP: the same `/CD/app` URI, but the body is a 4-byte
plaintext header `"HDR:"` followed by `"login SECRET token=1"` encoded with the
1-byte key `0x43`, so the decode offset skips the header.

Tests **16** and **17** have their own PCAPs: test 16 uses the URI `/43/app`
(the ASCII text `"43"` at offsets 1-2) with the body encoded by `0x43`; test 17
uses the URI `/AB/app` (`0x41 0x42` at offsets 1-2) with the body encoded by the
big-endian rendering `0x42 0x41` of the little-endian-extracted value.

Test **19** has its own PCAP: the same `/CD/app` URI, but the body is the key
byte `0x43` followed by `"login SECRET token=1"` encoded with `0x43`, so both
the in-buffer `extract` rule and the `byte_extract` `var` rule decode it.

Test **11** uses no PCAP (`--engine-analysis` only).
