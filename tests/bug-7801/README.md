# Bug 7801 verification suite

Regression tests for Redmine issue #7801: `byte_extract` and `byte_math` values
consumed outside the buffer that produced them. Suricata caches byte keyword
values on the transaction's `DetectEngineState`, so a later inspection - another
buffer, or the other direction - reads the value its own transaction produced
rather than whatever another transaction left in `det_ctx->byte_values`.

Every test except `bug-7801-07` fails on a build without the change, as a missed
alert, as an alert on the transaction, connection or signature that should not
match, or as a rule that loads when it should not. Most need the values kept on
the transaction; 13 and 24 to 26 need what the change does to variable numbering,
and 19 needs unset variables to read 0. `bug-7801-02` also needs the `isdataat`
fix from Redmine #9086, tested in `tests/bug-9086`: per-signature numbering
gives its `sum_val` the `local_id` 1 that fix is about. `bug-7801-07` replays
the rule and pcap from Redmine #1412, which match either way, so that case stays
covered. "Without" below means measured on such a build.

## Bidirectional tests with a pipelined spoiler (`=>`)

HTTP/1.1 pipelining puts several transactions in one flow. All toserver buffers
are inspected before any toclient buffer, so a spoiler transaction's producer
runs before the first transaction's consumer and overwrites its value.

- `bug-7801-01`: `http.uri` (toserver) -> `http.stat_code` (toclient) via `byte_test`. Spoiler extracts 99, real TX extracts 05; `byte_test: 48 > val`.
- `bug-7801-02`: `http.uri` (toserver) `byte_extract` (`a_val`, slot 0) plus `byte_math` (`sum_val`, slot 1) -> `http.stat_msg` (toclient) via negated `isdataat`. The spoiler clobbers both slots.

## Pipelined multi-transaction tests (`=>`)

Two requests are sent before any response, creating two transactions that share
one `det_ctx`. All toserver inspections finish before toclient inspection
begins, so the second transaction's byte values overwrite the first's.

- `bug-7801-03`: Spoiler first (99), real TX second (05). `http.uri` -> `http.stat_code` via `byte_test`. Without: 2 alerts, the spoiler reads 05 and matches too. With: 1.
- `bug-7801-04`: Real TX first (05), spoiler second (99). Same buffers. Without: 0 alerts. With: 1.
- `bug-7801-05`: False positive prevention. TX1 extracts 01 and must not alert, TX2 extracts 08 and must. `http.uri` -> `http.stat_msg` via negated `isdataat`. Without: 2 alerts. With: 1, and the check pins it to TX2's URL.
- `bug-7801-06`: `byte_math` producer. TX1 base=3 total=5 alerts, TX2 base=40 total=70 is the spoiler. Without: 0 alerts. With: 1.

## Two kinds of producer in one rule (`=>`)

- `bug-7801-13`: One transaction, no spoiler. `byte_extract` in `http.uri`
  produces `uri_val`, `byte_math` in `http.stat_code` produces `code_val`, and
  `file.data` checks `uri_val`. Both keywords take their `local_id` from one
  counter per signature. While each keyword type counted its own, the first
  `byte_extract` and the first `byte_math` in a rule shared slot 0 and
  `code_val` overwrote `uri_val`: 0 alerts. With distinct slots: 1.

## Multi-pass toclient restore (`=>`)

Two toclient buffers at different progress levels (`http.stat_code` at
`RESPONSE_LINE`, `file.data` at `RESPONSE_BODY`) make the engine run two
toclient passes per transaction, so each transaction's values are loaded twice.
The values have to be copied out of the transaction's entry each time: handing
the entry's storage to the thread on the first pass leaves nothing for the
second.

- `bug-7801-08`: Two pipelined transactions, both must match (`count: 2`).
  `http.uri` (toserver) -> `http.stat_code` plus `file.data` (toclient) via
  `byte_test` in string mode. TX1 extracts 11 and its body yields 22; TX2
  extracts 88 and its body yields 99. Without: 1 alert, TX1 compares its 22 with
  TX2's 88. With: 2.

## Original Redmine #1412 case (`->`)

- `bug-7801-07`: The rule and pcap from
  https://redmine.openinfosecfoundation.org/issues/1412. Unidirectional
  (`flow:to_client`). `byte_extract` in `http_raw_header` takes the
  `Content-Length` value (11); `byte_test` in `file_data` compares against it
  little-endian. One transaction, cross-buffer within one direction.

## Unidirectional multi-packet tests (`->`)

A unidirectional rule's producer and consumer can sit at different transaction
progress levels (`http.stat_code` at `RESPONSE_LINE`, `file.data` at
`RESPONSE_BODY`). The producer fires on one packet and the consumer on a later
one; any other connection the same thread inspects in between overwrites
`det_ctx->byte_values`. These tests run with `--runmode=single` so both
connections share a thread, and the first connection carries a toclient packet
between its headers and the other connection: acked data is inspected on the
next packet in its direction, and without that packet the headers would first be
inspected together with the body.

- `bug-7801-09`: Missed detection via `byte_extract`. Conn1's 200 response
  arrives in two packets: headers first (`code_val=200`), body `"200"` second
  (`byte_test` checks `"200" == code_val`). A Conn2 spoiler (404, body `"000"`)
  lands between them and sets `code_val=404`. Without: 0 alerts. With: 1.
- `bug-7801-10`: Same structure with `byte_math` as the producer, covering the
  `DETECT_BYTEMATH` save path. Status `"200"` -> `200+200=400`, body `"400"`.
  The spoiler's `"404"` gives 604. Without: 0 alerts. With: 1.
- `bug-7801-11`: False positive prevention. Conn1 gets a 404 (`code_val=404`)
  then body `"200"`, so it must not alert. Conn2 (200, body `"200"`) lands
  between Conn1's two packets and sets `code_val=200`. Without: 2 alerts.
  With: 1, and the check pins it to Conn2's addresses.
- `bug-7801-12`: `byte_extract` (`base`, slot 0) and `byte_math` (`total`, slot
  1) in one unidirectional rule; both slots must survive across packets. Status
  `"200"` -> base 200, total 400; body `"400"`. The spoiler's `"404"` gives base
  404 and total 808. Without: 0 alerts. With: 1.

## Two signatures on one transaction

Every signature numbers its byte variables from 0. Rule A extracts a value and
matches on it; rule B writes its own value to the same `local_id` on the same
transaction and can never match the pcap. Values are kept per signature, so
neither sees the other's. The lower sid is inspected first, so each pcap gets
both orders. With the change A alerts once and B never.

- `bug-7801-14`: `=>` rules on the pcap from `bug-7801-01`, A then B. Without: A
  misses.
- `bug-7801-15`: The same pair, B then A. Without: A misses.
- `bug-7801-16`: `->` rules on the split-packet pcap from `bug-7801-09`, A then
  B; producers run on the headers packet, consumers on the body packet. Without:
  A misses.
- `bug-7801-17`: The same pair, B then A. Without: B reads A's value and alerts.

## Other consumers, another protocol, and the edges

- `bug-7801-18`: A value produced on a pass that resumes stored state. A `=>`
  rule matches `http.uri` on the request, which stores inspect state, produces
  `code_val` in `http.stat_code` when the response headers arrive, and checks
  `file.data` when the body does; a second connection produces 404 in between.
  In tests 09 to 12 the producer runs on the pass that first stores state; here
  the state exists already, so the value has to be kept when it is updated.
  Runs with `--runmode=single`. Without: 0 alerts. With: 1.
- `bug-7801-19`: A variable that has not been produced reads 0. Rule 1 reads `v`
  in `http.stat_code`, inspected first because it holds the fast pattern, asks
  for 200 < `v`, and produces `v` later in `file.data`. Rule 2 extracts 999 into
  the same `local_id`. Without: rule 1 finds that 999 on the second transaction
  and alerts. With: rule 1 never alerts.
- `bug-7801-20`: `byte_jump` with its offset taken from `http.uri`, used in
  `file.data`. Pipelined spoiler carries offset 0. Without the values: 0 alerts.
  With them: 1, on the transaction carrying offset 2.
- `bug-7801-21`: `content` with `distance` taken from `http.uri`, used in
  `file.data`. "ZZ" sits exactly 3 bytes after "AA"; the pipelined spoiler
  carries 1. Without the values: 0 alerts. With them: 1.
- `bug-7801-22`: HTTP/2, on the pcap from `http2-keywords`. A browser requests
  five static files together on streams 3 to 11, so all five requests are
  inspected before the first response. `v` is the ninth byte of the path and the
  rule alerts when `n`, the first byte of the `server` header, is greater; only
  stream 7 (`_static/underscore.js`, `u`) must stay quiet. Without the values
  stream 7 reads a later stream's byte and alerts: 6 alerts. With them: 5.
- `bug-7801-23`: Three signatures write `local_id` 0 on each of two pipelined
  transactions. A wants the small URI value, C the large one, B never matches.
  Exactly two alerts: A on the 05 transaction, C on the 99 one.
- `bug-7801-24`: A rule with 257 byte variables fails to load (`exit-code: 1`).
  `local_id` is a `uint8_t`; the count used to wrap and the rule loaded.
- `bug-7801-25`: A rule with 256 byte variables loads, and the last one, with
  `local_id` 255, is read in the other direction.
- `bug-7801-26`: The packet path. `byte_extract` in `udp.hdr` and `byte_math` in
  `ipv4.hdr` feed a `byte_test` on the payload of one UDP packet. There is no
  transaction, so this covers only the per-signature numbering: with a shared
  slot the TTL overwrote the UDP length and the rule missed.

- `bug-7801-27`: Values kept when a file rule can't match a file. One multipart
  POST carries `a.txt` (6 bytes) and `b.bin` (20 bytes). Rule 2 takes `v` from
  `http.uri`, wants `filesize:>10`, and checks `file.data` against `v`. The first
  segment holds the request headers, all of `a.txt` and the boundary line that
  closes it, so the rule's first pass already reaches the file engine, which
  reports that the signature can't match this file. State is stored for that in
  case another file follows, and `v` has to be kept with it: when `b.bin`
  arrives `http.uri` is marked done. Rule 1 is inspected first and writes 45 to
  the same `local_id` from `b.bin`. Without the value: rule 2 compares 42 with
  45, no alert. With it: 1.

## What these tests leave out

On the packet path a consumer cannot be inspected before its producer: the
parser requires the producer to come first in the rule, and the packet engines
run in rule order. So no rule can show a packet-path variable being read before
it was written, and no test here tries to.

A `lua` script reading a byte variable is not covered either. `lua` does not
bind to a sticky buffer, it runs with the packet matches before any app-layer
producer, so a cross-buffer Lua consumer cannot be written.

Two of the four places where values are kept have a test (18 and 27) and a third
is what every other test goes through. The fourth, a file rule that fully
matches on its first pass, has none: once a rule has fully matched every
consumer has run, and a new file only reopens the file engine, which reads no
byte variable.

A ruleset reload in the middle of a transaction, multi-tenant setups and `<>`
rules are not covered; the first two cannot be driven from a pcap.

Two further cases moved to `tests/bug-9087`, on the `9087/1` branch. They use a
`=>` rule whose toserver buffer has a higher progress value than its toclient
one, and such a rule alerts on its toserver half alone: the toclient consumer is
never inspected and the kept value never read. That is Redmine #9087, a
match-accounting defect in `DetectRunTxInspectRule()`, not a byte value defect,
and the tests land with its fix.

## Structure

Each directory holds `test.rules` and a `test.yaml` spec, and most an `input.pcap`.
Tests 14 to 17 and 22 to 25 have no pcap of their own and name another test's in
`test.yaml`. Every other test except `bug-7801-07`, which reuses the pcap
attached to Redmine #1412, also ships the `gen_pcap.py` that produced its pcap, so the packet
contents can be read and regenerated. This file is the only description of the
individual tests.
