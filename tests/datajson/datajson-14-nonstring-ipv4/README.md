# datajson-14-nonstring-ipv4

Regression test: NULL-pointer dereference in the JSON/NDJSON dataset loader
(`src/datasets-context-json.c`) when a `value_key` points at a non-string
JSON node.

This case feeds a **ipv4** dataset an entry whose `value` is `null`
(not a string). `json_string_value()` returns NULL and the typed handler used
it without a check, crashing with SIGSEGV at dataset load.

PCAP: reused from `datajson-01-ip` (load-time crash, packets irrelevant).
Ticket: https://redmine.openinfosecfoundation.org/issues/8624
