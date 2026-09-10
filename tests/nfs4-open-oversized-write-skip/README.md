# NFSv4 compound scanner: OPEN skip layout

Regression test for the OPEN skip in the partial-compound scanner. The
skip had to mirror the full parser's open4args layout (20 fixed bytes
before the owner string); a 4-byte offset desyncs the scan on crafted
owners, turning the oversized-WRITE rejection into a malformed rejection
(or unbounded buffering toward the record claim).

Pcap: a small complete v4 GETATTR exchange (attach), then a partial v4
COMPOUND record [OPEN (open_type NONE, claim NONE), WRITE (17 MiB claim)]
claiming 4196 bytes of which only the compound is present.
