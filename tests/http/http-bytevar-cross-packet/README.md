# http-bytevar-cross-packet

A byte_extract value must survive the packet boundary for content
modifiers (depth/offset/distance/within/isdataat), which read the
slot value without the "written this run" marker - the behaviour
before the marker existed.

One signature, two sticky-buffer sections on separate packets: the
headers section (packet 1) extracts the "1" byte of
"Content-Length: 100" (ASCII 49) into v1; the body section (packet
2) matches "MARK" (at 3..6) at depth:v1. The body section is
inspected in a later detect run, after the packet boundary - it
reads the extracted value through the slot, not a fresh
extraction: with the surviving 49 it matches and the signature
fires once; when the value is zeroed at the boundary (the bug),
depth:v1 is 0 and the signature does not alert at all.

byte_extract variables are per-signature, which is why both sections
live in one alert.

make-pcap.py ships with the test and regenerates test.pcap (scapy).

Ticket: #9057.
