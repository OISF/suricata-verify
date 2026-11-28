# Test Purpose

Test that `byte_extract` with `string` and a byte count of 0 converts only the
digits inside the buffer it inspects, and leaves the read position at the end
of those digits.

The pcap is the one from `bug-9089-01`: `udp.hdr` ends in the digits `12` and
the payload behind it is `345x`. With the bound, offset 6 extracts `12` and
leaves the read position at offset 8, the end of the buffer. `sid:1` checks
both by comparing the extracted value with the 2 bytes before the read
position. A conversion with no length bound extracts `12345` and moves the
read position past the end of the buffer. At offset 8 nothing is left to
convert, so `sid:2` does not alert; without the bound it extracts `345`.

`sid:3` extracts 2 bytes, which should alert.

A stats check confirms all 3 rules load. A missing alert then means the
rule did not match.

## Redmine ticket

https://redmine.openinfosecfoundation.org/issues/9089
