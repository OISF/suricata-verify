# Test Purpose

Test that `byte_test` with `string` and a byte count of 0 converts only the
digits inside the buffer it inspects.

`udp.hdr` is 8 bytes and the payload follows it in the packet. The checksum
field at offset 6 holds `12` and the payload is `345x`, so a conversion with
no length bound reads `12345`. With the bound, offset 6 converts `12` (`sid:1`
alerts, `sid:2` does not) and offset 8 has nothing left to convert (`sid:3`
does not alert).

`sid:4` and `sid:5` take the count from a `byte_extract` variable that reads
the `0` at offset 3, so the packet chooses the count of 0. `sid:6` uses a
2-byte count, which should alert.

A stats check confirms all 6 rules load. A missing alert then means the
rule did not match.

## PCAP

`input.pcap` is crafted by `craft-pcap.py`. It is shared with `bug-9089-02` and
`bug-9089-03`.

## Redmine ticket

https://redmine.openinfosecfoundation.org/issues/9089
