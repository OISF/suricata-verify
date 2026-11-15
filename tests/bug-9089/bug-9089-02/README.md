# Test Purpose

Test that `byte_jump` with `string` and a byte count of 0 converts only the
digits inside the buffer it inspects.

The pcap is the one from `bug-9089-01`: `udp.hdr` ends in the digits `12` and
the payload behind it is `345x`. With the bound, offset 6 converts `12`, and
`from_beginning` with `post_offset -10` lands at offset 2, where
`content:"A0"; within:2;` matches (`sid:1`). A conversion with no length
bound reads `12345` and jumps out of the buffer. At offset 8 nothing is left
to convert, so `sid:2` does not alert; without the bound it reads `345` and
lands at offset 0.

`sid:3` takes the count from a `byte_extract` variable that reads the `0` at
offset 3. `sid:4` uses a 2-byte count, which should alert.

`sid:5` and `sid:6` jump relative to a `content` match. After `12` nothing is
left, so `sid:5` does not alert; without the bound it reads `345` and lands
at offset 5. After the `0x0c` byte at offset 5, `sid:6` converts `12`, steps
over those 2 digits, and with `post_offset -14` lands back on `12`.

A stats check confirms all 6 rules load. A missing alert then means the
rule did not match.

## Redmine ticket

https://redmine.openinfosecfoundation.org/issues/9089
