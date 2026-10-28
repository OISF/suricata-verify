# Description

Test that BSD defrag overlap handling never lowers an existing left trim.

A later, shorter overlap must not lower the left trim already set on a
following fragment. Doing so revives bytes that an earlier preferred
fragment replaced, producing a datagram that differs from BSD host
reassembly.

The test expects one control alert and one alert for the marker that only
survives correct BSD reassembly.

In the layouts below, offsets are bytes into the IP payload, fragments are
listed in arrival order, and `UDP hdr` is the 8 byte UDP header.

## Control (10.0.0.1)

```
         |0       |8       |16      |24      |
         |========|========|========|========|
 1       |UDP hdr |cccccccc|        |        |
 2 (end) |        |        |SVCTRLOK|cccccccc|

 BSD     |UDP hdr |cccccccc|SVCTRLOK|cccccccc|
```

## Regression (10.0.0.2)

Fragment 2 starts before fragment 1, so it is preferred, leaving fragment 1
with 48..56. Fragment 3 then starts before fragment 2, which leaves
fragment 2 with 40..48. Fragment 3 ends at 40, so it must not lower the trim
of fragment 1 back to 40. If it does, fragment 1 is copied over the marker.

```
         |0       |8       |16      |24      |32      |40      |48      |56      |
         |========|========|========|========|========|========|========|========|
 1       |        |        |        |NNNNNNNN|NNNNNNNN|NNNNNNNN|NNNNNNNN|        |
 2       |        |        |MMMMMMMM|MMMMMMMM|MMMMMMMM|SVOVLBUG|        |        |
 3       |UDP hdr |GGGGGGGG|GGGGGGGG|GGGGGGGG|GGGGGGGG|        |        |        |
 4 (end) |        |        |        |        |        |        |        |ZZZZZZZZ|

 BSD     |UDP hdr |GGGGGGGG|GGGGGGGG|GGGGGGGG|GGGGGGGG|SVOVLBUG|NNNNNNNN|ZZZZZZZZ|
 Vuln    |UDP hdr |GGGGGGGG|GGGGGGGG|GGGGGGGG|GGGGGGGG|NNNNNNNN|NNNNNNNN|ZZZZZZZZ|
```

# PCAP

Reporter supplied synthetic fixture.

# Ticket

https://redmine.openinfosecfoundation.org/issues/9161
