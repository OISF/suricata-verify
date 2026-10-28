# Description

Test that the BSD defrag policy trims every following fragment overlapped
by a preferred fragment, not just the immediate right-hand neighbour.

Both BSD overlap paths in `DefragInsertFrag()` are covered, for IPv4 and
IPv6. Vulnerable versions only trim the first overlapped fragment, so a
later fragment overwrites the preferred data with stale data.

Each case uses its own source address. A clean fragmented datagram per
address family is included as a control.

In the layouts below, offsets are bytes into the IP payload, fragments are
listed in arrival order, and `UDP hdr` is the 8 byte UDP header. The IPv6
cases are identical, with `V6` in place of `V4` in the tokens.

## Control (10.0.0.1, 2001:db8::1)

```
         |0       |8       |16      |24      |
         |========|========|========|========|
 1       |UDP hdr |aaaaaaaa|        |        |
 2 (end) |        |        |SV9160-V|4-CTRLOK|

 BSD     |UDP hdr |aaaaaaaa|SV9160-V|4-CTRLOK|
```

## Preferred fragment starts inside an earlier fragment (10.0.0.2, 2001:db8::2)

Fragment 4 starts inside fragment 1, so fragment 1 is preferred for 8..16.
Fragment 4 starts before fragments 2 and 3, so it is preferred over both of
them.

```
         |0       |8       |16      |24      |32      |40      |48      |
         |========|========|========|========|========|========|========|
 1       |UDP hdr |aaaaaaaa|        |        |        |        |        |
 2       |        |        |bbbbbbbb|bbbbbbbb|        |        |        |
 3       |        |        |        |        |cccccccc|cccccccc|        |
 4       |        |xxxxxxxx|dddddddd|dddddddd|SV9160-V|4-INSIDE|        |
 5 (end) |        |        |        |        |        |        |eeeeeeee|

 BSD     |UDP hdr |aaaaaaaa|dddddddd|dddddddd|SV9160-V|4-INSIDE|eeeeeeee|
 Vuln    |UDP hdr |aaaaaaaa|dddddddd|dddddddd|cccccccc|cccccccc|eeeeeeee|
```

## Preferred fragment starts before all earlier fragments (10.0.0.3, 2001:db8::3)

Fragment 4 starts before fragments 1, 2 and 3, so it is preferred over all
of them.

```
         |0       |8       |16      |24      |32      |40      |48      |56      |
         |========|========|========|========|========|========|========|========|
 1       |        |bbbbbbbb|bbbbbbbb|        |        |        |        |        |
 2       |        |        |        |cccccccc|cccccccc|        |        |        |
 3       |        |        |        |        |        |ffffffff|ffffffff|        |
 4       |UDP hdr |dddddddd|dddddddd|dddddddd|dddddddd|SV9160-V|4-BEFORE|        |
 5 (end) |        |        |        |        |        |        |        |eeeeeeee|

 BSD     |UDP hdr |dddddddd|dddddddd|dddddddd|dddddddd|SV9160-V|4-BEFORE|eeeeeeee|
 Vuln    |UDP hdr |dddddddd|dddddddd|dddddddd|dddddddd|ffffffff|ffffffff|eeeeeeee|
```

# PCAP

Generated with `gen-pcap.py` (scapy). UDP checksums are computed over the
expected BSD reassembled payload.

# Ticket

https://redmine.openinfosecfoundation.org/issues/9160
