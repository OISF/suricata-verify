# Test Description

Test for the edge case that should be handled properly by MIME decoder while
following RFC2045.

```
NA=
=Mg
==
```
should ideally get decoded to `42` as demonstrated in this test.

## PCAP

Manually created.

## Related issues

https://redmine.openinfosecfoundation.org/issues/6207
