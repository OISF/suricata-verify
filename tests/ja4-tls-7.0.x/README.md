# JA4 TLS

This test checks whether the correct JA4 fingerprints are calculated for the
given pcap, according to the [reference implementation](https://github.com/FoxIO-LLC/ja4).

## PCAP

Pcap was taken from another TLS Suricata-Verify test.

## Result

`t12i1810s1_27d4652c4487_06a4338d0495` which means

* `t`: TCP
* `12`: TLS 1.2
* `i`: SNI not is set
* `18`: 18 cipher suites in Client Hello
* `10`: 10 extensions in Client Hello
* `s1`: ALPN protocol (first and last character of `spdy/3.1` which is the first protocol listed in the extension)

and the hashes of the corresponding sorted extension codes.


## Reference output:

```
$ ../ja4/binaries/linux/ja4 tests/ja4-tls/input.pcap
- stream: 0
  transport: tcp
  src: 192.168.56.1
  dst: 192.168.56.101
  src_port: 49365
  dst_port: 443
  ja4: t12i1810s1_27d4652c4487_06a4338d0495
```
