# JA4 TLS + QUIC

This test checks whether the correct JA4 fingerprints are calculated for the
given pcap, according to the [reference implementation](https://github.com/FoxIO-LLC/ja4).

## PCAP

Pcap was taken from https://www.cloudshark.org/captures/1737557e3427.

## Result


### TCP TLS

`t13d1516h2_8daaf6152771_e5627efa2ab1` which means

* `t`: TCP
* `13`: TLS 1.2
* `d`: SNI is set
* `15`: 15 cipher suites in Client Hello
* `15`: 16 extensions in Client Hello
* `h2`: ALPN protocol

and the hashes of the corresponding sorted extension codes.

### QUIC

`q13d0310h3_55b375c5d22e_cd85d2d88918` which means

* `q`: QUIC
* `13`: TLS 1.2
* `d`: SNI is set
* `03`: 3 cipher suites in Client Hello
* `10`: 10 extensions in Client Hello
* `h3`: ALPN protocol

and the hashes of the corresponding sorted extension codes.


## Reference output:

According to [my issue upstream](https://github.com/FoxIO-LLC/ja4/issues/3):

```
../ja4/binaries/linux/ja4 tests/ja4-tls-quic/input.pcap
- stream: 0
  transport: tcp
  src: 2001:db8:1::1
  dst: 2606:4700:10::6816:826
  src_port: 57098
  dst_port: 443
  tls_server_name: cloudflare-quic.com
  ja4: t13d1516h2_8daaf6152771_e5627efa2ab1
  ja4s: t130200_1301_234ea6891581
  ja4l_c: 30_64
  ja4l_s: 5749_56
  http:
  - ja4h: ge20nn16enus_0f5a7a41a252_000000000000_000000000000
- stream: 0
  transport: udp
  src: 2001:db8:1::1
  dst: 2606:4700:10::6816:826
  src_port: 50280
  dst_port: 443
  tls_server_name: cloudflare-quic.com
  ja4: q13d0310h3_55b375c5d22e_cd85d2d88918
  ja4s: q130200_1301_234ea6891581
  ja4l_c: 113_64
  ja4l_s: 9285_56
```
