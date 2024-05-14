# JA4 QUIC

This test checks whether the correct JA4 fingerprints are calculated for the
given pcap, according to the [reference implementation](https://github.com/FoxIO-LLC/ja4)
and logged.

## PCAP

Pcap was created on developer machine using a short `tcpdump` session:
```
tcpdump -w out.pcap -i wlp61s0 'port 443 and udp'
```

## Result

`q13d0310h3_55b375c5d22e_cd85d2d88918` which means

* `q`: QUIC
* `13`: TLS 1.3
* `d`: SNI is set
* `03`: 3 cipher suites in Client Hello
* `10`: 10 extensions in Client Hello
* `h3`: ALPN protocol

and the hashes of the corresponding sorted extension codes.


## Reference output:

```
$ ../ja4/binaries/linux/ja4 tests/ja4-quic/input.pcap
- stream: 0
  transport: udp
  src: 192.168.178.25
  dst: 142.250.181.201
  src_port: 51333
  dst_port: 443
  tls_server_name: www.blogger.com
  ja4: q13d0310h3_55b375c5d22e_cd85d2d88918
- stream: 1
  transport: udp
  src: 192.168.178.25
  dst: 142.251.209.129
  src_port: 53371
  dst_port: 443
  tls_server_name: socpuppet.blogspot.com
  ja4: q13d0310h3_55b375c5d22e_cd85d2d88918
- stream: 2
  transport: udp
  src: 192.168.178.25
  dst: 142.250.181.206
  src_port: 50440
  dst_port: 443
  tls_server_name: apis.google.com
  ja4: q13d0310h3_55b375c5d22e_cd85d2d88918
- stream: 3
  transport: udp
  src: 192.168.178.25
  dst: 142.250.181.201
  src_port: 37252
  dst_port: 443
  tls_server_name: www.blogger.com
  ja4: q13d0310h3_55b375c5d22e_cd85d2d88918
- stream: 4
  transport: udp
  src: 192.168.178.25
  dst: 142.250.181.206
  src_port: 57334
  dst_port: 443
  tls_server_name: apis.google.com
  ja4: q13d0310h3_55b375c5d22e_cd85d2d88918
- stream: 5
  transport: udp
  src: 192.168.178.25
  dst: 142.250.185.164
  src_port: 38677
  dst_port: 443
  tls_server_name: www.google.com
  ja4: q13d0310h3_55b375c5d22e_cd85d2d88918
- stream: 6
  transport: udp
  src: 192.168.178.25
  dst: 142.250.181.195
  src_port: 42849
  dst_port: 443
  tls_server_name: www.gstatic.com
  ja4: q13d0310h3_55b375c5d22e_cd85d2d88918
- stream: 7
  transport: udp
  src: 192.168.178.25
  dst: 142.251.209.131
  src_port: 32997
  dst_port: 443
  tls_server_name: fonts.gstatic.com
  ja4: q13d0310h3_55b375c5d22e_cd85d2d88918
- stream: 8
  transport: udp
  src: 192.168.178.25
  dst: 142.250.181.193
  src_port: 60461
  dst_port: 443
  tls_server_name: 4.bp.blogspot.com
  ja4: q13d0310h3_55b375c5d22e_cd85d2d88918
- stream: 9
  transport: udp
  src: 192.168.178.25
  dst: 142.250.181.193
  src_port: 52446
  dst_port: 443
  tls_server_name: 1.bp.blogspot.com
  ja4: q13d0310h3_55b375c5d22e_cd85d2d88918
- stream: 10
  transport: udp
  src: 192.168.178.25
  dst: 142.250.181.193
  src_port: 41171
  dst_port: 443
  tls_server_name: 2.bp.blogspot.com
  ja4: q13d0310h3_55b375c5d22e_cd85d2d88918
```
