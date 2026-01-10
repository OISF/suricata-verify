flow default tcp 192.168.0.233:44123 > google.com:80 (tcp.initialize;);
default > (content:"CONNECT / HTTP/1.1\x0d\x0aMp-Country: US\x0d\x0aMp-BuildVersion: 136\x0d\x0aMp-Roaming: 0\x0d\x0aMp-VersionRelease: 4.3\x0d\x0aMp-Operator: android\x0d\x0aMp-SdkId: 18\x0d\x0aMp-NetworkType: 3\x0d\x0a\x0d\x0a";);
default < (content:"HTTP/1.1 200 OK\x0d\x0a\x0d\x0a";);
