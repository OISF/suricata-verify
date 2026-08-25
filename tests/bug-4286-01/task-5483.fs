flow default tcp 192.168.0.233:44123 > google.com:80 (tcp.initialize;);
default > (content:"GET /somestuff HTTP/1.1\x0d\x0aAccept: */*\x0d\x0aCookie: id=234524dst35e\x0d\x0aUser-Agent: Mozilla/4.0 (compatible; MSIE 6.0000; Windows NT 5.1; SV1)\x0d\x0aHost: google.com\x0d\x0a\x0d\x0a";);
default < (content:"HTTP/1.1 200 OK\x0d\x0aContent-Length: 26\x0d\x0a\x0d\x0aSomestuff on display!!\x0d\x0a\x0d\x0a";);
