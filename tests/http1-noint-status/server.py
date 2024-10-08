#! /usr/bin/env python

# @author: Philippe Antoine

import sys
import binascii
from threading import Thread
import time
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("127.0.0.1", 8001))
s.listen(1)
conn, addr = s.accept()
data = conn.recv(1024)
conn.send(b"HTTP/1.0 2XX OK\nServer: POC\nContent-Length:4\n\ntoto")
conn.close()
s.close()
