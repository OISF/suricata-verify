import sys
import binascii
from threading import Thread
import time
import socket



s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("127.0.0.1", 4445))
s.listen(1)
conn, addr = s.accept()
s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print("accpeted, now connecting")
s2.connect(("127.0.0.1", 445))
print("connected")
ok = True
while ok:
    data = conn.recv(32768)
    print("received", len(data), data[16])
    if len(data) == 0:
        break
    data = bytearray(data)
    changed = 0
    if data[16] == 9:
        # write request
        print("write", data[116])
        if data[116] == 69:
            # if the first letter of payload is E
            # let's remove 512 to the length
            data[73] = data[73] - 2
            print("modified", binascii.hexlify(data))
    s2.send(data)
    resp = s2.recv(32768)
    print("response", len(resp))
    resp = bytearray(resp)
    conn.send(resp)

conn.close()
s.close()
