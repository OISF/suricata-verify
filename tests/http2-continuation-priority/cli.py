import socket
import binascii

HOST = "127.0.0.1"  # The server's hostname or IP address
PORT = 8080  # The port used by the server

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    data = binascii.unhexlify("50 52 49 20 2a 20 48 54 54 50 2f 32 2e 30 0d 0a 0d 0a 53 4d 0d 0a 0d 0a".replace(" ", ""))
    s.sendall(data)
    data2 = binascii.unhexlify("00 00 00  04  00  00 00 00 00".replace(" ", ""))
    s.sendall(data2)
    data = s.recv(1024)
    data3 = binascii.unhexlify("00 00 11  01  21  00 00 00 01 00 00 00 00 0f  82 84 86 41 08 65 76 69 6c 2e 63 6f 00 00 01  09  04  00 00 00 01 6d".replace(" ", ""))
    s.sendall(data3)
    data = s.recv(1024)

print(f"Received {data!r}")
