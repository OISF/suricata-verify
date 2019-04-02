import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("127.0.0.1", 8000))

a = sock.send("GET /\r\nHeader1 : Value1\r\nUser-Agent : test\r\n\r\n")
data = sock.recv(2000)
print "returned", data

sock.close()
