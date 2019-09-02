import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("127.0.0.1", 8080))
s.listen(1)
conn, addr = s.accept()
conn.send("220 (FTP server)\r\n")
data = conn.recv(1024)
conn.send("HTTP/1.0 200 OK\r\nServer:EvadingHTTPasFTP\r\nContent-Length:12\r\n\r\nHere is HTTP")
conn.close()
s.close()
