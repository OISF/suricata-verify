import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("127.0.0.1", 25))

data = sock.recv(2000)
print "1", data
a = sock.send("EHLO ehlo.fr\r\n")
data = sock.recv(2000)
print "2", data
a = sock.send("MAIL FROM:<username@domain.com>\r\nRCPT TO:<john.doe@example.com>\r\nDATA\r\nThis is a test\r\n.\r\n")
data = sock.recv(2000)
print "3", data

sock.close()
