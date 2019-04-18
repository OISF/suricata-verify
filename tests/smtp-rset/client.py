import socket

def sendandrecv(sock, a):
    sock.send(a)
    sock.recv(2000)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("127.0.0.1", 25))
data = sock.recv(2000)

sendandrecv(sock,"EHLO ehlo.fr\r\n")
sendandrecv(sock,"MAIL FROM:<username@domain.com>\r\nRCPT TO:<john.doe@example.com>\r\n")
msg = "Message 1\r\n"
sock.send("BDAT %d LAST\r\n" % len(msg))
sendandrecv(sock,msg)
sendandrecv(sock,"RSET\r\n")
sendandrecv(sock,"MAIL FROM:<username@domain.com>\r\nRCPT TO:<john.doe@example.com>\r\n")
msg = "Message Two\r\n"
sock.send("BDAT %d LAST\r\n" % len(msg))
sendandrecv(sock,msg)
sendandrecv(sock,"QUIT\r\n")
sock.close()
