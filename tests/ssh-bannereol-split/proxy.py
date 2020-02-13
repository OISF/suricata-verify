import socket
import time

sock1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock1.bind(('', 2222))

sock1.listen(5)
client, address = sock1.accept()
print("{} connected".format( address ))

request = client.recv(2048)

sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock2.connect(("192.168.1.40", 22))

sock2.send(request[:-1])
time.sleep(0.1)
sock2.send(request[-1:])
response = sock2.recv(2048)
client.send(response)
for i in range(12):
    request = client.recv(2048)
    sock2.send(request)
    response = sock2.recv(2048)
    client.send(response)

print("Close")
client.close()
sock1.close()
sock.close()
