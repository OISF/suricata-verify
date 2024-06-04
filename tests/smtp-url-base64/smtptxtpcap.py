import sys
import binascii
from threading import Thread
import time
import socket

# Create a pcap from a htp test file
# Launches a server on port 8001
# Launches a client in another thread that connects to it
# Both client and server read the htp test file
# And they send and receive data as described (without analysing it)
# So, you need to capture traffic on port 8001 while running the script

class ServerThread(Thread):

    def __init__(self, filename):
        Thread.__init__(self)
        self.filename = filename

    def run(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 2525))
        s.listen(1)
        conn, addr = s.accept()
        f = open(self.filename)
        state = 0
        sending = ""
        receiving = ""

        for l in f.readlines():
            if len(l) > 4 and l[3] == ' ' and l[:3].isdigit():
                conn.send(bytes(l, "ascii"))
                print("server sent", len(l))
            else:
                data = conn.recv(len(l))
                print("server recvd", len(data))

        conn.close()
        s.close()
        f.close()


class ClientThread(Thread):

    def __init__(self, filename):
        Thread.__init__(self)
        self.filename = filename

    def run(self):
        time.sleep(1)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("127.0.0.1", 2525))
        f = open(self.filename)
        state = 0
        sending = ""
        receiving = ""

        for l in f.readlines():
            if len(l) > 4 and l[3] == ' ' and l[:3].isdigit():
                data = s.recv(len(l))
                print("client recvd", len(data))
            else:
                s.send(bytes(l, "ascii"))
                print("client sent", len(l))
        s.close()
        f.close()

t1 = ServerThread(sys.argv[1])
t2 = ClientThread(sys.argv[1])

# Launch threads
t1.start()
t2.start()

# Wait for threads to finish
t1.join()
t2.join()
