import sys
import binascii
from threading import Thread
import time
import socket

# Create a pcap from a htp test file
# Launches a server on port 8080
# Launches a client in another thread that connects to it
# Both client and server read the htp test file
# And they send and receive data as described (without analysing it)
# So, you need to capture traffic on port 8080 while running the script

def removeOneEOL(s):
    r = s
    if r[-1] == '\n':
        r = r[:-1]
        if r[-1] == '\r':
            r = r[:-1]
    return r

PCAP_TCP_PORT = 5353

class ServerThread(Thread):

    def __init__(self, filename):
        Thread.__init__(self)
        self.filename = filename

    def run(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", PCAP_TCP_PORT))
        s.listen(1)
        conn, addr = s.accept()
        f = open(self.filename)
        sending = ""
        receiving = ""

        for l in f.readlines():
            data = binascii.unhexlify(l.split()[1])
            if l.split()[0] == "s2c":
                conn.send(data)
                print "server sent", len(data)
            else:
                data = conn.recv(len(data))
                print "server recvd", len(data)

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
        s.connect(("127.0.0.1", PCAP_TCP_PORT))
        f = open(self.filename)
        sending = ""
        receiving = ""

        for l in f.readlines():
            data = binascii.unhexlify(l.split()[1])
            if l.split()[0] != "s2c":
                s.send(data)
                print "client sent", len(data)
            else:
                data = s.recv(len(data))
                print "client recvd", len(data)

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
