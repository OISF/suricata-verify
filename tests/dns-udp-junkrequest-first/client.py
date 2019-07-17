import socket
import binascii

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.connect(("192.168.1.1", 53))

snmp = binascii.unhexlify("3040020103300f02030091c8020205dc040104020103041530130400020100020100040561646d696e04000400301304000400a00d02030091c80201000201003000")
dns = binascii.unhexlify("c58e012000010000000000010b636174656e61637962657202467200000100010000291000000000000000")
a = sock.send(snmp)
data = sock.recv(2000)
print "1", binascii.hexlify(data)
a = sock.send(dns)
data = sock.recv(2000)
print "2", binascii.hexlify(data)

sock.close()
