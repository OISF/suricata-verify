#!/usr/bin/env python3
# Generates input.pcap: an HTTP GET whose REQUEST LINE is split over two TCP
# segments. The http.uri content ("/index") is only complete in the SECOND
# segment; until then the http_uri buffer is empty (there is no partial
# request-line inspection - the line fields are only set once the line
# completes).
#
#   seg1  : "GET /ind"                   (line incomplete, buffer empty)
#   seg2  : "ex HTTP/1.1\r\nHost: x\r\n\r\n" (line completes, then headers)
#   rsp   : 200 OK
#
# Note: the HTP progress is at request_line (LINE) from the first request byte
# until the line's CRLF is seen; the line completes (still at LINE progress)
# during the processing of seg2.
from scapy.all import Ether, IP, TCP, Raw, wrpcap

SIP, DIP = "10.20.0.14", "142.251.111.105"  # $HOME_NET -> $EXTERNAL_NET
SP, DP = 49152, 80

seg1 = b"GET /ind"
seg2 = b"ex HTTP/1.1\r\nHost: x\r\n\r\n"
rsp  = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"

Cs, Ss = 2000, 6000
cseq = Cs + 1
sseq = Ss + 1
sack = Cs + 1
cake = Ss + 1
pkts = []

def mk(src, dst, sp, dp, seq, ack, flags, payload=b""):
    p = Ether(src="00:11:22:33:44:55" if src == SIP else "66:77:88:99:aa:bb",
              dst="66:77:88:99:aa:bb" if src == SIP else "00:11:22:33:44:55")/IP(src=src, dst=dst)/TCP(sport=sp, dport=dp, seq=seq, ack=ack, flags=flags)
    if payload: p = p/Raw(payload)
    return p

def c(payload, flags="PA"):
    global cseq, sack
    pkts.append(mk(SIP, DIP, SP, DP, cseq, cake, flags, payload))
    cseq += len(payload) + (1 if "F" in flags else 0)
    sack = cseq

def s(payload, flags="PA"):
    global sseq, cake
    pkts.append(mk(DIP, SIP, DP, SP, sseq, sack, flags, payload))
    sseq += len(payload) + (1 if "F" in flags else 0)
    cake = sseq

pkts.append(mk(SIP, DIP, SP, DP, Cs, 0, "S"))
pkts.append(mk(DIP, SIP, DP, SP, Ss, Cs + 1, "SA"))
c(b"", "A")
c(seg1); s(b"", "A")
c(seg2); s(b"", "A")
s(rsp)
s(b"", "F"); c(b"", "A")
c(b"", "F"); s(b"", "A")
wrpcap("input.pcap", pkts)
print("wrote input.pcap", len(pkts), "packets")
