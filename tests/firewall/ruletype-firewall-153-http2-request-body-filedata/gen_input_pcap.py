#!/usr/bin/env python3
"""Generate input.pcap: an HTTP/2 session with one POST stream whose request
body does not contain the content matched by the http_client_body firewall
rule (content:"%PDF").

The request body is the "file" inspected by the filedata engine (progress
request_data). Once the request has moved past it the engine must report a
final no match, so the fail-closed default policy is applied before the
stream/tx has fully completed.

Layout (pcap_cnt):
  1-3   TCP handshake
  4     C: connection preface + SETTINGS
  5     S: SETTINGS + WINDOW_UPDATE
  6     C: HEADERS[1] POST /upload
  7     C: DATA[1] body part 1
  8     C: DATA[1] body part 2 (END_STREAM, request completes here)
  9     S: HEADERS[1] 200 OK (response left open, stream half-closed)
"""

from scapy.all import Ether, IP, TCP, Raw, wrpcap
from h2.connection import H2Connection
from h2.config import H2Configuration

ETH_SRC = "00:11:22:33:44:55"
ETH_DST = "66:77:88:99:aa:bb"
SRC = "192.168.0.1"
DST = "192.168.0.2"
SPORT = 44444
DPORT = 80

BODY1 = b"hello world, this is a plain text "
BODY2 = b"request body, not a pdf\n"


def frame(pkt):
    return Ether(src=ETH_SRC, dst=ETH_DST) / pkt


def main():
    client = H2Connection(config=H2Configuration(client_side=True))
    server = H2Connection(config=H2Configuration(client_side=False))

    packets = []
    cseq = 1
    sseq = 1
    t = 0.0

    def c2s(data, dt=0.02):
        nonlocal cseq, t
        t += dt
        p = frame(IP(src=SRC, dst=DST) / TCP(sport=SPORT, dport=DPORT, flags="PA",
                                                   seq=cseq, ack=sseq))
        if data:
            p = p / Raw(load=data)
        packets.append((p, t))
        if data:
            cseq += len(data)

    def s2c(data, dt=0.02):
        nonlocal sseq, t
        t += dt
        p = frame(IP(src=DST, dst=SRC) / TCP(sport=DPORT, dport=SPORT, flags="PA",
                                                   seq=sseq, ack=cseq))
        if data:
            p = p / Raw(load=data)
        packets.append((p, t))
        if data:
            sseq += len(data)

    def feed(conn, data):
        conn.receive_data(data)
        return bytes(conn.data_to_send())

    # handshake
    packets.append((frame(IP(src=SRC, dst=DST) / TCP(sport=SPORT, dport=DPORT,
                                       flags="S", seq=0)), 0.0))
    packets.append((frame(IP(src=DST, dst=SRC) / TCP(sport=DPORT, dport=SPORT,
                                       flags="SA", seq=0, ack=1)), 0.01))
    packets.append((frame(IP(src=SRC, dst=DST) / TCP(sport=SPORT, dport=DPORT,
                                       flags="A", seq=cseq, ack=sseq)), 0.02))

    # preface + settings
    client.initiate_connection()
    preface = client.data_to_send()
    c2s(preface)
    s2c(feed(server, preface))

    # request headers
    client.send_headers(
        1,
        [
            (":method", "POST"),
            (":authority", "upload.example.com"),
            (":scheme", "http"),
            (":path", "/upload"),
            ("content-type", "text/plain"),
        ],
    )
    hdrs = client.data_to_send()
    c2s(hdrs)
    feed(server, hdrs)

    # body part 1
    client.send_data(1, BODY1)
    d1 = client.data_to_send()
    c2s(d1)
    feed(server, d1)

    # body part 2 + END_STREAM
    client.send_data(1, BODY2, end_stream=True)
    d2 = client.data_to_send()
    c2s(d2)
    feed(server, d2)

    # response: headers only, no END_STREAM so the stream stays half-closed
    # (request closed, response still open) and the tx never completes on its
    # own. That is what makes the fail-closed drop at request_data observable.
    server.send_headers(1, [(":status", "200"), ("content-type", "text/plain")])
    resp = server.data_to_send()
    s2c(resp)
    feed(client, resp)

    for pkt, dt in packets:
        pkt.time = dt

    wrpcap("input.pcap", [pkt for pkt, _ in packets])
    print(f"wrote input.pcap with {len(packets)} packets")


if __name__ == "__main__":
    main()
