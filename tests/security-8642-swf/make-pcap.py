#!/usr/bin/env python3
"""Generate input.pcap for the SWF decompression-depth wrap test."""

import struct
import zlib

from scapy.all import Ether, IP, TCP, Raw, wrpcap

CLIENT = "10.31.0.1"
SERVER = "10.31.0.2"
SPORT = 43100
DPORT = 80


def tcp_packet(src, dst, sport, dport, seq, ack, flags, payload=b""):
    pkt = (
        Ether(src="02:00:00:00:31:01", dst="02:00:00:00:31:02")
        / IP(src=src, dst=dst)
        / TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags)
    )
    if payload:
        pkt /= Raw(payload)
    return pkt


def cws_body():
    # A small valid zlib-compressed SWF body. FileSwfDecompression rewrites CWS
    # to an FWS inspection buffer when HTTP SWF decompression is enabled.
    swf_tail = b"\x78\x00\x05_\x00\x00\x0f\xa0\x00\x00\x0c\x01\x00\x44\x00\x00\x00"
    swf_len = 8 + len(swf_tail)
    return b"CWS" + bytes([6]) + struct.pack("<I", swf_len) + zlib.compress(swf_tail)


def main():
    cseq = 1000
    sseq = 9000
    request = (
        b"GET /movie.swf HTTP/1.1\r\n"
        b"Host: example.test\r\n"
        b"User-Agent: suricata-verify\r\n"
        b"\r\n"
    )
    body = cws_body()
    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: application/x-shockwave-flash\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"\r\n" + body
    )

    packets = []
    packets.append(tcp_packet(CLIENT, SERVER, SPORT, DPORT, cseq, 0, "S"))
    cseq += 1
    packets.append(tcp_packet(SERVER, CLIENT, DPORT, SPORT, sseq, cseq, "SA"))
    sseq += 1
    packets.append(tcp_packet(CLIENT, SERVER, SPORT, DPORT, cseq, sseq, "A"))
    packets.append(tcp_packet(CLIENT, SERVER, SPORT, DPORT, cseq, sseq, "PA", request))
    cseq += len(request)
    packets.append(tcp_packet(SERVER, CLIENT, DPORT, SPORT, sseq, cseq, "A"))
    packets.append(tcp_packet(SERVER, CLIENT, DPORT, SPORT, sseq, cseq, "PA", response))
    sseq += len(response)
    packets.append(tcp_packet(CLIENT, SERVER, SPORT, DPORT, cseq, sseq, "A"))
    packets.append(tcp_packet(SERVER, CLIENT, DPORT, SPORT, sseq, cseq, "FA"))
    sseq += 1
    packets.append(tcp_packet(CLIENT, SERVER, SPORT, DPORT, cseq, sseq, "FA"))
    cseq += 1
    packets.append(tcp_packet(SERVER, CLIENT, DPORT, SPORT, sseq, cseq, "A"))

    for idx, pkt in enumerate(packets):
        pkt.time = idx / 1_000_000

    wrpcap("input.pcap", packets)
    print(f"wrote {len(packets)} packets to input.pcap")


if __name__ == "__main__":
    main()
