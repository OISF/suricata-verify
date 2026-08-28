#!/usr/bin/env python3

from scapy.all import Ether, IP, Raw, TCP, wrpcap


CLIENT_MAC = "02:00:00:00:00:01"
SERVER_MAC = "02:00:00:00:00:02"
SERVER_IP = "198.51.100.10"
REPEATED_COUNT = 3
BOUNDARY_COUNT = 513

packets = []


def add_packet(packet):
    packet.time = 1_700_000_000 + len(packets) / 1000
    packets.append(packet)


class TcpFlow:
    def __init__(self, client_ip, client_port, server_port):
        self.client_ip = client_ip
        self.client_port = client_port
        self.server_port = server_port
        self.client_seq = 1000
        self.server_seq = 2000

    def client_packet(self, flags, payload=b""):
        packet = (
            Ether(src=CLIENT_MAC, dst=SERVER_MAC)
            / IP(src=self.client_ip, dst=SERVER_IP)
            / TCP(
                sport=self.client_port,
                dport=self.server_port,
                flags=flags,
                seq=self.client_seq,
                ack=self.server_seq,
            )
        )
        if payload:
            packet /= Raw(payload)
        add_packet(packet)
        self.client_seq += len(payload)
        if "S" in flags or "F" in flags:
            self.client_seq += 1

    def server_packet(self, flags, payload=b""):
        packet = (
            Ether(src=SERVER_MAC, dst=CLIENT_MAC)
            / IP(src=SERVER_IP, dst=self.client_ip)
            / TCP(
                sport=self.server_port,
                dport=self.client_port,
                flags=flags,
                seq=self.server_seq,
                ack=self.client_seq,
            )
        )
        if payload:
            packet /= Raw(payload)
        add_packet(packet)
        self.server_seq += len(payload)
        if "S" in flags or "F" in flags:
            self.server_seq += 1

    def open(self):
        self.client_packet("S")
        self.server_packet("SA")
        self.client_packet("A")

    def close(self):
        self.client_packet("FA")
        self.server_packet("FA")
        self.client_packet("A")


def request_chunk_dedup():
    flow = TcpFlow("192.0.2.1", 10001, 80)
    flow.open()
    flow.client_packet(
        "PA",
        b"POST /request-dedup HTTP/1.1\r\n"
        b"Host: example.test\r\n"
        b"Transfer-Encoding: chunked\r\n\r\n",
    )
    for _ in range(REPEATED_COUNT):
        flow.client_packet("PA", b"1;x=y\r\na\r\n")
    flow.client_packet("PA", b"0\r\n\r\n")
    flow.server_packet("PA", b"HTTP/1.1 204 No Content\r\n\r\n")
    flow.close()


def response_chunk_dedup():
    flow = TcpFlow("192.0.2.2", 10002, 81)
    flow.open()
    flow.client_packet(
        "PA", b"GET /response-dedup HTTP/1.1\r\nHost: example.test\r\n\r\n"
    )
    flow.server_packet(
        "PA", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
    )
    for _ in range(REPEATED_COUNT):
        flow.server_packet("PA", b"1;x=y\r\na\r\n")
    flow.server_packet("PA", b"0\r\n\r\n")
    flow.close()


def continue_dedup():
    flow = TcpFlow("192.0.2.3", 10003, 82)
    flow.open()
    flow.client_packet(
        "PA",
        b"POST /continue-dedup HTTP/1.1\r\n"
        b"Host: example.test\r\n"
        b"Content-Length: 1\r\n"
        b"Expect: 100-continue\r\n\r\n",
    )
    for _ in range(REPEATED_COUNT):
        flow.server_packet("PA", b"HTTP/1.1 100 Continue\r\n\r\n")
    flow.client_packet("PA", b"a")
    flow.server_packet("PA", b"HTTP/1.1 204 No Content\r\n\r\n")
    flow.close()


def post_boundary_event():
    flow = TcpFlow("192.0.2.4", 10004, 83)
    flow.open()
    for tx_id in range(BOUNDARY_COUNT):
        flow.client_packet(
            "PA",
            (
                f"POST /boundary/{tx_id} HTTP/1.1\r\n"
                "Host: example.test\r\n"
                "Transfer-Encoding: chunked\r\n\r\n"
                "1;x=y\r\na\r\n0\r\n\r\n"
            ).encode(),
        )
        flow.server_packet("PA", b"HTTP/1.1 204 No Content\r\n\r\n")
    flow.close()


request_chunk_dedup()
response_chunk_dedup()
continue_dedup()
post_boundary_event()
wrpcap("input.pcap", packets)
