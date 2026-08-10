#!/usr/bin/env python3
"""Generate input.pcap for the Redmine #8813 SMTP regression test."""

import argparse

from scapy.all import Ether, IP, Raw, TCP, wrpcap


CLIENT = ("10.88.13.1", 48813)
SERVER = ("10.88.13.2", 25)
CLIENT_MAC = "02:00:00:88:13:01"
SERVER_MAC = "02:00:00:88:13:02"
CRLF = b"\r\n"


class SMTPFlow:
    def __init__(self):
        self.packets = []
        self.client_seq = 1000
        self.server_seq = 5000

        self._append(CLIENT, SERVER, "S", self.client_seq, 0)
        self.client_seq += 1
        self._append(SERVER, CLIENT, "SA", self.server_seq, self.client_seq)
        self.server_seq += 1
        self._append(CLIENT, SERVER, "A", self.client_seq, self.server_seq)

    def _append(self, source, destination, flags, seq, ack, payload=b""):
        if source == CLIENT:
            source_mac, destination_mac = CLIENT_MAC, SERVER_MAC
        else:
            source_mac, destination_mac = SERVER_MAC, CLIENT_MAC
        packet = (
            Ether(src=source_mac, dst=destination_mac)
            / IP(src=source[0], dst=destination[0])
            / TCP(
                sport=source[1],
                dport=destination[1],
                flags=flags,
                seq=seq,
                ack=ack,
            )
        )
        if payload:
            packet /= Raw(payload)
        packet.time = len(self.packets) / 1_000_000
        self.packets.append(packet)

    def client(self, payload):
        self._append(
            CLIENT,
            SERVER,
            "PA",
            self.client_seq,
            self.server_seq,
            payload,
        )
        self.client_seq += len(payload)
        self._append(SERVER, CLIENT, "A", self.server_seq, self.client_seq)

    def server(self, payload):
        self._append(
            SERVER,
            CLIENT,
            "PA",
            self.server_seq,
            self.client_seq,
            payload,
        )
        self.server_seq += len(payload)
        self._append(CLIENT, SERVER, "A", self.client_seq, self.server_seq)

    def finish(self):
        self._append(CLIENT, SERVER, "FA", self.client_seq, self.server_seq)
        self.client_seq += 1
        self._append(SERVER, CLIENT, "FA", self.server_seq, self.client_seq)
        self.server_seq += 1
        self._append(CLIENT, SERVER, "A", self.client_seq, self.server_seq)


def generate(output):
    flow = SMTPFlow()
    flow.server(b"220 mail.example ESMTP ready" + CRLF)
    flow.client(b"EHLO client.example" + CRLF)
    flow.server(b"250 mail.example" + CRLF)
    flow.client(b"MAIL FROM:<alice@example.com>" + CRLF)
    flow.server(b"250 sender ok" + CRLF)
    flow.client(b"RCPT TO:<bob@example.com>" + CRLF)
    flow.server(b"250 recipient ok" + CRLF)
    flow.client(b"DATA" + CRLF)
    flow.server(b"354 send message" + CRLF)

    # The blank line following Content-Disposition makes the MIME parser open
    # the transaction's first attachment, named x.bin.
    for line in (
        b"MIME-Version: 1.0",
        b'Content-Type: multipart/mixed; boundary="BND"',
        b"",
        b"--BND",
        b"Content-Type: application/octet-stream",
        b'Content-Disposition: attachment; filename="x.bin"',
        b"",
        b"X",
        b"--BND--",
        b".",
    ):
        flow.client(line + CRLF)

    flow.server(b"250 queued" + CRLF)
    flow.client(b"QUIT" + CRLF)
    flow.server(b"221 bye" + CRLF)
    flow.finish()
    wrpcap(output, flow.packets)
    print(f"wrote {len(flow.packets)} packets to {output}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-o", "--output", default="input.pcap")
    args = parser.parse_args()
    generate(args.output)


if __name__ == "__main__":
    main()
