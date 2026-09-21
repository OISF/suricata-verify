#!/usr/bin/env python3
"""Craft the pcap for lua-tls-client-cert-version.

A TLS handshake where the client hello and the server hello carry
different version fields:

- client hello: version 0x0301 (record and handshake)
- server hello: version 0x0303 (record and handshake)
- server certificate message (self-signed cert)
- client certificate message (self-signed cert)

The parser tracks the version per direction, so the lua tls lib must
report "TLSv1" for get_client_cert_info() and "TLS 1.2" for
get_server_cert_info(). The certs are parsed by OpenSSL, so they must
be real certificates; they are generated next to this script if the
DER files are not there yet.
"""

import subprocess
import sys
from pathlib import Path

from scapy.all import Raw, TCP, IP, Ether, wrpcap

HERE = Path(__file__).parent
SERVER_DER = HERE / "server.der"
CLIENT_DER = HERE / "client.der"


def make_cert(path: Path, cn: str) -> None:
    if path.exists():
        return
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", "/dev/null",
        "-out", str(path.with_suffix(".crt")), "-days", "3650", "-nodes",
        "-subj", f"/CN={cn}",
    ], check=True, capture_output=True)
    subprocess.run([
        "openssl", "x509", "-outform", "DER",
        "-in", str(path.with_suffix(".crt")), "-out", str(path),
    ], check=True, capture_output=True)


def tls_record(version: int, handshake: bytes) -> bytes:
    return bytes([0x16, version >> 8, version & 0xFF]) + \
        len(handshake).to_bytes(2, "big") + handshake


def hs(hs_type: int, body: bytes) -> bytes:
    return bytes([hs_type]) + len(body).to_bytes(3, "big") + body


def client_hello() -> bytes:
    body = (
        (0x0301).to_bytes(2, "big")          # version field: TLS 1.0
        + bytes(32)                          # random
        + bytes([0])                         # no session id
        + (0x0004).to_bytes(2, "big")        # 4 bytes of cipher suites
        + bytes([0x00, 0x2F, 0x00, 0x35])    # AES128-SHA, AES128-SHA256
        + bytes([0x01, 0x00])                # one compression method: NULL
    )
    return hs(0x01, body)


def server_hello() -> bytes:
    body = (
        (0x0303).to_bytes(2, "big")          # version field: TLS 1.2
        + bytes(32)                          # random
        + bytes([0])                         # no session id
        + bytes([0x00, 0x35])                # selected cipher suite
        + bytes([0x00])                      # compression: NULL
    )
    return hs(0x02, body)


def certificate(cert_der: bytes) -> bytes:
    cert_entry = len(cert_der).to_bytes(3, "big") + cert_der
    body = len(cert_entry).to_bytes(3, "big") + cert_entry  # one cert in the list
    return hs(0x0B, body)


def main() -> None:
    make_cert(SERVER_DER, "test-server")
    make_cert(CLIENT_DER, "test-client")
    server_der = SERVER_DER.read_bytes()
    client_der = CLIENT_DER.read_bytes()

    src_ip, dst_ip = "10.0.0.2", "10.0.0.1"
    sport, dport = 12345, 443
    cseq, sseq = 1000, 2000

    pkts = []

    def tcp(sip, dip, sp, dp, s, a, payload=b"", flags="S"):
        p = Ether() / IP(src=sip, dst=dip) / TCP(sport=sp, dport=dp, seq=s, ack=a, flags=flags)
        if payload:
            p = p / Raw(load=payload)
        pkts.append(p)

    # 3-way handshake
    tcp(src_ip, dst_ip, sport, dport, cseq, 0, flags="S")
    cseq += 1
    tcp(dst_ip, src_ip, dport, sport, sseq, cseq, flags="SA")
    sseq += 1
    tcp(src_ip, dst_ip, sport, dport, cseq, sseq, flags="A")

    # client -> server: client hello (record + handshake version 0x0301)
    payload = tls_record(0x0301, client_hello())
    tcp(src_ip, dst_ip, sport, dport, cseq, sseq, payload, flags="AP")
    cseq += len(payload)

    # server -> client: server hello (version 0x0303) + server certificate
    payload = tls_record(0x0303, server_hello()) + tls_record(0x0303, certificate(server_der))
    tcp(dst_ip, src_ip, dport, sport, sseq, cseq, payload, flags="AP")
    sseq += len(payload)

    # server -> client: certificate request, so the client certificate
    # that follows is a message the parser tracks on the client side
    cr_body = bytes([0x01, 0x01, 0x00, 0x02, 0x04, 0x01, 0x00, 0x00])
    payload = tls_record(0x0303, hs(0x0D, cr_body))
    tcp(dst_ip, src_ip, dport, sport, sseq, cseq, payload, flags="AP")
    sseq += len(payload)

    # client -> server: client certificate (record + handshake version 0x0301)
    payload = tls_record(0x0301, certificate(client_der))
    tcp(src_ip, dst_ip, sport, dport, cseq, sseq, payload, flags="AP")
    cseq += len(payload)

    # client -> server: finished, so the parser commits the client cert and a
    # later rule evaluation can see both certificates
    body = hs(0x14, bytes(12))  # finished: 12-byte verify data
    payload = tls_record(0x0301, body)
    tcp(src_ip, dst_ip, sport, dport, cseq, sseq, payload, flags="AP")
    cseq += len(payload)
    # server -> client: ack so the last rule run happens with both certs set
    tcp(dst_ip, src_ip, dport, sport, sseq, cseq, flags="A")

    out = HERE / "input.pcap"
    wrpcap(str(out), pkts)
    print(f"wrote {out}")


if __name__ == "__main__":
    sys.exit(main())
