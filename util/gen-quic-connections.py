#!/usr/bin/env python3
"""Generate deterministic QUIC Initial regression captures (requires cryptography).

Run from any directory. The test tree is relative to this script in util/.
Captures exercise passive Initial parsing, not a complete live TLS handshake.
"""
import hashlib
import hmac
from pathlib import Path
import socket
import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROOT = Path(__file__).resolve().parent.parent
V2 = 0x6B3343CF
SALTS = {
    1: bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"),
    0xFF00001B: bytes.fromhex("c3eef712c72ebb5a11a7d2432bb46365bef9f502"),
    0xFF00001C: bytes.fromhex("c3eef712c72ebb5a11a7d2432bb46365bef9f502"),
    V2: bytes.fromhex("0dede3def700a6db819381be6e269dcbf9bd2ed9"),
}


def expand(secret, label, length):
    label = b"tls13 " + label
    info = struct.pack("!HB", length, len(label)) + label + b"\0"
    result = b""
    previous = b""
    for i in range(1, (length + 31) // 32 + 1):
        previous = hmac.digest(secret, previous + info + bytes([i]), "sha256")
        result += previous
    return result[:length]


def varint(n):
    if n < 64:
        return bytes([n])
    if n < 16384:
        return struct.pack("!H", n | 0x4000)
    return struct.pack("!I", n | 0x80000000)


def client_hello(name):
    name = name.encode()
    sni = struct.pack("!H", len(name) + 3) + b"\0" + struct.pack("!H", len(name)) + name
    ext = b"\0\0" + struct.pack("!H", len(sni)) + sni
    # SupportedVersions and ALPN make the synthetic ClientHello useful for JA4 too.
    ext += b"\0+\0\3\2\3\4" + b"\0\x10\0\5\0\3\2h3"
    body = b"\3\3" + bytes(32) + b"\0\0\2\x13\1\1\0"
    body += struct.pack("!H", len(ext)) + ext
    return b"\1" + len(body).to_bytes(3, "big") + body


def server_hello():
    body = b"\3\3" + bytes(32) + b"\0\x13\1\0\0\0"
    return b"\2" + len(body).to_bytes(3, "big") + body


def initial(version, key_dcid, dcid, scid, number, client, offset, data, token=b""):
    secret = hmac.digest(SALTS[version], key_dcid, "sha256")
    directional = expand(secret, b"client in" if client else b"server in", 32)
    prefix = b"quicv2 " if version == V2 else b"quic "
    key = expand(directional, prefix + b"key", 16)
    iv = expand(directional, prefix + b"iv", 12)
    hp = expand(directional, prefix + b"hp", 16)
    plain = b"\6" + varint(offset) + varint(len(data)) + data
    plain = plain.ljust(1160, b"\0")
    header = bytes([0xD3 if version == V2 else 0xC3]) + struct.pack("!I", version)
    header += bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid + varint(len(token)) + token
    header += varint(4 + len(plain) + 16)
    pn_offset = len(header)
    header += struct.pack("!I", number)
    nonce = bytes(a ^ b for a, b in zip(iv, number.to_bytes(12, "big")))
    packet = bytearray(header + AESGCM(key).encrypt(nonce, plain, header))
    enc = Cipher(algorithms.AES(hp), modes.ECB()).encryptor()
    mask = enc.update(bytes(packet[pn_offset + 4:pn_offset + 20])) + enc.finalize()
    packet[0] ^= mask[0] & 15
    for i in range(4):
        packet[pn_offset + i] ^= mask[i + 1]
    return bytes(packet)


class Connection:
    def __init__(self, i, version=1, empty=False, shared=False):
        self.original = self.key_dcid = bytes([i]) * 8
        self.client = b"" if empty else bytes([11 if shared else i + 10]) * 8
        self.server = bytes([i + 20]) * 8
        self.version = version
        self.name = f"connection-{i}.example"
        self.hello = client_hello(self.name)
        self.pn = [0, 0]
        self.token = b""

    def fragment(self, start=0, end=None, server_cid=False):
        pn = self.pn[0]
        self.pn[0] += 1
        dcid = self.server if server_cid else self.key_dcid
        return True, initial(self.version, self.key_dcid, dcid, self.client, pn,
                             True, start, self.hello[start:end], self.token)

    def response(self):
        pn = self.pn[1]
        self.pn[1] += 1
        return False, initial(self.version, self.key_dcid, self.client, self.server,
                              pn, False, 0, server_hello())

    def retry(self):
        retry_cid = bytes([self.original[0] + 30]) * 8
        packet = b"\xf0" + struct.pack("!I", self.version) + bytes([len(self.client)]) + self.client
        packet += bytes([len(retry_cid)]) + retry_cid + b"retry-token"
        pseudo = bytes([len(self.original)]) + self.original + packet
        if self.version in (0xFF00001B, 0xFF00001C):
            key, nonce = "4d32ecdb2a2133c841e4043df27d4430", "4d1611d05513a552c587d575"
        else:
            assert self.version == 1
            key, nonce = "be0c690b9f66575a1d766b54e368c84e", "461599d35d632bf2239825bb"
        tag = AESGCM(bytes.fromhex(key)).encrypt(bytes.fromhex(nonce), b"", pseudo)
        self.token = b"retry-token"
        self.key_dcid = retry_cid
        return False, packet + tag


def checksum(data):
    data += b"\0" * (len(data) % 2)
    n = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while n >> 16:
        n = (n & 65535) + (n >> 16)
    return (~n) & 65535


def ethernet(client, payload):
    src, dst = ("192.0.2.1", "198.51.100.1") if client else ("198.51.100.1", "192.0.2.1")
    sp, dp = (55555, 443) if client else (443, 55555)
    udp = struct.pack("!HHHH", sp, dp, len(payload) + 8, 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, len(udp) + 20, 0, 0,
                     64, 17, 0, socket.inet_aton(src), socket.inet_aton(dst))
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    return bytes.fromhex("0200000000020200000000010800") + ip + udp


def write_test(name, packets, names, description, settings=(), event_counts=(), no_anomaly=True):
    directory = ROOT / "tests" / name
    directory.mkdir(parents=True, exist_ok=True)
    capture = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for i, packet in enumerate(packets):
        client, payload = packet[:2]
        time_ms = packet[2] if len(packet) > 2 else i * 10
        data = ethernet(client, payload)
        capture += struct.pack("<IIII", 1730000000 + time_ms // 1000,
                               time_ms % 1000 * 1000, len(data), len(data)) + data
    (directory / "input.pcap").write_bytes(capture)
    checks = ["requires:", "  min-version: 9", "", "checks:"]
    rules = []
    for i, hostname in enumerate(names):
        checks += ["  - filter:", "      count: 1", "      match:",
                   "        event_type: quic", f"        quic.sni: {hostname}",
                   "  - filter:", "      count: 1", "      match:",
                   "        event_type: alert", f"        alert.signature_id: {1000001+i}"]
        rules.append(f'alert quic any any -> any any (msg:"{hostname}"; quic.sni; content:"{hostname}"; sid:{1000001+i}; rev:1;)')
    for i, (event, count) in enumerate(event_counts):
        sid = 1000100 + i
        rules.append(f'alert quic any any -> any any (msg:"{event}"; app-layer-event:quic.{event}; sid:{sid}; rev:1;)')
        checks += ["  - filter:", f"      count: {count}", "      match:",
                   "        event_type: alert", f"        alert.signature_id: {sid}"]
    if no_anomaly:
        checks += ["  - filter:", "      count: 0", "      match:", "        event_type: anomaly"]
    if settings:
        checks += ["", "args:"] + [f"  - --set app-layer.protocols.quic.{setting}" for setting in settings]
    (directory / "test.yaml").write_text("\n".join(checks) + "\n")
    (directory / "test.rules").write_text("\n".join(rules) + "\n")
    (directory / "README.md").write_text(
        f"# {name}\n\n{description}\n\n"
        "All packets use the same UDP five-tuple. These deterministic synthetic "
        "captures contain valid encrypted Initial packets and exercise passive "
        "Hello extraction, not a complete TLS session.\n\n"
        "Regenerate with `python3 util/gen-quic-connections.py` (requires cryptography).\n\n"
        "Ticket: https://redmine.openinfosecfoundation.org/issues/9228\n")


def main():
    for name, kwargs in [
        ("quic-concurrent-connections", {}),
        ("quic-concurrent-v2", {"version": V2}),
        ("quic-concurrent-zero-cid", {"empty": True}),
        ("quic-concurrent-shared-cid", {"shared": True}),
    ]:
        contexts = [Connection(i, **kwargs) for i in range(1, 4)]
        packets = [c.fragment(0, 20) for c in contexts]
        packets += [contexts[0].fragment(40), contexts[0].fragment(40)]
        for c in reversed(contexts):
            packets += [c.fragment(20), c.response()]
        write_test(name, packets, [c.name for c in contexts],
                   "Three independent handshakes are interleaved, including a duplicate "
                   "tail fragment arriving before the middle. Each SNI and rule must appear once.")

    a, b = Connection(1), Connection(2)
    packets = [a.fragment(0, 20), b.fragment(0, 20), a.response(),
               a.fragment(20, server_cid=True), b.fragment(20), b.response()]
    write_test("quic-concurrent-server-cid", packets, [a.name, b.name],
               "After a server Initial, client Initial packets use its SCID as DCID "
               "while retaining the original Initial keys. Capture ordering puts the "
               "server response ahead of the final observed client fragment.")

    a, b = Connection(1), Connection(2)
    packets = [a.fragment(0, 20), b.fragment(0, 20)]
    good = a.retry()
    packets += [(False, good[1][:-1] + bytes([good[1][-1] ^ 1])), good,
                a.fragment(), a.response(), b.fragment(20), b.response(), good]
    write_test("quic-concurrent-retry", packets, [a.name, b.name],
               "A valid Retry resets only its connection. Invalid and repeated Retry "
               "packets must not reset either active handshake.")

    a, b, c = Connection(1), Connection(2), Connection(3)
    bad = c.fragment()[1]
    bad = bad[:-1] + bytes([bad[-1] ^ 1])
    malformed = initial(1, c.key_dcid, c.key_dcid, c.client, 1, True, 0, b"\xff\0\0\0")
    packets = [a.fragment(0, 20), b.fragment(0, 20), (True, bad), (True, malformed),
               a.fragment(20), b.fragment(20), a.response(), b.response()]
    write_test("quic-concurrent-invalid-initial", packets, [a.name, b.name],
               "Invalid independent Initial packets must not destroy existing contexts.",
               event_counts=[("failed_decrypt", 1), ("error_on_data", 1)], no_anomaly=False)

    a, b, c = Connection(1), Connection(2), Connection(3)
    packets = [a.fragment(0, 20), b.fragment(0, 20), c.fragment(0, 20),
               a.fragment(20), b.fragment(20), a.response(), b.response()]
    write_test("quic-concurrent-capacity", packets, [a.name, b.name],
               "A third context exceeds the configured limit without evicting either "
               "unfinished handshake.", settings=["max-connections=2"],
               event_counts=[("too_many_connections", 1)], no_anomaly=False)

    a, b = Connection(1), Connection(2)
    packets = [a.fragment(), a.response(), b.fragment(0, 20), b.fragment(20), b.response()]
    write_test("quic-concurrent-after-hello", packets, [a.name, b.name],
               "Completing one connection under default track-only policy must leave "
               "the UDP flow able to inspect a subsequent connection.")

    a, b = Connection(1), Connection(2)
    packets = [a.fragment(0, 20), b.fragment(0, 20), a.fragment(20), a.response(),
               b.fragment(20), b.response(), (True, b"\x40" + bytes(40))]
    write_test("quic-concurrent-bypass", packets, [a.name, b.name],
               "Explicit bypass must wait while another known connection is unfinished.",
               settings=["encryption-handling=bypass"])

    a, b, c = Connection(1), Connection(2), Connection(3)
    packets = [(*a.fragment(0, 20), 0), (*b.fragment(0, 20), 3000),
               (*b.fragment(20), 6000), (*c.fragment(), 7000)]
    write_test("quic-concurrent-expiry", packets, [b.name, c.name],
               "An idle incomplete context expires while a recently active context "
               "retains its CRYPTO prefix.", settings=["connection-idle-timeout=5"])


    for name, kwargs in [
        ("quic-concurrent-missing-server", {"shared": True}),
        ("quic-concurrent-missing-server-v2", {"version": V2, "empty": True}),
    ]:
        contexts = [Connection(i, **kwargs) for i in range(1, 4)]
        packets = [c.fragment(0, 20) for c in contexts]
        packets += [c.fragment(20, server_cid=True) for c in reversed(contexts)]
        write_test(name, packets, [c.name for c in contexts],
                   "Server Initial packets are missing from the capture. Client tails "
                   "use unseen server SCIDs as DCIDs, but retain the original Initial keys. "
                   "Shared or empty client SCIDs must be disambiguated by decryption.")

    a, b = Connection(1, shared=True), Connection(2, shared=True)
    packets = [a.fragment(), b.fragment(0, 20),
               a.fragment(server_cid=True), b.fragment(20, server_cid=True)]
    write_test("quic-concurrent-shared-cid-reuse", packets, [a.name, b.name],
               "A completed client Hello sharing a SCID must not suppress a new "
               "connection or produce duplicate SNI events on retransmission.")

    for draft in (27, 28):
        version = 0xFF000000 | draft
        a = Connection(1, version=version)
        packets = [a.fragment(0, 20), a.retry(), a.fragment(), a.response()]
        write_test(f"quic-concurrent-retry-draft{draft}", packets, [a.name],
                   f"A draft-{draft} Retry must pass its version-specific integrity check "
                   "and reset the existing context, even when only one context is allowed.",
                   settings=["max-connections=1"])

        a = Connection(1, version=version, shared=True)
        b = Connection(2, version=version, shared=True)
        packets = [a.fragment(0, 20), b.fragment(0, 20)]
        good = a.retry()
        corrupt = (False, good[1][:-1] + bytes([good[1][-1] ^ 1]))
        wrong = Connection(99, version=version, shared=True).retry()
        packets += [corrupt, wrong, good, a.fragment(0, 20), good,
                    a.fragment(20), a.response(), b.fragment(20), b.response()]
        write_test(f"quic-concurrent-retry-draft{draft}-parallel", packets, [a.name, b.name],
                   f"A draft-{draft} Retry is associated by its original DCID integrity tag "
                   "when connections share a client SCID. Invalid tags, wrong original DCIDs, "
                   "and repeated Retry packets must preserve unfinished CRYPTO buffers.",
                   settings=["max-connections=2"])

    a, b = Connection(1, version=V2), Connection(2)
    vn = b"\x80\0\0\0\0" + bytes([len(a.client)]) + a.client
    vn += bytes([len(a.original)]) + a.original + struct.pack("!I", 1)
    packets = [a.fragment(), (False, vn), b.fragment(), b.response()]
    name = "quic-concurrent-version-negotiation"
    write_test(name, packets, [a.name, b.name],
               "A v2 client Initial followed by Version Negotiation advertising v1 "
               "must retain the version-zero transaction for EVE logging and rules.")
    directory = ROOT / "tests" / name
    p = directory / "test.yaml"
    s = p.read_text()
    s += ('  - filter:\n      count: 1\n      match:\n'
          '        event_type: quic\n        quic.version: "0"\n'
          '  - filter:\n      count: 1\n      match:\n'
          '        event_type: alert\n        alert.signature_id: 1000200\n')
    p.write_text(s)
    with (directory / "test.rules").open("a") as rules:
        rules.write('alert quic any any -> any any (msg:"Version Negotiation"; '
                    'flow:to_client; quic.version; content:"|00 00 00 00|"; sid:1000200; rev:1;)\n')


if __name__ == "__main__":
    main()
