#!/usr/bin/env python3
"""
Pcap generator for the rfb-max-8731-reason-coalesced SV test (ticket
#8731, PR 16164).

Exercises the TCFailureReason rem-handling defect: a second,
well-formed failure reason PDU coalesced in the SAME TCP segment as a
truncated (longer-than-cap) first failure reason.

Stream shape (RFB 3.8, security type 2 VNC auth failure path -
spec-compliant, fully dissectable by tshark's VNC dissector):

  - RFB 3.8 version exchange
  - server offers 1 security type: VNC auth (2); client selects it
  - 16-byte VNC challenge / 16-byte client response
  - ONE server segment containing:
      * security result: failure (1), 4-byte big-endian, as modeled by
        both the parser's be_u32 and tshark's VNC dissector
      * first failure reason: REASON_LEN (2048) bytes of 'A'
        (> cap 1024): truncated, rfb.too_long_string
      * a second, well-formed failure reason: 10 bytes "0123456789"
    A real server write() of reason + follow-up produces exactly this
    coalesced shape.
  - clean TCP close (EOF) so the transaction is logged.

The parser stays in the TCFailureReason state after a truncated reason
and re-parses following reason PDUs (last reason wins - pinned by the
sibling test rfb-max-8731-toskip-vncauth, where the second reason
arrives in a separate segment). The second reason must therefore be
parsed here as well.

The v3.4-v3.6 code loses it: the TCFailureReason branch does
    if request.to_skip >= rem.len() as u32 {
        self.to_skip_tc = request.to_skip - rem.len() as u32;
    }
and then returns AppLayerResult::ok() without processing rem. The
framework treats ok as full-input-consumed (app-layer-parser.c:
consumed = input_len), so the second PDU in rem is dropped, and the
pending skip is mis-credited by the rem bytes (which are NOT part of
the skipped string tail). Result: the logged reason is the truncated
first reason and the second PDU is silently lost.
"""
import struct
import sys
import time

CLIENT_MAC = bytes.fromhex("020000000001")
SERVER_MAC = bytes.fromhex("020000000002")
CLIENT_IP = "10.0.0.1"
SERVER_IP = "10.0.0.2"
CLIENT_PORT = 40000
SERVER_PORT = 5900

REASON_LEN = 2048           # > cap (1024): truncated, too_long_string
SECOND_REASON = b"0123456789"  # 10 bytes, well-formed, must be parsed
SEC_RESULT_FAIL = b"\x00\x00\x00\x01"


def ip4(addr):
    return bytes(int(x) for x in addr.split("."))


def checksum(data):
    if len(data) & 1:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def tcp_packet(src_ip, dst_ip, src_port, dst_port, seq, ack, flags, payload=b""):
    src = ip4(src_ip)
    dst = ip4(dst_ip)
    offset_flags = (5 << 12) | flags
    tcp = struct.pack(
        "!HHIIHHHH", src_port, dst_port, seq, ack, offset_flags, 65535, 0, 0)
    pseudo = src + dst + struct.pack("!BBH", 0, 6, len(tcp) + len(payload))
    csum = checksum(pseudo + tcp + payload)
    tcp = struct.pack(
        "!HHIIHHHH", src_port, dst_port, seq, ack, offset_flags, 65535, csum, 0)

    total_len = 20 + len(tcp) + len(payload)
    ip = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, total_len, 0, 0x4000, 64, 6, 0, src, dst)
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]

    if src_ip == CLIENT_IP:
        eth = SERVER_MAC + CLIENT_MAC + struct.pack("!H", 0x0800)
    else:
        eth = CLIENT_MAC + SERVER_MAC + struct.pack("!H", 0x0800)
    return eth + ip + tcp + payload


def write_record(f, packet, ts):
    sec = int(ts)
    usec = int((ts - sec) * 1_000_000)
    f.write(struct.pack("<IIII", sec, usec, len(packet), len(packet)))
    f.write(packet)


def cseg(f, cseq, sseq, payload, ts):
    """One client->server data segment plus the server's ACK."""
    write_record(f,
                 tcp_packet(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT,
                            cseq, sseq, 0x18, payload), ts)
    cseq += len(payload)
    ts += 0.0005
    write_record(f,
                 tcp_packet(SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT,
                            sseq, cseq, 0x10), ts)
    return cseq, ts + 0.0005


def sseg(f, sseq, cseq, payload, ts):
    """One server->client data segment plus the client's ACK."""
    write_record(f,
                 tcp_packet(SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT,
                            sseq, cseq, 0x18, payload), ts)
    sseq += len(payload)
    ts += 0.0005
    write_record(f,
                 tcp_packet(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT,
                            cseq, sseq, 0x10), ts)
    return sseq, ts + 0.0005


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "rfb_reason_coalesced.pcap"
    cseq = 1000
    sseq = 9000
    ts = time.time()
    with open(out, "wb") as f:
        f.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))

        # TCP 3WHS
        write_record(f, tcp_packet(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT,
                                   cseq, 0, 0x02), ts)
        cseq += 1
        ts += 0.001
        write_record(f, tcp_packet(SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT,
                                   sseq, cseq, 0x12), ts)
        sseq += 1
        ts += 0.001
        write_record(f, tcp_packet(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT,
                                   cseq, sseq, 0x10), ts)
        ts += 0.001

        # RFB versions (3.8)
        sseq, ts = sseg(f, sseq, cseq, b"RFB 003.008\n", ts)
        cseq, ts = cseg(f, cseq, sseq, b"RFB 003.008\n", ts)

        # VNC auth handshake
        sseq, ts = sseg(f, sseq, cseq, b"\x01\x02", ts)      # 1 type: VNC auth
        cseq, ts = cseg(f, cseq, sseq, b"\x02", ts)          # client selects it
        sseq, ts = sseg(f, sseq, cseq, bytes(range(16)), ts)       # challenge
        cseq, ts = cseg(f, cseq, sseq, bytes(range(16, 32)), ts)   # response

        # result + truncated first reason + well-formed second reason,
        # coalesced in a single segment (rem > 0 at parse time)
        coalesced = (SEC_RESULT_FAIL
                     + struct.pack("!I", REASON_LEN) + b"A" * REASON_LEN
                     + struct.pack("!I", len(SECOND_REASON)) + SECOND_REASON)
        sseq, ts = sseg(f, sseq, cseq, coalesced, ts)

        # clean close
        write_record(f, tcp_packet(SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT,
                                   sseq, cseq, 0x11), ts)
        ts += 0.001
        write_record(f, tcp_packet(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT,
                                   cseq, sseq + 1, 0x10), ts)
        cseq += 1
        ts += 0.001
        write_record(f, tcp_packet(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT,
                                   cseq, sseq + 1, 0x11), ts)
        ts += 0.001
        write_record(f, tcp_packet(SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT,
                                   sseq + 1, cseq + 1, 0x10), ts)

    print("wrote %s" % out)


if __name__ == "__main__":
    main()
