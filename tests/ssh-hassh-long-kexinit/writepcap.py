#!/usr/bin/env python3
# Generates input.pcap for the ssh-hassh-long-kexinit test (redmine #8837).
#
# The client sends an SSH_MSG_KEXINIT record whose declared body length is
# exactly SSH_MAX_REASSEMBLED_RECORD_LEN (65535) bytes, split so that the
# 6-byte record header and only the first 4 body bytes arrive (and are
# processed by the app layer) before the remaining 65531 body bytes. This is
# the "oversized KEXINIT" path in the SSH parser, which raises the
# long_kex_record event and skips the record instead of computing hassh.
#
# It is then followed by a well-formed KEXINIT (borrowed from the ssh-hassh
# test pcap) so that a correct parser still computes the client hassh. With
# the record_left bug the parser over-skips 4 bytes into this second KEXINIT,
# desynchronises, and never computes the client hassh.

from scapy.all import Ether, IP, TCP, wrpcap

CLIENT_IP = "10.0.0.1"
SERVER_IP = "10.0.0.2"
CLIENT_PORT = 34567
SERVER_PORT = 22
CLIENT_MAC = "00:00:00:00:00:01"
SERVER_MAC = "00:00:00:00:00:02"

# A well-formed client KEXINIT record (SSH-2.0-OpenSSH_for_Windows_7.7),
# client hassh = 2dd6531c7e89d3c925db9214711be76a. Taken verbatim from
# tests/ssh-hassh/input.pcap (packet 14 payload).
CLIENT_KEXINIT = bytes.fromhex(
    "00000524091403265c866cfa28973161bbbfbd897d9800000130637572766532353531"
    "392d7368613235362c637572766532353531392d736861323536406c69627373682e6f"
    "72672c656364682d736861322d6e697374703235362c656364682d736861322d6e6973"
    "74703338342c656364682d736861322d6e697374703532312c6469666669652d68656c"
    "6c6d616e2d67726f75702d65786368616e67652d7368613235362c6469666669652d68"
    "656c6c6d616e2d67726f757031362d7368613531322c6469666669652d68656c6c6d61"
    "6e2d67726f757031382d7368613531322c6469666669652d68656c6c6d616e2d67726f"
    "75702d65786368616e67652d736861312c6469666669652d68656c6c6d616e2d67726f"
    "757031342d7368613235362c6469666669652d68656c6c6d616e2d67726f757031342d"
    "736861312c6578742d696e666f2d630000012265636473612d736861322d6e69737470"
    "3235362d636572742d763031406f70656e7373682e636f6d2c65636473612d73686132"
    "2d6e697374703338342d636572742d763031406f70656e7373682e636f6d2c65636473"
    "612d736861322d6e697374703532312d636572742d763031406f70656e7373682e636f"
    "6d2c65636473612d736861322d6e697374703235362c65636473612d736861322d6e69"
    "7374703338342c65636473612d736861322d6e697374703532312c7373682d65643235"
    "3531392d636572742d763031406f70656e7373682e636f6d2c7373682d7273612d6365"
    "72742d763031406f70656e7373682e636f6d2c7373682d656432353531392c7273612d"
    "736861322d3531322c7273612d736861322d3235362c7373682d7273610000006c6368"
    "6163686132302d706f6c7931333035406f70656e7373682e636f6d2c6165733132382d"
    "6374722c6165733139322d6374722c6165733235362d6374722c6165733132382d6763"
    "6d406f70656e7373682e636f6d2c6165733235362d67636d406f70656e7373682e636f"
    "6d0000006c63686163686132302d706f6c7931333035406f70656e7373682e636f6d2c"
    "6165733132382d6374722c6165733139322d6374722c6165733235362d6374722c6165"
    "733132382d67636d406f70656e7373682e636f6d2c6165733235362d67636d406f7065"
    "6e7373682e636f6d000000d5756d61632d36342d65746d406f70656e7373682e636f6d"
    "2c756d61632d3132382d65746d406f70656e7373682e636f6d2c686d61632d73686132"
    "2d3235362d65746d406f70656e7373682e636f6d2c686d61632d736861322d3531322d"
    "65746d406f70656e7373682e636f6d2c686d61632d736861312d65746d406f70656e73"
    "73682e636f6d2c756d61632d3634406f70656e7373682e636f6d2c756d61632d313238"
    "406f70656e7373682e636f6d2c686d61632d736861322d3235362c686d61632d736861"
    "322d3531322c686d61632d73686131000000d5756d61632d36342d65746d406f70656e"
    "7373682e636f6d2c756d61632d3132382d65746d406f70656e7373682e636f6d2c686d"
    "61632d736861322d3235362d65746d406f70656e7373682e636f6d2c686d61632d7368"
    "61322d3531322d65746d406f70656e7373682e636f6d2c686d61632d736861312d6574"
    "6d406f70656e7373682e636f6d2c756d61632d3634406f70656e7373682e636f6d2c75"
    "6d61632d313238406f70656e7373682e636f6d2c686d61632d736861322d3235362c68"
    "6d61632d736861322d3531322c686d61632d73686131000000046e6f6e65000000046e"
    "6f6e6500000000000000000000000000000000000000000000"
)

# A well-formed server KEXINIT record (SSH-2.0-OpenSSH_7.4),
# server hassh = 6832f1ce43d4397c2c0a3e2f8c94334e. Taken verbatim from
# tests/ssh-hassh/input.pcap (packet 15 payload).
SERVER_KEXINIT = bytes.fromhex(
    "000004fc0a1412a427ab5300b56584d48d256f5ae42500000140637572766532353531"
    "392d7368613235362c637572766532353531392d736861323536406c69627373682e6f"
    "72672c656364682d736861322d6e697374703235362c656364682d736861322d6e6973"
    "74703338342c656364682d736861322d6e697374703532312c6469666669652d68656c"
    "6c6d616e2d67726f75702d65786368616e67652d7368613235362c6469666669652d68"
    "656c6c6d616e2d67726f757031362d7368613531322c6469666669652d68656c6c6d61"
    "6e2d67726f757031382d7368613531322c6469666669652d68656c6c6d616e2d67726f"
    "75702d65786368616e67652d736861312c6469666669652d68656c6c6d616e2d67726f"
    "757031342d7368613235362c6469666669652d68656c6c6d616e2d67726f757031342d"
    "736861312c6469666669652d68656c6c6d616e2d67726f7570312d7368613100000041"
    "7373682d7273612c7273612d736861322d3531322c7273612d736861322d3235362c65"
    "636473612d736861322d6e697374703235362c7373682d65643235353139000000af63"
    "686163686132302d706f6c7931333035406f70656e7373682e636f6d2c616573313238"
    "2d6374722c6165733139322d6374722c6165733235362d6374722c6165733132382d67"
    "636d406f70656e7373682e636f6d2c6165733235362d67636d406f70656e7373682e63"
    "6f6d2c6165733132382d6362632c6165733139322d6362632c6165733235362d636263"
    "2c626c6f77666973682d6362632c636173743132382d6362632c336465732d63626300"
    "0000af63686163686132302d706f6c7931333035406f70656e7373682e636f6d2c6165"
    "733132382d6374722c6165733139322d6374722c6165733235362d6374722c61657331"
    "32382d67636d406f70656e7373682e636f6d2c6165733235362d67636d406f70656e73"
    "73682e636f6d2c6165733132382d6362632c6165733139322d6362632c616573323536"
    "2d6362632c626c6f77666973682d6362632c636173743132382d6362632c336465732d"
    "636263000000d5756d61632d36342d65746d406f70656e7373682e636f6d2c756d6163"
    "2d3132382d65746d406f70656e7373682e636f6d2c686d61632d736861322d3235362d"
    "65746d406f70656e7373682e636f6d2c686d61632d736861322d3531322d65746d406f"
    "70656e7373682e636f6d2c686d61632d736861312d65746d406f70656e7373682e636f"
    "6d2c756d61632d3634406f70656e7373682e636f6d2c756d61632d313238406f70656e"
    "7373682e636f6d2c686d61632d736861322d3235362c686d61632d736861322d353132"
    "2c686d61632d73686131000000d5756d61632d36342d65746d406f70656e7373682e63"
    "6f6d2c756d61632d3132382d65746d406f70656e7373682e636f6d2c686d61632d7368"
    "61322d3235362d65746d406f70656e7373682e636f6d2c686d61632d736861322d3531"
    "322d65746d406f70656e7373682e636f6d2c686d61632d736861312d65746d406f7065"
    "6e7373682e636f6d2c756d61632d3634406f70656e7373682e636f6d2c756d61632d31"
    "3238406f70656e7373682e636f6d2c686d61632d736861322d3235362c686d61632d73"
    "6861322d3531322c686d61632d73686131000000156e6f6e652c7a6c6962406f70656e"
    "7373682e636f6d000000156e6f6e652c7a6c6962406f70656e7373682e636f6d000000"
    "0000000000000000000000000000000000000000"
)

# NEWKEYS record: pkt_len=12, padding=10, msg_code=21, 10 bytes of padding.
NEWKEYS = bytes.fromhex("0000000c0a15") + b"\x00" * 10

# Oversized KEXINIT header: pkt_len=65537, padding=4, msg_code=20 (KEXINIT),
# followed by 4 body bytes. Full body would be pkt_len - 2 = 65535 bytes.
LONG_KEXINIT_HEADER = bytes.fromhex("000100010414") + b"\xaa" * 4
LONG_KEXINIT_BODY_REMAINING = b"\x00" * (65535 - 4)

CLIENT_BANNER = b"SSH-2.0-Evil_1.0\r\n"
SERVER_BANNER = b"SSH-2.0-OpenSSH_7.4\r\n"


class Flow:
    """Minimal stateful TCP flow builder with correct seq/ack tracking."""

    def __init__(self):
        self.pkts = []
        self.cseq = 1000
        self.sseq = 5000
        # ack values track the next expected seq from the peer
        self.cack = 0
        self.sack = 0

    def _l2(self, to_server):
        if to_server:
            return Ether(src=CLIENT_MAC, dst=SERVER_MAC) / IP(
                src=CLIENT_IP, dst=SERVER_IP
            ) / TCP(sport=CLIENT_PORT, dport=SERVER_PORT)
        return Ether(src=SERVER_MAC, dst=CLIENT_MAC) / IP(
            src=SERVER_IP, dst=CLIENT_IP
        ) / TCP(sport=SERVER_PORT, dport=CLIENT_PORT)

    def handshake(self):
        p = self._l2(True)
        p[TCP].flags = "S"
        p[TCP].seq = self.cseq
        self.pkts.append(p)
        self.cseq += 1

        p = self._l2(False)
        p[TCP].flags = "SA"
        p[TCP].seq = self.sseq
        p[TCP].ack = self.cseq
        self.pkts.append(p)
        self.sseq += 1
        self.sack = self.cseq

        p = self._l2(True)
        p[TCP].flags = "A"
        p[TCP].seq = self.cseq
        p[TCP].ack = self.sseq
        self.pkts.append(p)
        self.cack = self.sseq

    def send(self, data, to_server):
        """Emit a data segment and an immediate ACK from the peer, so the
        app layer processes this segment on its own."""
        if to_server:
            p = self._l2(True)
            p[TCP].flags = "PA"
            p[TCP].seq = self.cseq
            p[TCP].ack = self.sseq
            p = p / data
            self.pkts.append(p)
            self.cseq += len(data)
            # peer ACK
            a = self._l2(False)
            a[TCP].flags = "A"
            a[TCP].seq = self.sseq
            a[TCP].ack = self.cseq
            self.pkts.append(a)
            self.sack = self.cseq
        else:
            p = self._l2(False)
            p[TCP].flags = "PA"
            p[TCP].seq = self.sseq
            p[TCP].ack = self.cseq
            p = p / data
            self.pkts.append(p)
            self.sseq += len(data)
            a = self._l2(True)
            a[TCP].flags = "A"
            a[TCP].seq = self.cseq
            a[TCP].ack = self.sseq
            self.pkts.append(a)
            self.cack = self.sseq

    def teardown(self):
        p = self._l2(True)
        p[TCP].flags = "FA"
        p[TCP].seq = self.cseq
        p[TCP].ack = self.sseq
        self.pkts.append(p)
        self.cseq += 1

        p = self._l2(False)
        p[TCP].flags = "FA"
        p[TCP].seq = self.sseq
        p[TCP].ack = self.cseq
        self.pkts.append(p)
        self.sseq += 1

        p = self._l2(True)
        p[TCP].flags = "A"
        p[TCP].seq = self.cseq
        p[TCP].ack = self.sseq
        self.pkts.append(p)


def main():
    f = Flow()
    f.handshake()

    # Banners
    f.send(CLIENT_BANNER, to_server=True)
    f.send(SERVER_BANNER, to_server=False)

    # Oversized KEXINIT: header + 4 body bytes processed alone, then the
    # remaining 65531 body bytes (segmented, IPv4 cannot carry them at once).
    f.send(LONG_KEXINIT_HEADER, to_server=True)
    chunk = 8192
    body = LONG_KEXINIT_BODY_REMAINING
    for off in range(0, len(body), chunk):
        f.send(body[off:off + chunk], to_server=True)

    # Well-formed KEXINIT records in both directions.
    f.send(CLIENT_KEXINIT, to_server=True)
    f.send(SERVER_KEXINIT, to_server=False)

    # NEWKEYS in both directions to finish the transaction (so the ssh event
    # is logged with both hashes).
    f.send(NEWKEYS, to_server=True)
    f.send(NEWKEYS, to_server=False)

    f.teardown()

    wrpcap("input.pcap", f.pkts)
    print("wrote input.pcap with %d packets" % len(f.pkts))


if __name__ == "__main__":
    main()
