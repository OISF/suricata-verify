#!/usr/bin/env python3
"""Generate sip-log-limits.pcap: oversized SIP request URI and SDP fields."""

from scapy.all import IP, UDP, Raw, wrpcap

uri = "sip:" + "a" * 9000 + "@example.com"
sdp = "\r\n".join([
    "v=0",
    "o=alice 2890844526 2890844526 IN IP4 192.168.1.10",
    "s=" + "A" * 20000,
    "c=IN IP4 192.168.1.10",
    "t=0 0",
    "k=clear:supersecretsessionkey",
    "a=" + "b" * 6000,
    "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:cryptosecretsessionkey|2^20|1:32",
    "m=audio 49170 RTP/AVP 0",
    "k=clear:supersecretmediakey",
    "a=crypto:2 AES_CM_128_HMAC_SHA1_80 inline:cryptosecretmediakey|2^20|1:32",
    "a=rtpmap:0 PCMU/8000",
]) + "\r\n"
body = sdp.encode()
msg = "\r\n".join([
    f"INVITE {uri} SIP/2.0",
    "Via: SIP/2.0/UDP 192.168.1.10:5060;branch=z9hG4bK776asdhds",
    "Max-Forwards: 70",
    "From: Alice <sip:alice@example.com>;tag=1928301774",
    "To: Bob <sip:bob@example.com>",
    "Call-ID: a84b4c76e66710@pc33.example.com",
    "CSeq: 314159 INVITE",
    "Contact: <sip:alice@192.168.1.10>",
    "Content-Type: application/sdp",
    f"Content-Length: {len(body)}",
    "",
    "",
])
pkt = (
    IP(src="192.168.1.10", dst="192.168.1.20")
    / UDP(sport=5060, dport=5060)
    / Raw(msg.encode() + body)
)
wrpcap("sip-log-limits.pcap", [pkt])
