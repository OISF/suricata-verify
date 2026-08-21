#!/usr/bin/env python3
# Generates input.pcap: a Modbus/TCP session with a Write Multiple
# Registers (fc 16), a Mask Write Register (fc 22) and a Write Single
# Register (fc 6) transaction, each with its response.
from scapy.all import Ether, IP, TCP, Raw, wrpcap

CLI = "10.0.0.1"; SRV = "10.0.0.2"; CP = 40000; SP = 502
pkts = []; cseq = 1000; sseq = 5000

def pkt(src_cli, flags, payload=b""):
    global cseq, sseq
    if src_cli:
        p = Ether() / IP(src=CLI, dst=SRV) / TCP(
            sport=CP, dport=SP, flags=flags, seq=cseq, ack=sseq)
        cseq += len(payload) + (1 if 'S' in flags or 'F' in flags else 0)
    else:
        p = Ether() / IP(src=SRV, dst=CLI) / TCP(
            sport=SP, dport=CP, flags=flags, seq=sseq, ack=cseq)
        sseq += len(payload) + (1 if 'S' in flags or 'F' in flags else 0)
    if payload:
        p = p / Raw(payload)
    pkts.append(p)

def mbap(txn, pdu):
    return txn.to_bytes(2, 'big') + b'\x00\x00' + \
        (len(pdu) + 1).to_bytes(2, 'big') + b'\x01' + pdu

pkt(True, 'S'); pkt(False, 'SA'); pkt(True, 'A')
# fc16 write multiple registers: addr=100 qty=2 values 0x1111 0x2222
pkt(True, 'PA', mbap(1, bytes([0x10]) + (100).to_bytes(2, 'big')
    + (2).to_bytes(2, 'big') + bytes([4]) + b'\x11\x11\x22\x22'))
pkt(False, 'A')
pkt(False, 'PA', mbap(1, bytes([0x10]) + (100).to_bytes(2, 'big')
    + (2).to_bytes(2, 'big')))
pkt(True, 'A')
# fc22 mask write register: addr=200 and=0x00ff or=0x0f00
pkt(True, 'PA', mbap(2, bytes([0x16]) + (200).to_bytes(2, 'big')
    + b'\x00\xff\x0f\x00'))
pkt(False, 'A')
pkt(False, 'PA', mbap(2, bytes([0x16]) + (200).to_bytes(2, 'big')
    + b'\x00\xff\x0f\x00'))
pkt(True, 'A')
# fc6 write single register: addr=300 value=1234
pkt(True, 'PA', mbap(3, bytes([0x06]) + (300).to_bytes(2, 'big')
    + (1234).to_bytes(2, 'big')))
pkt(False, 'A')
pkt(False, 'PA', mbap(3, bytes([0x06]) + (300).to_bytes(2, 'big')
    + (1234).to_bytes(2, 'big')))
pkt(True, 'A')
pkt(True, 'FA'); pkt(False, 'FA'); pkt(True, 'A')

wrpcap('input.pcap', pkts)
