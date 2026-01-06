from scapy.all import *
import struct
import sys

# Configuration
NUM_PACKETS = 33
OUTPUT_FILENAME = f"dnp3-{NUM_PACKETS}-inflight.pcap"

def dnp3_crc(data):
    crc = 0x0000
    for byte in data:
        crc = crc ^ byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA6BC
            else:
                crc = crc >> 1
    c = (~crc) & 0xFFFF
    return c.to_bytes(2, byteorder='little')

def build_dnp3_frame(transport_seq, app_seq, src_addr, dst_addr, is_request=True):
    # Construct User Data
    # Transport Header
    # FIN=1, FIR=1, SEQ
    th = 0xC0 | (transport_seq & 0x3F)
    
    # App Header
    # FIN=1, FIR=1, CON=0, SEQ
    ah = 0xC0 | (app_seq & 0x0F)
    
    if is_request:
        # Select Request
        # Funct: 03 (Select)
        # Obj 12, Var 1, Qual 28, Range 1, Index 1
        # Code 3 (Latch On), Count 1, On 100, Off 100, Status 0
        payload = bytes.fromhex("03 0c 01 28 01 00 01 00 03 01 64 00 00 00 64 00 00 00 00")
    else:
        # Response
        # Funct: 81 (Response)
        # IIN: 00 00
        # Then same object data usually
        payload = bytes.fromhex("81 00 00 0c 01 28 01 00 01 00 03 01 64 00 00 00 64 00 00 00 00")

    user_data = bytes([th, ah]) + payload
    
    # Calculate chunks for the wire (with CRCs)
    chunks = []
    chunk_size = 16
    for i in range(0, len(user_data), chunk_size):
        chunk = user_data[i:i+chunk_size]
        crc = dnp3_crc(chunk)
        chunks.append(chunk + crc)
        
    full_payload_with_crcs = b"".join(chunks)
    
    # Calculate DNP3 Length Field
    # Length = 5 (Ctrl + Dst + Src) + User Data Length (excluding CRCs)
    length = 5 + len(user_data)
    
    # Header
    # Start 05 64
    # Len
    # Ctrl: DIR=1, PRM=1 (Request) or 0 (Response)?
    # Template Request: c4 (DIR=1, PRM=1)
    # Template Response: 44 (DIR=0, PRM=1) -> Outstation to Master.
    
    ctrl = 0xC4 if is_request else 0x44
    
    # Dst, Src (2 bytes each, LE)
    dst_bytes = dst_addr.to_bytes(2, byteorder='little')
    src_bytes = src_addr.to_bytes(2, byteorder='little')
    
    header_block = bytes([0x05, 0x64, length, ctrl]) + dst_bytes + src_bytes
    header_crc = dnp3_crc(header_block)
    
    return header_block + header_crc + full_payload_with_crcs

# IP/TCP config
src_ip = "192.168.1.100"
dst_ip = "192.168.1.200"
src_port = 49404
dst_port = 20000

# Initial Sequence Numbers
client_seq = 1000
server_seq = 5000

packets = []

# Handshake
syn = IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags="S", seq=client_seq)
packets.append(syn)
client_seq += 1

synack = IP(src=dst_ip, dst=src_ip)/TCP(sport=dst_port, dport=src_port, flags="SA", seq=server_seq, ack=client_seq)
packets.append(synack)
server_seq += 1

ack = IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags="A", seq=client_seq, ack=server_seq)
packets.append(ack)

# Requests
req_dnp_addr_src = 3
req_dnp_addr_dst = 2

for i in range(NUM_PACKETS):
    dnp_frame = build_dnp3_frame(i, i, req_dnp_addr_src, req_dnp_addr_dst, is_request=True)
    
    pkt = IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags="PA", seq=client_seq, ack=server_seq)/Raw(load=dnp_frame)
    packets.append(pkt)
    client_seq += len(dnp_frame)

# Server ACKs all requests
ack_server = IP(src=dst_ip, dst=src_ip)/TCP(sport=dst_port, dport=src_port, flags="A", seq=server_seq, ack=client_seq)
packets.append(ack_server)

# Teardown
fin = IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags="FA", seq=client_seq, ack=server_seq)
packets.append(fin)
client_seq += 1

finack = IP(src=dst_ip, dst=src_ip)/TCP(sport=dst_port, dport=src_port, flags="FA", seq=server_seq, ack=client_seq)
packets.append(finack)
server_seq += 1

ack_final = IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags="A", seq=client_seq, ack=server_seq)
packets.append(ack_final)

wrpcap(OUTPUT_FILENAME, packets)
print(f"Created {OUTPUT_FILENAME}")
