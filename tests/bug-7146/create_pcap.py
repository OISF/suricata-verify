from scapy.all import Ether, IP, Raw, wrpcap

# 253 and 254 are "experimental / unused" protocol numbers
UNKNOWN_PROTO = 253

# Build Ethernet + IPv4 header with unknown protocol
pkt = (
    Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") /
    IP(src="192.168.1.10", dst="192.168.1.20", proto=UNKNOWN_PROTO) /
    Raw(b"hello-unknown-proto")
)

# Write to pcap file
wrpcap("input.pcap", pkt)

print("Wrote input.pcap")
