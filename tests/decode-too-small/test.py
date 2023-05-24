from scapy.all import Ether, IP, IPv6, PcapWriter, Raw

with PcapWriter('test.pcap') as pcap:
    # TCP and UDP too small packets
    udp_payload = Raw(b'\x81\x58\x00\x35')  # Half a UDP header
    s_mac = 'cb:cf:2b:50:a7:61'
    d_mac = '49:a2:25:1a:07:4a'
    proto_udp = 17
    proto_tcp = 6

    pcap.write(Ether(src=s_mac, dst=d_mac) / IP(src='1.1.1.1', dst='2.2.2.2', proto=proto_tcp))
    pcap.write(Ether(src=s_mac, dst=d_mac) / IP(src='1.1.1.1', dst='2.2.2.2', proto=proto_udp))
    pcap.write(Ether(src=s_mac, dst=d_mac) / IP(src='1.1.1.1', dst='2.2.2.2', proto=proto_udp) / udp_payload)
    pcap.write(Ether(src=s_mac, dst=d_mac) / IPv6(src='fd01::1.1.1.1', dst='fd02::2.2.2.2', nh=proto_tcp))
    pcap.write(Ether(src=s_mac, dst=d_mac) / IPv6(src='fd01::1.1.1.1', dst='fd02::2.2.2.2', nh=proto_udp))
    pcap.write(Ether(src=s_mac, dst=d_mac) / IPv6(src='fd01::1.1.1.1', dst='fd02::2.2.2.2', nh=proto_udp) / udp_payload)
