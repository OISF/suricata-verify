from scapy.all import Ether, IP, IPv6, PcapWriter, Raw

with PcapWriter('test.pcap') as pcap:
    # Too small packets
    udp_payload = Raw(b'\x81\x58\x00\x35')  # Half a UDP header
    gre_payload = Raw(b'\x00\x00') # Half of non-optional GRE hdr

    proto_gre = 47
    proto_udp = 17
    proto_tcp = 6

    def mk_pkt(proto, ver=4):
        s_mac, d_mac = 'cb:cf:2b:50:a7:61', '49:a2:25:1a:07:4a'
        pkt = Ether(src=s_mac, dst=d_mac)
        if ver == 4:
            s_ip, d_ip = '1.1.1.1', '2.2.2.2'
            pkt /= IP(src=s_ip, dst=d_ip, proto=proto)
        else:
            s_ipv6 = f'fd01::1.1.1.1'
            d_ipv6 = f'fd02::2.2.2.2'
            pkt /= IPv6(src=s_ipv6, dst=d_ipv6, nh=proto)
        return pkt

    pcap.write(mk_pkt(proto_tcp))
    pcap.write(mk_pkt(proto_udp))
    pcap.write(mk_pkt(proto_udp) / udp_payload)
    pcap.write(mk_pkt(proto_gre) / gre_payload)
    pcap.write(mk_pkt(proto_tcp, ver=6))
    pcap.write(mk_pkt(proto_udp, ver=6))
    pcap.write(mk_pkt(proto_udp, ver=6) / udp_payload)
    pcap.write(mk_pkt(proto_gre, ver=6) / gre_payload)
