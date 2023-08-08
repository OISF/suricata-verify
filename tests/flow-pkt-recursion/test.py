from pathlib import Path

from scapy.all import ICMP, IP, Ether, IPv6, PcapWriter, Raw

mac_1, mac_2 = 'cb:cf:2b:50:a7:61', '49:a2:25:1a:07:4a'

request = Ether(src=mac_1, dst=mac_2)
reply = Ether(src=mac_2, dst=mac_1)

ip_1, ip_2 = '1.1.1.1', '2.2.2.2'
ipv6_1, ipv6_2 = 'fd01::1.1.1.1', 'fd02::2.2.2.2'

payload = Raw(b'#JSb[abR^79aV(kDAN,(C\n\\A+p V+MF7\rd9Z&&9D31.;T%\x0ct.#')
icmp_echo = ICMP(type=8, seq=1) / payload
icmp_reply = ICMP(type=0, seq=1) / payload

middleware_pcap = Path.cwd() / 'middleware-pkt-flows.pcap'
with PcapWriter(str(middleware_pcap)) as pcap:
    # Flow of IPv6 tunneled packets in both directions
    pcap.write(request / IPv6(src=ipv6_1, dst=ipv6_2) / IP(src=ip_1, dst=ip_2) / icmp_echo)
    pcap.write(reply / IPv6(src=ipv6_2, dst=ipv6_1) / IP(src=ip_2, dst=ip_1) / icmp_reply)

terminated_pcap = Path.cwd() / 'tunnel-pkt-flows.pcap'
with PcapWriter(str(terminated_pcap)) as pcap:
    # Flow of tunnel terminated on Suricata device, echo originates
    # from Suricata device
    pcap.write(request / IP(src=ip_1, dst=ip_2) / icmp_echo)
    pcap.write(reply / IPv6(src=ipv6_2, dst=ipv6_1) / IP(src=ip_2, dst=ip_1) / icmp_reply)

    # Flow of tunnel terminated on Suricata device, reply originates
    # from Suricata device
    pcap.write(reply / IPv6(src=ipv6_2, dst=ipv6_1) / IP(src=ip_2, dst=ip_1) / icmp_echo)
    pcap.write(request / IP(src=ip_1, dst=ip_2) / icmp_reply)
