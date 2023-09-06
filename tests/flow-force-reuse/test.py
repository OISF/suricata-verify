import ipaddress
import itertools

from scapy.all import IP, TCP, Ether, wrpcap
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse

LATENCY = 0.01


def ip_to_mac(ip_addr):
    num = int(ip_addr)
    mbytes = [0x00, 0x1a, 0xeb]
    for shift in range(3, 0, -1):
        mask = 0xff << (8 * shift)
        byte = (num & mask) >> (8 * shift)
        mbytes.append(byte)
    return ':'.join(map(lambda byte: f'{byte:02X}', mbytes))


def pkt(src_addr, dst_addr):
    src_mac = ip_to_mac(src_addr)
    dst_mac = ip_to_mac(dst_addr)
    eth_hdr = Ether(src=src_mac, dst=dst_mac)
    return eth_hdr / IP(src=src_addr, dst=dst_addr)


def ip_to_ephermeral_port(ip_addr):
    start, end = 32768, 60999  # Use Linux ephemeral port range
    port = start + (int(ip_addr) % (end - start))
    return port


def ip_to_tcp_seq(ip_addr):
    return int(ip_addr)


def tcp_handshake(client_ip, server_ip, timestamp):
    client_port = ip_to_ephermeral_port(client_ip)
    server_port = 80

    tcp_seq = ip_to_tcp_seq(client_ip)
    tcp_ack = ip_to_tcp_seq(server_ip)

    syn = pkt(client_ip, server_ip)
    syn /= TCP(sport=client_port, dport=server_port, flags='S',
               seq=tcp_seq)
    syn.time = timestamp

    syn_ack = pkt(server_ip, client_ip)
    syn_ack /= TCP(sport=server_port, dport=client_port, flags='SA',
                   seq=tcp_ack, ack=tcp_seq + 1)
    syn_ack.time = timestamp + LATENCY

    ack = pkt(client_ip, server_ip)
    ack /= TCP(sport=client_port, dport=server_port, flags='A',
               seq=tcp_seq + 1, ack=tcp_ack + 1)
    ack.time = timestamp + 2 * LATENCY

    return [syn, syn_ack, ack]


def http_transaction(client_ip, flow, timestamp=None):
    last_flow = flow[-1]

    # If no timestamp, just continue from last packet
    if timestamp is None:
        timestamp = last_flow.time + LATENCY

    # Get current TCP seqence numbers, this is only called
    # after a completed transaction, if HTTP the TCP ack of
    # the client needs to be incremented.
    if HTTP in last_flow:
        tcp_seq, tcp_ack = last_flow[TCP].ack, last_flow[TCP].seq + len(last_flow[HTTP])
    else:
        tcp_seq, tcp_ack = last_flow[TCP].seq, last_flow[TCP].ack

    def flow_has_src(flow):
        return int(client_ip) == int(flow[IP].src)

    # Copy Eth and IP headers of packets
    last_client = next(filter(flow_has_src, reversed(flow)))
    last_server = next(filter(lambda f: not flow_has_src(f), reversed(flow)))

    client_request = last_client[Ether].copy()
    client_request[IP].remove_payload()
    client_request /= TCP(sport=last_client.sport, dport=last_client.dport,
                          flags='A', seq=tcp_seq, ack=tcp_ack)
    client_request /= HTTP()
    client_request /= HTTPRequest(Host='suricata.io', Path=f'/style-{len(flow)}.css')
    client_request.time = timestamp
    tcp_seq += len(client_request[HTTP])

    server_reply = last_server[Ether].copy()
    server_reply[IP].remove_payload()
    server_reply /= TCP(sport=last_server.sport, dport=last_server.dport,
                        flags='PA', seq=tcp_ack, ack=tcp_seq)
    server_reply /= HTTP()
    http_body = f'a .style{len(flow)} {{font-size: {len(flow)}rem;}}'
    server_reply /= HTTPResponse(Content_Length=str(len(http_body)),
                                 Content_Type='text/css', Server='FakeServer/0.1')
    server_reply /= http_body
    server_reply.time = timestamp + LATENCY

    flow.extend([client_request, server_reply])
    return flow


def main():
    client_addrs = list(ipaddress.ip_network('1.1.1.0/28').hosts())
    server_addr = ipaddress.ip_address('2.2.2.1')

    first_flow = http_transaction(client_addrs[0], tcp_handshake(client_addrs[0], server_addr, 0))

    client_flows = first_flow[:]
    client_flows.extend(itertools.chain.from_iterable([
        http_transaction(client_addr, tcp_handshake(client_addr, server_addr, 5 + 0.5 * i))
        for i, client_addr in enumerate(client_addrs[1:])
    ]))

    # Send another http transaction from the first flow
    last_ts = client_flows[-1].time + 1
    client_flows.extend(http_transaction(client_addrs[0], first_flow, last_ts)[-2:])

    wrpcap('test.pcap', client_flows)


main()
