#!/usr/bin/env python

from uuid import uuid4
from scapy.all import wrpcap, Ether, IP, UDP
from scapy.contrib.dce_rpc import DceRpc


def create_pkt(rtype, seqnum, obj, iface, act):
    """
    Create a DCE/RPC over UDP packet as per the given arguments.
    This function is responsible for creating request as well as
    response packets.

    Scapy layering has been done (default) as per the TCP/IP model.

                Data Link Layer (Ether)
                        |
                Internet Layer (IP)
                        |
                Transport Layer (UDP)
                        |
                Application Layer (DceRpc)

    """
    # sport and dport at default make the packet be detected as
    # a DNS packet by Wireshark so change it
    return Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05') / \
        IP(dst='255.255.255.255', src='192.168.0.1') / \
        UDP(sport=80, dport=8000) / \
        DceRpc(
        type=rtype,
        flags1=0x01,
        sequence_num=seqnum,
        object_uuid=obj,
        interface_uuid=iface,
        activity=act,
    )


def create_pcap():
    """
    Method to create a few request response cycles
    """
    pkts = list()
    for i in range(0, 10):
        if i % 2 == 0:
            activity_uuid = uuid4()
            pkts.append(create_pkt(rtype=0,
                                   seqnum=i,
                                   obj=uuid4(),
                                   iface=uuid4(),
                                   act=activity_uuid,))
        else:
            pkts.append(create_pkt(rtype=2,
                                   seqnum=i-1,
                                   obj=uuid4(),
                                   iface=uuid4(),
                                   act=activity_uuid,))
    return pkts


wrpcap('input.pcap', create_pcap())
