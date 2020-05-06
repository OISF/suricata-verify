#!/usr/bin/env python
from scapy.all import *
import struct

pkts = []

# First flow
pkts += Ether()/ \
    IP(src='190.0.0.1', dst='190.0.0.2')/ \
    ESP(spi=123, seq=1)
pkts += Ether()/ \
    IP(src='190.0.0.1', dst='190.0.0.2')/ \
    ESP(spi=123, seq=2)

# Second flow
# Same src/dst, diffrent SPI
pkts += Ether()/ \
    IP(src='190.0.0.1', dst='190.0.0.2')/ \
    ESP(spi=321, seq=1)
pkts += Ether()/ \
    IP(src='190.0.0.1', dst='190.0.0.2')/ \
    ESP(spi=321, seq=2)

# Third flow
# Same SPI, different dst
pkts += Ether()/ \
    IP(src='190.0.0.1', dst='190.0.0.3')/ \
    ESP(spi=123, seq=1)
pkts += Ether()/ \
    IP(src='190.0.0.1', dst='190.0.0.3')/ \
    ESP(spi=123, seq=2)

# Fourth flow
# IPv6
pkts += Ether()/ \
    IPv6(src='::1', dst='::2')/ \
    ESP(spi=123, seq=1)
pkts += Ether()/ \
    IPv6(src='::1', dst='::2')/ \
    ESP(spi=123, seq=2)

wrpcap('input.pcap', pkts)
