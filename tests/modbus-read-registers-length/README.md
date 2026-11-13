# Description

Modbus/TCP read responses are checked against their requests: a Read Holding
Registers or Read Input Registers response carries two octets per register,
and a Read Coils response one bit per coil. Only a response with the wrong
number of octets raises "Modbus Data mismatch".

- tid 1: Read Holding Registers, 11 registers, correct response
- tid 2: Read Input Registers, 2 registers, correct response
- tid 3: Read Coils, 11 coils, correct response
- tid 4: Read Holding Registers, 2 registers, response one register short

## PCAP

Generated with `create-pcap.py` (Scapy).

## Ticket

https://redmine.openinfosecfoundation.org/issues/9208
