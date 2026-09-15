# modbus-keywords-write

Test modbus.write.quantity, modbus.write.value and modbus.write.address
on multiple-write, mask-write and single-write transactions
(https://redmine.openinfosecfoundation.org/issues/8131).

Multiple-write responses echo the written quantity in the value field
of the protocol; this test checks that modbus.write.quantity matches
that echo and that modbus.write.value does not.

## PCAP

input.pcap is synthetic, generated with generate-pcap.py (scapy):
a Modbus/TCP session with Write Multiple Registers (fc 16),
Mask Write Register (fc 22) and Write Single Register (fc 6)
transactions and their responses.
