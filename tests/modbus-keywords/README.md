# modbus-keywords

Test the per-value Modbus detection keywords (modbus.unit_id,
modbus.transaction_id, modbus.protocol_id, modbus.function,
modbus.subfunction, modbus.exception_code, modbus.read.address,
modbus.read.quantity, modbus.write.address, modbus.write.value)
introduced in Suricata 9 (https://redmine.openinfosecfoundation.org/issues/8131),
including negation, range and direction-pinned cases.

modbus.write.quantity is covered by the modbus-keywords-write test,
as this pcap contains no multiple-write transaction.

## PCAP

Reuses ../modbus/modbus.pcap.
