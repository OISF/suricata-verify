# modbus-keywords-enum

Test that modbus.function, modbus.subfunction and modbus.exception_code
accept the code names logged in function_code, diagnostic.code and
exception.code as well as the numeric values
(https://redmine.openinfosecfoundation.org/issues/8131).

Each name is paired with the numeric rule it should behave like, so the
two signatures of a pair are expected to alert the same number of times.
Names are matched case insensitively and can be negated.

## PCAP

Reuses ../modbus/modbus.pcap.
