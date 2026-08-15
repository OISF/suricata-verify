Purpose
-------

A backend-side RowDescription ('T') or DataRow ('D') declares a field count
that does not match the body its length field delimits -- either more fields
than the body can hold, or fewer.

The rest of the response must still be inspected: the message boundary is
known from the length field, so parsing continues with the next message, the
mismatch is reported, and the declared count is logged as sent.

Flows
-----

Each flow sends a query, then the crafted (or well-formed) message in its own
segment, then the messages that follow in a separate segment.

    47830  'D', body too short for the declared count   4400000007000100
    47831  'T', no field-name terminator in the body    540000000800014142
    47832  'T', declares 65535 fields in a 4-byte body  540000000affff41004243
    47833  'T', body is only a terminator               5400000007000100
    47834  control, well-formed

47830 sends no well-formed DataRow of its own, so its only data row is the
crafted one: counted, but contributing no data size.

Before the fix: 47830, 47831 and 47832 logged an empty `pgsql.response`, and
47833 logged identically to the control.

Pcap
----

Crafted by Claude, using scapy and the ticket description for reproducing
traffic. See `writepcap.py`.

Ticket
------

https://redmine.openinfosecfoundation.org/issues/8885
