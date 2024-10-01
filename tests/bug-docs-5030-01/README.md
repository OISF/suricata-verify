# Test

Showcase the usage of `distance`, `within` and `endswith`, as proposed
in https://redmine.openinfosecfoundation.org/issues/5030.

## Behavior

There should be an alert. "The distance and within effectively limit how much
of a payload can be present while ensuring the packet still "endswith" the
desired content." This happens for this pcap.

## Pcap

35_bytes.pcap Shared by Brandon Murphy in the aforementioned ticket.

## Redmine ticket

https://redmine.openinfosecfoundation.org/issues/5030
