# Description

Test protocol detection when flow starts from midstream from 'to client' direction

# PCAP

The pcap is a mqtt communication with missing client request.
It starts from the server response and the first message is split between 2 TCP segments.
So probing parser returns 'incomplete' after the first one.
