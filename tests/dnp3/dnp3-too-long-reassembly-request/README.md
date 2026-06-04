DNP3 request reassembly test for the too_long_reassembly decoder event.

The pcap contains one TCP flow with 65 max-sized DNP3 request transport
segments. The reassembled request application data exceeds the 63 * 0xff
transport sequence-space bound and should raise sid 2270007.

Generated with create-pcap.py.

Tickets: #8460
