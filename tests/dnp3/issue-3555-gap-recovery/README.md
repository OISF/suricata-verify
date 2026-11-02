# DNP3 inspection resumes after a TCP gap

Regression test for [Redmine #3555](https://redmine.openinfosecfoundation.org/issues/3555)
and [Suricata PR #16553](https://github.com/OISF/suricata/pull/16553).

Two established TCP connections carry four DNP3 READ/RESPONSE exchanges each:

- Client port 40000: capture loss in the request direction.
- Client port 40001: capture loss in the response direction.

In the second exchange, the capture contains the first 12 bytes of a frame,
omits the next four bytes, and contains the remaining tail. The endpoint ACKs
the omitted bytes, and they are never retransmitted in the capture. This is a
real TCP sequence gap, not malformed application data substituted for a gap.

The parser must discard its buffered partial frame and scan past the orphaned
tail. The first complete frame after the gap has its two start bytes split
across TCP segments. Small, deterministic reassembly chunks exercise recovery
across parser calls.

The application markers are 0x11111111 before the gap, 0x22222222 in the damaged
exchange, 0x33333333 in the first recovered exchange, and 0x44444444 in the later
exchange. Checks assert:

- Exactly two TCP reassembly gaps, with no DNP3 gap/parser errors.
- Three complete messages in each damaged direction, and four in each
  unaffected direction (14 DNP3 records in total).
- The exact pre-gap and post-gap request indices and response values on each
  connection, including both the first and last response point.
- DNP3 function/data rule alerts before the gap and on both later exchanges,
  proving application-layer detection resumes as well as logging.

The generated capture has valid IP, TCP, DNP3 header, and DNP3 data CRCs.
`input.py` is the retained Scapy generator.
