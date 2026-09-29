#!/usr/bin/env python3
"""Generate input.pcap: one SMTP session carrying two complete emails.

Layout (pcap_cnt):
  1-3    TCP handshake
  4      S: 220 greeting (must be the first to-client data, otherwise
       SMTP_PARSER_STATE_FIRST_REPLY_SEEN is never set and no tx is freed)
  5      C: EHLO                       -> tx 0
  6      S: 250
  7      C: MAIL FROM:<alice@example.com>
  8      S: 250
  9      C: RCPT TO:<bob@example.com>
  10     S: 250
  11     C: DATA
  12     S: 354 (a 250 here would be DATA_COMMAND_REJECTED and would leave
       the tx incomplete to-client, so it would never be freed)
  13     C: headers + body
  14     C: .                          -> request complete
  15     S: 250                        -> response complete
  16     C: EHLO
  17     S: 250
  18     C: MAIL FROM:<carol@example.com>  opens tx 1, cleanup frees tx 0
  19     S: 250
  20     C: RCPT TO:<dave@example.com>
  21     S: 250
  22     C: DATA
  23     S: 354
  24     C: headers + body
  25     C: .
  26     S: 250
  27     C: QUIT
  28     S: 221

Each data packet carries the acknowledgement for everything the peer sent, so
the capture is a dialogue rather than a run of un-acknowledged segments, and
detection sees the data the same way it would on a live connection.

Every command goes out in its own packet so that the transactions are
completed and reaped while the flow is still live: the Lua scripts in this
test hold on to the transaction handle of tx 0 and read it again from a
packet that is inspected after tx 0 was freed.
"""

import sys

from scapy.all import Ether, IP, TCP, Raw, wrpcap

CLIENT_MAC = "00:00:00:00:11:11"
SERVER_MAC = "00:00:00:00:22:22"
CLIENT = "10.0.0.1"
SERVER = "10.0.0.2"
CPORT = 4001
SPORT = 25

# the SYN consumes one sequence number, so data starts one past the baseline
CSEQ = 1001
SSEQ = 2001


class Session:
    """Track the sequence numbers of both sides so the stream is in order.

    A SYN and a FIN each consume one sequence number on top of the payload
    length, so the accounting is done here rather than by the caller.

    The acknowledgement each side sends is the next number it expects from the
    peer, which is the peer's running counter as it stands when the packet is
    added: a client packet acknowledges the server up to self.sseq, a server
    packet the client up to self.cseq.
    """

    def __init__(self):
        self.pkts = []
        self.cseq = 1001
        self.sseq = 2001

    def _add(self, src, dst, smac, dmac, sport, dport, seq, ack, flags, payload):
        if "A" not in flags:
            # a bare SYN has nothing acknowledged yet, and the peer's number is
            # not known at this point, so leave the field clear
            ack = 0
        tcp = TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags, window=65535)
        pkt = Ether(src=smac, dst=dmac) / IP(src=src, dst=dst) / tcp
        if payload:
            pkt = pkt / Raw(load=payload.encode())
        self.pkts.append(pkt)
        consumed = len(payload) if payload else 0
        if "S" in flags or "F" in flags:
            consumed += 1
        return pkt, consumed

    def client(self, payload="", flags="PA"):
        pkt, consumed = self._add(
            CLIENT, SERVER, CLIENT_MAC, SERVER_MAC, CPORT, SPORT, self.cseq, self.sseq,
            flags, payload)
        self.cseq += consumed
        return pkt

    def server(self, payload="", flags="PA"):
        pkt, consumed = self._add(
            SERVER, CLIENT, SERVER_MAC, CLIENT_MAC, SPORT, CPORT, self.sseq, self.cseq,
            flags, payload)
        self.sseq += consumed
        return pkt


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "input.pcap"
    s = Session()

    # handshake
    s.client(flags="S")
    s.server(flags="SA")
    s.client(payload="", flags="A")

    def mail(sender, recipient, subject, body):
        s.client("EHLO client.example.com\r\n")
        s.server("250 mail.example.com\r\n")
        s.client("MAIL FROM:<%s>\r\n" % sender)
        s.server("250 2.1.0 Ok\r\n")
        s.client("RCPT TO:<%s>\r\n" % recipient)
        s.server("250 2.1.5 Ok\r\n")
        s.client("DATA\r\n")
        s.server("354 End data with <CR><LF>.<CR><LF>\r\n")
        s.client("Subject: %s\r\nTo: %s\r\nFrom: %s\r\n\r\n%s\r\n" % (subject, recipient, sender, body))
        s.client(".\r\n")
        s.server("250 2.0.0 Ok: queued\r\n")

    # the greeting has to be the very first to-client data
    s.server("220 mail.example.com ESMTP\r\n")
    mail("alice@example.com", "bob@example.com", "first", "hello bob")
    mail("carol@example.com", "dave@example.com", "second", "hello dave")

    s.client("QUIT\r\n")
    s.server("221 Bye\r\n")

    wrpcap(out, s.pkts)
    print("wrote %s (%d packets)" % (out, len(s.pkts)))


if __name__ == "__main__":
    main()
