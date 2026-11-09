# detect-bidir-doh2-tc-fast-pattern-ips

The IPS-mode variant of `detect-bidir-doh2-tc-fast-pattern`: transactional
(`=>`) rules on a DoH2 POST whose fast pattern is on the response half, on the
same capture (Redmine #9087). In IPS mode each segment is parsed as it
arrives, so the response HEADERS (pcap_cnt 16) are inspected before the
response DATA (17) that carries the DNS message. On the HEADERS pass a rule
with its fast pattern on `http.stat_code` already has its response half; its
DNS request half must then be looked up as the DNS request of the transaction
and waited for. Looked up as the DNS response it does not exist yet, and a
pair that drops the request half as not applicable alerts on the status code
alone, even when the request half does not match (sid 5).

See the sibling test for the packet list, the rules and how the capture was
made.
