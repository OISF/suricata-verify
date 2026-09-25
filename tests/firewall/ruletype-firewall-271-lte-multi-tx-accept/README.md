# ruletype-firewall-271-lte-multi-tx-accept

Cross-transaction LTE resolution: the flow carries 8 requests (reusing
`ruletype-firewall-17-http-txbits-multi-tx/http-sticky-server-s8.pcap`), and the
LTE rule at `http1:<request_headers` matches in the first transaction, accepts
the flow, and must not let the app state default policy decide any of the
remaining transactions.

## Expected

* one `sid:100` alert at packet 4 (`http:request_headers`, allowed);
* no drops at all, and `stats.firewall.accepted` 27 with every drop reason 0;
* the flow ends accepted and alerted.
