# A pending rule above every candidate still accepts the packet

What the case pins
------------------

sid 100 is an `accept:hook` rule at an earlier state and is the only candidate the fast
pattern brings back above the hook; sid 110 is the LTE rule of the growable group, pending
with a higher id than every candidate. The candidate loop therefore never reaches a rule
above the pending one, and a build that only accounts for pending rules when it does never
runs 110's accept. The packet then falls to the `packet.filter` default policy - which is
`drop:packet` unless the config overrides it - so the request packets of a flow that ends
up accepted are dropped.

This yaml has no `packet:` block on purpose. The rest of the firewall corpus sets
`packet.default-policy: ["accept:hook"]`, and that override is what hid the path.

Rules
-----

    accept:hook http1:request_line ... (http.method; content:"POST"; sid:100;)
    accept:flow,alert http1:<request_headers ... (http.header; content:"Content-Length: 46"; sid:110;)

`gen_pcap.py` builds the flow (it is 607's pcap, unchanged): the POST request line and the
`Host:` header at packet 4 with the header block left open, the `Content-Length` line
closing it at packet 6, where 110's pattern lands.

Results
-------

| build | outcome |
|---|---|
| target `1e8504abe` | no drop, alert 110 @6 `allowed`, flow `accept` |
| before the fix | **drop @4**, alert 110 @6, flow `accept` |
| this branch | no drop, alert 110 @6 `allowed`, flow `accept` |

Fixture from the review bundle `~/share/review/106/missing-packet-accept/`.
