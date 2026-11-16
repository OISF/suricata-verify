# ruletype-firewall-608: LTE retirement with a trailer rule of the same group

560 with a second rule of the same hook and a higher iid:

```
accept:flow,alert http2:stream:<request_headers $HOME_NET any -> $EXTERNAL_NET any (http.header; content:"x-note"; sid:110; rev:1;)
accept:flow,alert http2:stream:<request_headers $HOME_NET any -> $EXTERNAL_NET any (http.host; content:"never.example"; sid:120; rev:1;)
```

`x-note` is in the trailer HEADERS frame, so rule 110 can only match two progress
values above its hook. Rule 120's buffer is complete at the hook, so retiring the
group on the last rule of the group there takes the whole group out of the list and
sid 110 is never inspected: the trailer frame at packet 8 matches nothing.

An http2 tx can rewrite a header buffer above the hook, so the group is not final at
``C`` and its window must stay filled until the tx ends. Expected: sid 110 alerts at
packet 8, no drop, sid 120 silent.

pcap: frames 1-9, request HEADERS frame 4, body DATA frame 6, trailer HEADERS at frame 8.
