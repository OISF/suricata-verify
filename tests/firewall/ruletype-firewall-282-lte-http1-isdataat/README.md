# ruletype-firewall-282-lte-http1-isdataat

Rounds out the LTE buffer-predicate set with `isdataat` instead of `content`:
the `<request_line` rule checks that the `http.uri` buffer has data at offset 5
and accepts the flow at packet 6 with the `http:request_line` hook.
