# ruletype-firewall-274-lte-absent-body-positive

The positive `absent` case: the fixture's requests are GETs with no body, so the
`http.request_body; absent` LTE rule at `http1:<request_body` matches once the
request_body state is reached and accepts the flow.

## Expected

* one `sid:100` alert at packet 4 (`http:request_body`, allowed);
* no drops;
* the flow accepted and alerted.
