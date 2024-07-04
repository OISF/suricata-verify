Test the following sequence of DNS messages on a flow:

- DNS request with ID 0x99ab.
- DNS response with ID 0x9941 (unsolicited response).
- DNS response with ID 0x99ab (expected response).

Check that all 3 DNS message are logged, and that an unsolicted dns
response event is logged.

NOTE: Unsolicited responses do not exist with the Rust DNS parser as
it doesn't correlate responses with requests.
