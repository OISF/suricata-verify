# Test Description

Test that we parse weird HTTP (adding lots of whitespaces) not as HTTP/0.9

## PCAP

Crafted by running server `python3 -m http.server 8000` and a dummy client sending hardcoded data

## Related issues

https://redmine.openinfosecfoundation.org/issues/6757
