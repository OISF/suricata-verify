Test Description
================

This test demonstrates the unset operation for datasets.

PCAP
====

Running as server `python3 -m http.server 8001`
And as clients
```
curl -A "useragent1" http://127.0.0.1:8001/toto
curl -A "useragent2" http://127.0.0.1:8001/toto
curl -A "useragent1" http://127.0.0.1:8001/tata
```

Related tickets
===============

https://redmine.openinfosecfoundation.org/issues/7195
