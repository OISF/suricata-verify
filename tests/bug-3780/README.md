Description
===========
Negated content with distance gives a false positive alert.
The rule keyword sequence to make that alert happen for the given pcap is

```
content:"|C0 0C 00 10 00 01|"; content:!"v=spf"; distance:0;
```

PCAP
====
PCAP comes from redmine ticket [3780](https://redmine.openinfosecfoundation.org/issues/3780)

Redmine ticket
==============
https://redmine.openinfosecfoundation.org/issues/3780
