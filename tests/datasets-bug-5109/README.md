Description
===========
A space condition with dataset parsing was not handled which caused rules like
```
alert http any any -> any any (http.user_agent; dataset:set  ,ua-seen,type string,save datasets.csv; sid:1;)
```
Note the spaces after `dataset:set`.
Corresponding redmine ticket: https://redmine.openinfosecfoundation.org/issues/5019

PCAP
====
PCAP is irrelevant to the test but comes from the test [datasets-01](https://github.com/OISF/suricata-verify/blob/master/tests/datasets-01/input.pcap)
