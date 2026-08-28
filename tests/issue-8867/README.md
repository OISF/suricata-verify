# Redmine issue 8867

Regression coverage for draining libhtp warning messages beyond the 512-message
boundary and for deduplicating attacker-controlled warnings within one HTTP/1
transaction.

The capture contains four HTTP flows:

- three request chunks with extensions in one transaction;
- three response chunks with extensions in one transaction;
- three `100 Continue` responses followed by a final response;
- 513 request/response transactions with one request chunk extension each.

The first three flows must each produce only one anomaly update for the repeated
warning source. The last flow deliberately queues 513 warnings; it must emit
`too_many_warnings` at message 512 and retain the request chunk extension event
on transaction 512.

Regenerate the capture with:

```
python3 writepcap.py
```
