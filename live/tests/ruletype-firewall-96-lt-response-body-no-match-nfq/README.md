# Firewall response body no match

Port of `ruletype-firewall-96-lt-response-body-no-match` as a live NFQ
firewall test.

The server returns the classic testmyids.org response body:

```text
uid=0(root) gid=0(root) groups=0(root)
```

The firewall rules only allow response bodies containing `suricata`, so this
response should be blocked.
