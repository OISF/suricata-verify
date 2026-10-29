# Redmine issue 8949 LDAP gap resynchronization

The pcap contains two LDAP-over-TCP flows. One has a to-server stream gap and
the other has a to-client stream gap. In each direction, the first post-gap
slice contains only a BER sequence tag and is therefore incomplete. A complete
LDAP message follows in a later slice.

The LDAP parser must retain its gap state after the incomplete slice, recover
at the next complete PDU boundary, and continue LDAP logging and detection
without entering a parser error state.

Regenerate `input.pcap` with:

```sh
./writepcap.py
```
