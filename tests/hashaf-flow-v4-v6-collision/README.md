# IPv4/IPv6 flow hash collision

Checks that an IPv6 packet cannot reuse an IPv4 `Flow` when all packets are
forced into one flow hash bucket.

The pcap contains:

1. UDP/IPv4 `1.2.3.4:1111 -> 5.6.7.8:2222` with payload `SETFLOW`.
2. UDP/IPv6 `[102:304::]:1111 -> [506:708::]:2222` with payload `HITFLOW`.

The rules are explicitly limited to `ipv4` for the `SETFLOW` packet and `ipv6`
for the `HITFLOW` packet. The IPv6 address words match the raw IPv4 address
words with the remaining words zero. With `flow.hash-size=1`, a compare function
that ignores the address family can treat the IPv6 packet as belonging to the
existing IPv4 flow. The second rule must not alert.
