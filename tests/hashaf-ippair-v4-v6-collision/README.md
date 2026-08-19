# IPv4/IPv6 IPPair hash collision

Checks that an IPv6 packet cannot reuse IPv4 IPPair state when all packets are
forced into one IPPair hash bucket.

The pcap contains:

1. UDP/IPv4 `1.2.3.4:1111 -> 5.6.7.8:2222` with payload `SETFLOW`.
2. UDP/IPv6 `[102:304::]:1111 -> [506:708::]:2222` with payload `HITFLOW`.

The rules are explicitly limited to `ipv4` for the `SETFLOW` packet and `ipv6`
for the `HITFLOW` packet. The IPv6 address words match the raw IPv4 address
words with the remaining words zero. With `ippair.hash-size=1`, an IPPair compare
function that ignores `Address.family` can treat the IPv6 pair as the existing
IPv4 pair. The second rule must not alert.
