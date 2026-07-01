A DHCP request/reply exchange must produce one alert per datagram, not
one per direction.

DHCP is a stateless parser where each datagram is a standalone,
single-direction transaction. Before the fix for issue 8621 the
transactions were created without the per-direction SKIP_INSPECT bits, so
each transaction was inspected in both the toserver and toclient
directions and a matching rule alerted twice.

Related ticket:
https://redmine.openinfosecfoundation.org/issues/8621
