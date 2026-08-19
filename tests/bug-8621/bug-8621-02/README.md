Directional rules must only match the DHCP transaction for their own
direction.

Each DHCP datagram is a standalone, single-direction transaction. With the
fix for issue 8621 the transaction carries the SKIP_INSPECT bit for the
direction it will never be seen in, so a toserver rule only matches the
request and a toclient rule only matches the reply. Before the fix both
directional rules could fire on both transactions.

Related ticket:
https://redmine.openinfosecfoundation.org/issues/8621
