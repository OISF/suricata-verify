Test
----

Showcase Suricata behavior when encountering async traffic from the client side
without the ``syn`` packet, and having ``stream.async-oneside: false``.

Pcap
----

Used the same from test ``bug-2491-02`` to also showcase what changes (since in that test
``stream.async-oneside: true``.

Ticket
------

https://redmine.openinfosecfoundation.org/issues/6063
