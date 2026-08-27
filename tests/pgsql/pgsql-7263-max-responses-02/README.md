Purpose
-------

Cover `pgsql.max-responses` defaulting to the built-in max, when an invalid
setting is used.

`max-responses` is set to 0 here to check it will default to the
pre-defined max value of 64.

Pcap
----

Similar to the script for pgsql-7263-max-responses-01, but inflating
ParameterStatus with custom values, to exercise the cap with the default value.

Ticket
------

https://redmine.openinfosecfoundation.org/issues/7263
