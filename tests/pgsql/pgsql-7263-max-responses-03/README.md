Purpose
-------

Cover the cap for the two response kinds that are summarised rather
than logged
one by one: the rows of a SELECT, and the data of a COPY TO STDOUT.

`max-responses` is set to 21, the lowest value the parser accepts.

Companion to `pgsql-7263-max-responses-01`, which reaches the cap
during the
startup sequence. A normal query transaction cannot reach the cap, given the
consolidated results. No matter how many rows come back, DataRow and CopyData
are summarised into a single response, so a SELECT reply is four responses deep
and a COPY reply five.

ParameterStatus is what can fill this limit here. The protocol allows it at any
point: the backend reports a parameter whenever its value changes. Names outside
the pre-defined set are reported the same way.


The flows
---------

Both flows open with a trust/no-auth startup reporting the eleven parameters a
real server sends, which fits well within the cap, then run one query whose
reply carries a batch of nineteen parameter reports:

  47830  SELECT age FROM census;  three rows, then the reports. The row
                                  description is kept; the summarised rows and
                                  the command completion are not.
  47831  COPY census TO STDOUT;   three rows of COPY output, then the reports.
                                  The copy-out header is kept; the copy data,
                                  the copy-done and the command completion are
                                  not.

Each flow's BackendKeyData carries a distinct pid, so a filter can confirm the
startup transaction kept it.

There is deliberately no "it all fits" control among the query transactions
here -- the parameter run is sized to leave no room for what follows it.
`-01`'s query transactions serve that purpose: four responses deep, they fit
the same cap and log field_count, data_rows and command_completed together.

Pcap
----

Crafted by Claude, with some guidance, and using scapy and partly the ticket description for reproducing
traffic. See `writepcap.py`.

Ticket
------

https://redmine.openinfosecfoundation.org/issues/7263
