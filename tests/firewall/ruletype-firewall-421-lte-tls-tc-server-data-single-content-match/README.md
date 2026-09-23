# ruletype-firewall-421-lte-tls-tc-server-data-single-content-match

LTE (`<`) state matrix, tls tc `server_data`, case `single-content-match`.

< rule with a matching tls.version keyword: accepts at S.

The opposite direction carries one scaffolding `accept:hook <last-state`
rule so its default policy does not drop the flow before this direction
reaches S + 1, where a phase no match becomes final.
