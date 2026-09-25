# ruletype-firewall-279-lte-smtp-filedata

LTE (`<`) file-data coverage cell for smtp: a `<request_data` rule whose
predicate is a `file.data` content match.

The file-data engine streams the tracked attachments at the `request_data`
state; the matching `<` rule accepts the flow at the packet where the raw
7bit attachment body is available (packet 24), so the file-data buffer is
usable as an LTE predicate at this state.

The opposite direction carries one scaffolding `accept:hook <last-state`
rule so its default policy does not drop the flow before this direction
reaches S + 1, where a phase no match becomes final.
