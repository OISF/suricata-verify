# ruletype-firewall-276-lte-first-state-smtp-rejected

Same first-state `<hook` invariant as 275/263, on smtp. smtp has separate
to-server (`request_*`) and to-client (`response_*`) state tables, so this pins
that the rejection is resolved against the correct axis: `smtp:<request_started`
is the first to-server state and is rejected at load. Checked with `-T` and a
stderr grep for the specific message.
