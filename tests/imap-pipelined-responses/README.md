This test verifies that untagged server responses are associated with a
compatible command in a pipelined request stream, including when a later
command completes first. It also verifies active response grouping and that an
ambiguous response is retained without being assigned to either request.
It also verifies that untagged responses fitting no single command, such as
those of a UID STORE pipelined with a NOOP, share one transaction per chunk
instead of one each.
An unmatched response ending with a literal joins the transaction of the
chunk its literal ends in, so it is still logged when the literal continues in
the next segment, and the 300 body responses of two pipelined UID FETCHes do
not take a transaction each.
The global reassembly depth is far below the server data, which IMAP still
parses in full, as it tracks the whole stream by default.
