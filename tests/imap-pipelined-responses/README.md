# IMAP pipelined response association

This test verifies that untagged server responses are associated with a
compatible command in a pipelined request stream, including when a later
command completes first. It also verifies active response grouping and that an
ambiguous response is retained without being assigned to either request.
